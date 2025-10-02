#include <algorithm>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <fstream>

#include <google/protobuf/stubs/common.h>

#include "connection_engine.h"
#include "beast_ws_transport.h"

static std::string ws_join(const std::string& base, const std::string& room) {
  std::string url = base;
  if (url.rfind("http://", 0) == 0) url.replace(0, 4, "ws");
  else if (url.rfind("https://", 0) == 0) url.replace(0, 5, "wss");
  if (url.find('/', url.find("://") + 3) == std::string::npos) url += "/ws";
  if (url.find("/ws", url.find("://") + 3) == std::string::npos) {
    // append /ws if path was '/' or empty
    auto slash = url.find("://");
    auto hostend = url.find('/', slash + 3);
    if (hostend == std::string::npos) url += "/ws";
  }
  url += (url.find('?') == std::string::npos ? "?" : "&");
  url += "room=" + room;
  return url;
}

static void print_usage(const char* exe) {
  std::cerr << "Usage: " << exe << " (--host|--connect) --relay <url> --room <name> [--password <pw>]\n";
  std::cerr << "Examples:\n  " << exe << " --host --relay http://127.0.0.1:8080 --room alice --password mypass\n  "
            << exe << " --connect --relay http://127.0.0.1:8080 --room alice --password mypass\n";
}

static std::string url_host(const std::string& url) {
  auto pos = url.find("://");
  std::string rest = pos==std::string::npos ? url : url.substr(pos+3);
  auto slash = rest.find('/');
  std::string hostport = slash==std::string::npos ? rest : rest.substr(0, slash);
  return hostport;
}

int main(int argc, char* argv[]) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  std::string mode;
  std::string relay;
  std::string room;
  std::string pw;
  std::string id_path = "client.id";
  bool used_flags = false;
  for (int i=1; i<argc; ++i) {
    std::string a = argv[i];
    if (a == "--host") { mode = "host"; used_flags = true; }
    else if (a == "--connect") { mode = "connect"; used_flags = true; }
    else if ((a == "--relay" || a == "-r") && i+1 < argc) { relay = argv[++i]; used_flags = true; }
    else if ((a == "--room" || a == "-m") && i+1 < argc) { room = argv[++i]; used_flags = true; }
    else if ((a == "--password" || a == "-p") && i+1 < argc) { pw = argv[++i]; used_flags = true; }
    else if ((a == "--id-file" || a == "-i") && i+1 < argc) { id_path = argv[++i]; used_flags = true; }
    else if (a == "--help" || a == "-h") { print_usage(argv[0]); return 0; }
  }
  if (!used_flags) {
    if (argc < 5) { print_usage(argv[0]); return 1; }
    mode = argv[1]; relay = argv[2]; room = argv[3]; pw = argv[4];
  }
  if (mode != "host" && mode != "connect") { print_usage(argv[0]); return 1; }
  if (relay.empty() || room.empty()) { print_usage(argv[0]); return 1; }
  if (pw.empty()) {
    std::cerr << "Enter password for identity (client.id): ";
    std::getline(std::cin, pw);
  }
  std::string url = ws_join(relay, room);

  ConnectionEngine engine;
  std::string fp; std::string err; bool created=false;
  if (!engine.loadOrCreateIdentity(id_path, pw, fp, err, &created)) {
    std::cerr << "Identity error: " << err << "\n"; return 1;
  }
  std::cout << "Identity " << (created?"created":"loaded") << ", fp: " << fp.substr(0,16) << "...\n";

  BeastWebSocketTransport ws;
  std::cout << "Connecting to " << url << " ...\n";
  if (!ws.connect_url(url)) { std::cerr << "WebSocket connect failed\n"; return 1; }

  auto send_fn = [&](const std::vector<uint8_t>& frame){ return ws.send(frame); };
  auto recv_fn = [&](std::vector<uint8_t>& frame){ return ws.recv(frame); };

  std::string peer_fp;
  bool ok = false;
  if (mode == "host") ok = engine.runServerHandshake(send_fn, recv_fn, peer_fp, err);
  else if (mode == "connect") ok = engine.runClientHandshake(send_fn, recv_fn, peer_fp, err);
  else { std::cerr << "mode must be host or connect\n"; return 1; }
  if (!ok) { std::cerr << "Handshake failed: " << err << "\n"; return 1; }
  std::cout << "Peer fp: " << peer_fp.substr(0,16) << "...\n";

  // Simple TOFU pinning: pins.txt stores "room fingerprint\n" lines.
  auto load_pin = [&](const std::string& key)->std::string{
    std::ifstream f("pins.txt");
    if (!f) return {};
    std::string k,v;
    while (f >> k >> v) {
      if (k == key) return v;
    }
    return {};
  };
  auto save_pin = [&](const std::string& key, const std::string& val){
    // Append or rewrite line: for simplicity, append if not present.
    // If present and different, we don't overwrite automatically.
    std::ifstream fin("pins.txt");
    bool exists=false; std::string k,v; while (fin >> k >> v) { if (k==key) { exists=true; break; } }
    if (!exists) { std::ofstream f("pins.txt", std::ios::app); f << key << " " << val << "\n"; }
  };
  const std::string key = url_host(relay) + "#" + room;
  const std::string pinned = load_pin(key);
  if (!pinned.empty() && pinned != peer_fp) {
    std::cerr << "[TOFU] Peer fingerprint changed for room '" << room << "'!\n";
    std::cerr << "  pinned: " << pinned.substr(0,16) << "... new: " << peer_fp.substr(0,16) << "...\n";
    std::cerr << "  aborting to be safe. Delete pins.txt line to re-pin.\n";
    return 1;
  }
  if (pinned.empty()) {
    save_pin(key, peer_fp);
    std::cout << "[TOFU] pinned peer for room '" << room << "'\n";
  }

  std::cout << "Type messages, Ctrl-D to quit\n";
  // simple loop: stdin -> send; recv -> print (in another thread)
  std::atomic<bool> running{true};
  std::thread rx([&]{
    while (running) {
      std::vector<uint8_t> frame;
      if (!ws.recv(frame)) break;
      std::string plain;
      if (engine.parseAndDecryptMessage(frame, plain, err)) {
        std::cout << "Peer: " << plain << "\n";
      } else {
        std::cout << "[drop] " << err << "\n";
      }
    }
    running = false;
  });

  std::string line;
  while (running && std::getline(std::cin, line)) {
    if (line.empty()) continue;
    std::vector<uint8_t> frame;
    if (!engine.encryptAndSerializeMessage(line, "cli", "peer", frame, err)) {
      std::cerr << "Encrypt failed: " << err << "\n"; break;
    }
    if (!ws.send(frame)) { std::cerr << "Send failed\n"; break; }
  }
  running = false;
  ws.close();
  if (rx.joinable()) rx.join();

  return 0;
}
