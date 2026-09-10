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
#include "pin_store.h"
#include "room_token.h"

// Joins the relay using the opaque room TOKEN (derived by room_token()), not
// the raw room name, so the relay's URL/logs never see the real room name.
static std::string ws_join(const std::string& base, const std::string& room_token_hex) {
  std::string url = base;
  if (url.rfind("http://", 0) == 0) url.replace(0, 4, "ws");
  else if (url.rfind("https://", 0) == 0) url.replace(0, 5, "wss");
  if (url.find('/', url.find("://") + 3) == std::string::npos) url += "/ws";
  if (url.find("/ws", url.find("://") + 3) == std::string::npos) {
    // add /ws when the path is empty
    auto slash = url.find("://");
    auto hostend = url.find('/', slash + 3);
    if (hostend == std::string::npos) url += "/ws";
  }
  url += (url.find('?') == std::string::npos ? "?" : "&");
  url += "room=" + room_token_hex;
  return url;
}

static void print_usage(const char* exe) {
  std::cerr << "Usage: " << exe << " (--host|--connect) --relay <url> --room <name> [--room-secret <s>] [--password <pw>] [--insecure]\n";
  std::cerr << "  --room-secret <s>   Shared out-of-band secret mixed into the room token sent to\n";
  std::cerr << "                      the relay. Without it, the token only hides the room name from\n";
  std::cerr << "                      casual log reading/enumeration -- it is OBFUSCATED, NOT SECRET,\n";
  std::cerr << "                      since a guessable room name can still be dictionary-attacked.\n";
  std::cerr << "  --insecure   DEV ONLY: disable TLS certificate verification for wss:// (self-signed relays)\n";
  std::cerr << "Examples:\n  " << exe << " --host --relay http://127.0.0.1:8080 --room alice --password mypass\n  "
            << exe << " --connect --relay http://127.0.0.1:8080 --room alice --password mypass\n  "
            << exe << " --host --relay http://127.0.0.1:8080 --room alice --room-secret ourpass --password mypass\n";
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
  std::string room_secret;
  std::string pw;
  std::string id_path = "client.id";
  bool insecure_tls = false;
  bool used_flags = false;
  for (int i=1; i<argc; ++i) {
    std::string a = argv[i];
    if (a == "--host") { mode = "host"; used_flags = true; }
    else if (a == "--connect") { mode = "connect"; used_flags = true; }
    else if ((a == "--relay" || a == "-r") && i+1 < argc) { relay = argv[++i]; used_flags = true; }
    else if ((a == "--room" || a == "-m") && i+1 < argc) { room = argv[++i]; used_flags = true; }
    else if (a == "--room-secret" && i+1 < argc) { room_secret = argv[++i]; used_flags = true; }
    else if ((a == "--password" || a == "-p") && i+1 < argc) { pw = argv[++i]; used_flags = true; }
    else if ((a == "--id-file" || a == "-i") && i+1 < argc) { id_path = argv[++i]; used_flags = true; }
    else if (a == "--insecure") { insecure_tls = true; used_flags = true; }
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

  // The relay only ever sees this derived token, never the real room name.
  // Print a short prefix at startup so two peers can confirm out-of-band
  // that they derived the SAME token (i.e. their room+room-secret match)
  // before assuming a silent connect failure is something else.
  const std::string token = room_token(room, room_secret);
  std::cout << "Room token: " << token.substr(0, 16) << "..."
            << (room_secret.empty()
                    ? " (no --room-secret: obfuscated only, not secret)"
                    : " (derived with --room-secret)")
            << "\n";
  std::string url = ws_join(relay, token);

  ConnectionEngine engine;
  std::string fp; std::string err; bool created=false;
  if (!engine.loadOrCreateIdentity(id_path, pw, fp, err, &created)) {
    std::cerr << "Identity error: " << err << "\n"; return 1;
  }
  std::cout << "Identity " << (created?"created":"loaded") << ", fp: " << fp.substr(0,16) << "...\n";

  BeastWebSocketTransport ws;
  if (insecure_tls) {
    std::cerr << "[WARNING] --insecure enabled: TLS certificate verification is DISABLED.\n";
    ws.set_insecure_tls(true);
  }
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

  // TOFU pinning via the shared PinStore (same logic the GUI now uses). Keyed by
  // relay-host#room so a peer identity change for a given room is caught.
  const std::string pin_key = url_host(relay) + "#" + room;
  const PinResult pin = PinStore::checkAndPin("pins.txt", pin_key, peer_fp);
  if (pin == PinResult::Mismatch) {
    const std::string pinned = PinStore::lookup("pins.txt", pin_key);
    std::cerr << "[TOFU] Peer fingerprint CHANGED for room '" << room << "'!\n";
    std::cerr << "  pinned: " << pinned.substr(0,16) << "... new: " << peer_fp.substr(0,16) << "...\n";
    std::cerr << "  aborting to be safe. Delete the pins.txt line to re-pin.\n";
    return 1;
  }
  if (pin == PinResult::Pinned) {
    std::cout << "[TOFU] pinned peer for room '" << room << "' (fp " << peer_fp.substr(0,16)
              << "...). VERIFY this fingerprint with your peer out-of-band.\n";
  } else {
    std::cout << "[TOFU] peer fingerprint matches the pinned entry for room '" << room << "'.\n";
  }

  std::cout << "Type messages, Ctrl-D to quit\n";
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
  // shutdown() tears down the underlying socket (cancel + shutdown_both)
  // without writing a WebSocket close frame, so it can never race the rx
  // thread's in-flight ws.recv(). It unblocks that blocked read promptly,
  // whereas ws.close() here would collide with the concurrent read and trip
  // Beast's "one reader + one writer" assertion (UB in release builds).
  ws.shutdown();
  if (rx.joinable()) rx.join();
  // Now single-threaded (rx has exited): an optional best-effort graceful
  // close. It's a no-op since shutdown() already tore the connection down,
  // kept here in case that ever changes.
  ws.close();

  return 0;
}
