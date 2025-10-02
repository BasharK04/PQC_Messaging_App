// Minimal in-memory handshake + message roundtrip using ConnectionEngine.
// No sockets; uses two queues as channels.

#include <condition_variable>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

#include <google/protobuf/stubs/common.h>

#include "connection_engine.h"

struct Channel {
  std::mutex mtx;
  std::condition_variable cv;
  std::queue<std::vector<uint8_t>> q;
  bool closed = false;
};

static bool send_to(Channel& ch, const std::vector<uint8_t>& frame) {
  std::lock_guard<std::mutex> lk(ch.mtx);
  if (ch.closed) return false;
  ch.q.push(frame);
  ch.cv.notify_one();
  return true;
}

static bool recv_from(Channel& ch, std::vector<uint8_t>& out) {
  std::unique_lock<std::mutex> lk(ch.mtx);
  ch.cv.wait(lk, [&]{ return !ch.q.empty() || ch.closed; });
  if (ch.q.empty()) return false;
  out = std::move(ch.q.front());
  ch.q.pop();
  return true;
}

int main() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  // Prepare identities (stored under build/ to avoid clutter)
  std::filesystem::create_directories("build/test_id");
  const std::string pw = "pw";
  const std::string client_id = "build/test_id/client.id";
  const std::string server_id = "build/test_id/server.id";

  ConnectionEngine client;
  ConnectionEngine server;
  std::string fp_c, fp_s, err;
  bool created = false;
  if (!client.loadOrCreateIdentity(client_id, pw, fp_c, err, &created)) {
    std::cerr << "client identity error: " << err << "\n"; return 1;
  }
  if (!server.loadOrCreateIdentity(server_id, pw, fp_s, err, &created)) {
    std::cerr << "server identity error: " << err << "\n"; return 1;
  }
  std::cout << "client fp: " << fp_c.substr(0, 16) << "...\n";
  std::cout << "server fp: " << fp_s.substr(0, 16) << "...\n";

  Channel c2s, s2c;

  auto c_send = [&](const std::vector<uint8_t>& f){ return send_to(c2s, f); };
  auto c_recv = [&](std::vector<uint8_t>& f){ return recv_from(s2c, f); };
  auto s_send = [&](const std::vector<uint8_t>& f){ return send_to(s2c, f); };
  auto s_recv = [&](std::vector<uint8_t>& f){ return recv_from(c2s, f); };

  // Kick off server handshake so it can block waiting for client's hello
  std::thread th_server([&]{
    std::string peer;
    if (!server.runServerHandshake(s_send, s_recv, peer, err)) {
      std::cerr << "server handshake failed: " << err << "\n";
      // close channels
      { std::lock_guard<std::mutex> lk(c2s.mtx); c2s.closed = true; c2s.cv.notify_all(); }
      { std::lock_guard<std::mutex> lk(s2c.mtx); s2c.closed = true; s2c.cv.notify_all(); }
      return;
    }
    std::cout << "server sees client fp: " << peer.substr(0, 16) << "...\n";
  });

  std::string peer_client;
  if (!client.runClientHandshake(c_send, c_recv, peer_client, err)) {
    std::cerr << "client handshake failed: " << err << "\n";
    { std::lock_guard<std::mutex> lk(c2s.mtx); c2s.closed = true; c2s.cv.notify_all(); }
    { std::lock_guard<std::mutex> lk(s2c.mtx); s2c.closed = true; s2c.cv.notify_all(); }
    th_server.join();
    return 1;
  }
  std::cout << "client sees server fp: " << peer_client.substr(0, 16) << "...\n";
  th_server.join();

  // Round-trip a message
  std::vector<uint8_t> frame;
  if (!client.encryptAndSerializeMessage("hello loopback", "client", "server", frame, err)) {
    std::cerr << "encrypt failed: " << err << "\n"; return 1;
  }
  if (!send_to(c2s, frame)) { std::cerr << "send frame failed\n"; return 1; }
  std::vector<uint8_t> inbound;
  if (!recv_from(c2s, inbound)) { std::cerr << "unexpected channel state\n"; return 1; }
  std::string plain;
  if (!server.parseAndDecryptMessage(inbound, plain, err)) {
    std::cerr << "decrypt failed: " << err << "\n"; return 1;
  }
  std::cout << "server decrypted: " << plain << "\n";

  google::protobuf::ShutdownProtobufLibrary();
  return 0;
}

