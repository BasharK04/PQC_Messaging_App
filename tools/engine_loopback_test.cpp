// Minimal in-memory handshake + message roundtrip using ConnectionEngine.
// No sockets; uses two queues as channels.

#include <algorithm>
#include <condition_variable>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include <google/protobuf/stubs/common.h>

#include "connection_engine.h"
#include "envelope.pb.h"
#include "handshake.pb.h"
#include "messages.pb.h"

// Flip one byte inside Envelope.ciphertext (the sealed-sender AEAD output).
// Since ALL per-message metadata now lives inside the ciphertext, this is the
// only way left to "tamper metadata" from outside the engine: it must fail
// GCM tag verification just like tampering the visible-text portion would.
static bool tamper_ciphertext_byte(const std::vector<uint8_t>& in,
                                   std::vector<uint8_t>& out) {
  Envelope env;
  if (!env.ParseFromArray(in.data(), static_cast<int>(in.size()))) return false;
  std::string ct = env.ciphertext();
  if (ct.empty()) return false;
  ct[0] ^= 0x01;
  env.set_ciphertext(ct);
  std::string env_bytes;
  if (!env.SerializeToString(&env_bytes)) return false;
  out.assign(env_bytes.begin(), env_bytes.end());
  return true;
}

// Flip the Envelope.version field. It is bound into the AEAD AAD, so changing
// it must break tag verification even though the ciphertext bytes themselves
// are untouched.
static bool tamper_version(const std::vector<uint8_t>& in,
                           std::vector<uint8_t>& out) {
  Envelope env;
  if (!env.ParseFromArray(in.data(), static_cast<int>(in.size()))) return false;
  env.set_version(env.version() + 1);
  std::string env_bytes;
  if (!env.SerializeToString(&env_bytes)) return false;
  out.assign(env_bytes.begin(), env_bytes.end());
  return true;
}

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

// Does `haystack` contain `needle` as a contiguous byte run? Used to prove
// sender/recipient identifiers never appear in the raw serialized frame.
static bool bytes_contain(const std::vector<uint8_t>& haystack, const std::string& needle) {
  if (needle.empty() || needle.size() > haystack.size()) return false;
  const auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end());
  return it != haystack.end();
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

  // ---- 1) Real encrypt -> decrypt round trip (seq = 1) ----
  std::vector<uint8_t> frame;
  if (!client.encryptAndSerializeMessage("hello loopback", "client", "server", frame, err)) {
    std::cerr << "encrypt failed: " << err << "\n"; return 1;
  }
  {
    std::string plain;
    if (!server.parseAndDecryptMessage(frame, plain, err)) {
      std::cerr << "decrypt failed: " << err << "\n"; return 1;
    }
    if (plain != "hello loopback") {
      std::cerr << "round-trip mismatch: got '" << plain << "'\n"; return 1;
    }
    std::cout << "server decrypted: " << plain << "\n";
  }

  // ---- 1b) Reverse direction (server -> client) proves the s2c key works ----
  {
    std::vector<uint8_t> rframe;
    if (!server.encryptAndSerializeMessage("reply from server", "server", "client", rframe, err)) {
      std::cerr << "server encrypt failed: " << err << "\n"; return 1;
    }
    std::string plain;
    if (!client.parseAndDecryptMessage(rframe, plain, err)) {
      std::cerr << "client decrypt failed: " << err << "\n"; return 1;
    }
    if (plain != "reply from server") {
      std::cerr << "reverse round-trip mismatch: got '" << plain << "'\n"; return 1;
    }
    std::cout << "client decrypted: " << plain << "\n";
  }

  // ---- 2) Replay of an already-accepted frame must be REJECTED ----
  {
    std::string plain;
    if (server.parseAndDecryptMessage(frame, plain, err)) {
      std::cerr << "SECURITY FAIL: replayed frame was accepted\n"; return 1;
    }
    std::cout << "replay correctly rejected: " << err << "\n";
  }

  // ---- 3) Sealed sender: no plaintext metadata on the wire ----
  // Build a text message with distinctive sender/recipient identifiers,
  // serialize the frame, and assert the raw bytes contain NEITHER. This is
  // the core anonymity property of the redesign: sender_id and recipient_id
  // (formerly ChatMessage.sender_id and Envelope.to_username, both plaintext)
  // now live only inside the AEAD ciphertext.
  {
    const std::string sender = "alice-unique-sender-id";
    const std::string recipient = "bob-unique-recipient-id";
    std::vector<uint8_t> sealed;
    if (!client.encryptAndSerializeMessage("metadata should be sealed", sender, recipient,
                                           sealed, err)) {
      std::cerr << "encrypt(sealed-sender probe) failed: " << err << "\n"; return 1;
    }
    if (bytes_contain(sealed, sender)) {
      std::cerr << "SECURITY FAIL: sender id appears in plaintext on the wire\n"; return 1;
    }
    if (bytes_contain(sealed, recipient)) {
      std::cerr << "SECURITY FAIL: recipient id appears in plaintext on the wire\n"; return 1;
    }
    std::cout << "sealed sender: neither sender id nor recipient id found in "
              << sealed.size() << "-byte frame\n";
    // Consume it so it doesn't dangle in the server's inbound state / seq
    // counter for the tests that follow.
    std::string plain;
    if (!server.parseAndDecryptMessage(sealed, plain, err)) {
      std::cerr << "decrypt(sealed-sender probe) failed: " << err << "\n"; return 1;
    }
  }

  // ---- 4) Length padding: frame size only reveals a size bucket ----
  {
    std::vector<uint8_t> small, mid, big;
    if (!client.encryptAndSerializeMessage(std::string(5, 'a'), "client", "server", small, err) ||
        !client.encryptAndSerializeMessage(std::string(200, 'b'), "client", "server", mid, err) ||
        !client.encryptAndSerializeMessage(std::string(1000, 'c'), "client", "server", big, err)) {
      std::cerr << "encrypt(padding probe) failed: " << err << "\n"; return 1;
    }
    if (small.size() != mid.size()) {
      std::cerr << "SECURITY FAIL: a 5-byte and a 200-byte message produced "
                << "different frame sizes (" << small.size() << " vs " << mid.size()
                << "); length leaks\n";
      return 1;
    }
    std::cout << "length padding: 5-byte and 200-byte messages both produced "
              << small.size() << "-byte frames (same bucket)\n";
    if (big.size() <= small.size()) {
      std::cerr << "SECURITY FAIL: a ~1000-byte message did not land in a larger "
                << "bucket than a 5-byte message (" << big.size() << " vs "
                << small.size() << ")\n";
      return 1;
    }
    std::cout << "length padding: ~1000-byte message landed in a larger bucket ("
              << big.size() << " > " << small.size() << ")\n";
    // Drain them so seq/order stays consistent for what follows.
    std::string plain;
    if (!server.parseAndDecryptMessage(small, plain, err) ||
        !server.parseAndDecryptMessage(mid, plain, err) ||
        !server.parseAndDecryptMessage(big, plain, err)) {
      std::cerr << "decrypt(padding probe) failed: " << err << "\n"; return 1;
    }
  }

  // ---- 5) Tamper detection: ciphertext byte flip must FAIL decryption ----
  {
    std::vector<uint8_t> frame2;
    if (!client.encryptAndSerializeMessage("second message", "client", "server", frame2, err)) {
      std::cerr << "encrypt(2) failed: " << err << "\n"; return 1;
    }
    std::vector<uint8_t> tampered;
    if (!tamper_ciphertext_byte(frame2, tampered)) {
      std::cerr << "tamper helper failed\n"; return 1;
    }
    std::string plain;
    if (server.parseAndDecryptMessage(tampered, plain, err)) {
      std::cerr << "SECURITY FAIL: ciphertext-tampered frame was accepted\n"; return 1;
    }
    std::cout << "ciphertext tamper correctly rejected: " << err << "\n";

    // The untampered frame behind it must still decrypt fine (proves the
    // tamper helper only mutated the copy, not the real frame/seq state).
    std::string plain2;
    if (!server.parseAndDecryptMessage(frame2, plain2, err)) {
      std::cerr << "decrypt(post-tamper genuine frame) failed: " << err << "\n"; return 1;
    }
    if (plain2 != "second message") {
      std::cerr << "post-tamper genuine round-trip mismatch: got '" << plain2 << "'\n"; return 1;
    }
  }

  // ---- 6) Tamper detection: version field flip must FAIL decryption (AAD) ----
  {
    std::vector<uint8_t> frame3;
    if (!client.encryptAndSerializeMessage("third message", "client", "server", frame3, err)) {
      std::cerr << "encrypt(3) failed: " << err << "\n"; return 1;
    }
    std::vector<uint8_t> tampered;
    if (!tamper_version(frame3, tampered)) {
      std::cerr << "tamper helper (version) failed\n"; return 1;
    }
    std::string plain;
    if (server.parseAndDecryptMessage(tampered, plain, err)) {
      std::cerr << "SECURITY FAIL: version-tampered frame was accepted\n"; return 1;
    }
    std::cout << "version tamper correctly rejected: " << err << "\n";

    std::string plain3;
    if (!server.parseAndDecryptMessage(frame3, plain3, err)) {
      std::cerr << "decrypt(post-tamper genuine frame 3) failed: " << err << "\n"; return 1;
    }
    if (plain3 != "third message") {
      std::cerr << "post-tamper genuine round-trip mismatch: got '" << plain3 << "'\n"; return 1;
    }
  }

  // ---- 7) A tampered server key-confirmation must be REJECTED by the client ----
  // Runs a fresh 3-message handshake but flips the server's confirmation MAC in
  // flight. The server signature (over the transcript hash H) still verifies, so
  // this specifically exercises the HMAC key-confirmation step (item 3).
  {
    ConnectionEngine client2, server2;
    std::string e;
    bool cr = false;
    std::string fpc2, fps2;
    if (!client2.loadOrCreateIdentity(client_id, pw, fpc2, e, &cr) ||
        !server2.loadOrCreateIdentity(server_id, pw, fps2, e, &cr)) {
      std::cerr << "neg-test identity error: " << e << "\n"; return 1;
    }

    Channel nc2s, ns2c;
    auto ns_send = [&](const std::vector<uint8_t>& f){ return send_to(ns2c, f); };
    auto ns_recv = [&](std::vector<uint8_t>& f){ return recv_from(nc2s, f); };
    auto nc_send = [&](const std::vector<uint8_t>& f){ return send_to(nc2s, f); };
    // The client's only received frame during the handshake is the response; we
    // corrupt its confirmation MAC before handing it to the engine.
    auto nc_recv = [&](std::vector<uint8_t>& f){
      std::vector<uint8_t> raw;
      if (!recv_from(ns2c, raw)) return false;
      HandshakeResponse resp;
      if (!resp.ParseFromArray(raw.data(), static_cast<int>(raw.size()))) { f = raw; return true; }
      std::string c = resp.confirm();
      if (!c.empty()) {
        c[0] ^= 0x01;
        resp.set_confirm(c);
        std::string bytes;
        if (resp.SerializeToString(&bytes)) { f.assign(bytes.begin(), bytes.end()); return true; }
      }
      f = raw;
      return true;
    };

    std::string serr;
    std::thread th_s([&]{
      std::string peer;
      server2.runServerHandshake(ns_send, ns_recv, peer, serr);
      { std::lock_guard<std::mutex> lk(nc2s.mtx); nc2s.closed = true; nc2s.cv.notify_all(); }
      { std::lock_guard<std::mutex> lk(ns2c.mtx); ns2c.closed = true; ns2c.cv.notify_all(); }
    });

    std::string peer2, cerr;
    bool ok2 = client2.runClientHandshake(nc_send, nc_recv, peer2, cerr);
    // Unblock the server thread even though the client aborted before msg 3.
    { std::lock_guard<std::mutex> lk(nc2s.mtx); nc2s.closed = true; nc2s.cv.notify_all(); }
    { std::lock_guard<std::mutex> lk(ns2c.mtx); ns2c.closed = true; ns2c.cv.notify_all(); }
    th_s.join();

    if (ok2) {
      std::cerr << "SECURITY FAIL: client accepted a tampered key confirmation\n";
      return 1;
    }
    std::cout << "tampered key-confirmation correctly rejected: " << cerr << "\n";
  }

  std::cout << "ALL CHECKS PASSED\n";
  google::protobuf::ShutdownProtobufLibrary();
  return 0;
}
