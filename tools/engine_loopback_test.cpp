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
#include "crypto.h"
#include "envelope.pb.h"
#include "handshake.pb.h"
#include "hkdf.h"
#include "identity.h"
#include "kem_kyber.h"
#include "messages.pb.h"
#include "protocol.h"
#include "room_token.h"

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

  // ---- 0) Handshake identity concealment on the wire ----
  // Runs its own capture-instrumented handshake (fresh ConnectionEngine
  // instances, same on-disk identities) and inspects the RAW serialized
  // msg1/msg2 frames exactly as they pass through the send callbacks. Proves
  // the core anonymity property of the identity-concealing redesign: neither
  // party's raw 32-byte Ed25519 public key -- nor, for msg1, anything
  // signature-sized derived from an identity key -- ever appears as a
  // contiguous byte run in what a relay/observer sees.
  {
    ConnectionEngine cw, sw;
    std::string fpcw, fpsw, ew;
    bool crw = false;
    if (!cw.loadOrCreateIdentity(client_id, pw, fpcw, ew, &crw) ||
        !sw.loadOrCreateIdentity(server_id, pw, fpsw, ew, &crw)) {
      std::cerr << "wire-capture identity error: " << ew << "\n"; return 1;
    }

    Channel wc2s, ws2c;
    std::mutex capture_mtx;
    std::vector<uint8_t> msg1_bytes, msg2_bytes;

    // cw_send fires for msg1 (Hello) AND msg3 (Confirm); only the FIRST call
    // is msg1, so only capture when msg1_bytes is still empty.
    auto cw_send = [&](const std::vector<uint8_t>& f) {
      {
        std::lock_guard<std::mutex> lk(capture_mtx);
        if (msg1_bytes.empty()) msg1_bytes = f;
      }
      return send_to(wc2s, f);
    };
    auto cw_recv = [&](std::vector<uint8_t>& f) { return recv_from(ws2c, f); };
    // sw_send fires exactly once, for msg2 (Response).
    auto sw_send = [&](const std::vector<uint8_t>& f) {
      {
        std::lock_guard<std::mutex> lk(capture_mtx);
        if (msg2_bytes.empty()) msg2_bytes = f;
      }
      return send_to(ws2c, f);
    };
    auto sw_recv = [&](std::vector<uint8_t>& f) { return recv_from(wc2s, f); };

    std::thread th_sw([&] {
      std::string peer, e;
      sw.runServerHandshake(sw_send, sw_recv, peer, e);
    });
    std::string peer, e;
    if (!cw.runClientHandshake(cw_send, cw_recv, peer, e)) {
      std::cerr << "wire-capture handshake failed: " << e << "\n"; return 1;
    }
    th_sw.join();

    if (msg1_bytes.empty() || msg2_bytes.empty()) {
      std::cerr << "wire-capture failed to capture msg1/msg2\n"; return 1;
    }

    const std::string client_pub_s(cw.identity().pub.begin(), cw.identity().pub.end());
    const std::string server_pub_s(sw.identity().pub.begin(), sw.identity().pub.end());

    if (bytes_contain(msg1_bytes, client_pub_s) || bytes_contain(msg1_bytes, server_pub_s)) {
      std::cerr << "SECURITY FAIL: msg1 contains a raw identity public key\n"; return 1;
    }
    if (bytes_contain(msg2_bytes, client_pub_s) || bytes_contain(msg2_bytes, server_pub_s)) {
      std::cerr << "SECURITY FAIL: msg2 contains a raw identity public key\n"; return 1;
    }

    // msg1 additionally must carry no signature-sized blob derived from
    // either identity. Probe: a genuine Ed25519 signature produced with the
    // client's real key (over the exact bytes it put on the wire, standing in
    // for "anything the client might have signed") is effectively random and
    // must not appear as a substring of msg1 -- msg1 no longer signs
    // anything at all, so this should trivially hold.
    auto probe_sig = IdentityStore::sign(cw.identity().priv, msg1_bytes);
    const std::string probe_sig_s(probe_sig.begin(), probe_sig.end());
    if (bytes_contain(msg1_bytes, probe_sig_s)) {
      std::cerr << "SECURITY FAIL: msg1 contains a signature-sized identity blob\n"; return 1;
    }
    std::cout << "wire capture: msg1 (" << msg1_bytes.size() << " bytes) and msg2 ("
              << msg2_bytes.size() << " bytes) contain neither party's raw identity "
              << "public key, and msg1 carries no identity signature\n";
  }

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

  // ---- 7) A tampered sealed_identity blob must be REJECTED (AEAD open fails) ----
  // Runs a fresh 3-message handshake but flips one byte inside the server's
  // sealed_identity blob in flight. Identity material (including the server's
  // key-confirmation MAC) now travels only as ciphertext sealed under
  // k_outer, so this is the only way left to tamper with it from outside the
  // engine: any single-byte change anywhere in the blob must break the GCM
  // tag as a whole, rather than corrupting one field (e.g. confirm) in
  // isolation the way the old plaintext test did.
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
    // The client's only received frame during the handshake is the response;
    // we corrupt its sealed_identity bytes before handing it to the engine.
    auto nc_recv = [&](std::vector<uint8_t>& f){
      std::vector<uint8_t> raw;
      if (!recv_from(ns2c, raw)) return false;
      HandshakeResponse resp;
      if (!resp.ParseFromArray(raw.data(), static_cast<int>(raw.size()))) { f = raw; return true; }
      std::string si = resp.sealed_identity();
      if (!si.empty()) {
        si[0] ^= 0x01;
        resp.set_sealed_identity(si);
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
      std::cerr << "SECURITY FAIL: client accepted a tampered sealed identity\n";
      return 1;
    }
    if (cerr != "failed to open server identity") {
      std::cerr << "SECURITY FAIL: expected 'failed to open server identity', got '"
                << cerr << "'\n";
      return 1;
    }
    std::cout << "tampered sealed identity correctly rejected: " << cerr << "\n";
  }

  // ---- 8) A corrupted server signature must be REJECTED, independent of AEAD ----
  // Hand-rolls a "server" for msg2 using the same public crypto building
  // blocks the real handshake uses (KyberKEM, hkdf_sha256, AESGCMCrypto,
  // IdentityStore), so the AEAD seal on sealed_identity is completely VALID --
  // this exercises signature verification specifically, which item 7 above
  // cannot (any byte tamper there breaks the seal before a signature is ever
  // checked). The claimed identity_pub is the REAL server's public key, but
  // the signature over it is produced by a DIFFERENT identity ("mallory"), so
  // IdentityStore::verify must still reject it even though the seal opens.
  {
    ConnectionEngine client3, mallory;
    std::string e3;
    bool cr3 = false;
    std::string fpc3, fpm;
    if (!client3.loadOrCreateIdentity(client_id, pw, fpc3, e3, &cr3) ||
        !mallory.loadOrCreateIdentity("build/test_id/mallory.id", pw, fpm, e3, &cr3)) {
      std::cerr << "sig-test identity error: " << e3 << "\n"; return 1;
    }

    Channel fc2s, fs2c;
    auto fc_send = [&](const std::vector<uint8_t>& f){ return send_to(fc2s, f); };
    auto fc_recv = [&](std::vector<uint8_t>& f){ return recv_from(fs2c, f); };

    std::thread th_fake([&]{
      std::vector<uint8_t> hello_frame;
      if (!recv_from(fc2s, hello_frame)) return;
      HandshakeHello hello;
      if (!hello.ParseFromArray(hello_frame.data(), static_cast<int>(hello_frame.size()))) return;
      std::vector<uint8_t> client_pk(hello.kem_public_key().begin(), hello.kem_public_key().end());

      KyberKEM kem;
      kem.init();
      std::vector<uint8_t> ct, ss;
      kem.encapsulate(client_pk, ct, ss);
      auto k_outer = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_outer(), 32);

      // Sign an unrelated message with mallory's key, but claim the REAL
      // server's identity_pub -- pub key and signature deliberately do not
      // correspond to the same keypair.
      const std::vector<uint8_t>& real_server_pub = server.identity().pub;
      const std::vector<uint8_t> bogus_msg = {'b', 'a', 'd'};
      auto bad_sig = IdentityStore::sign(mallory.identity().priv, bogus_msg);
      const std::vector<uint8_t> fake_confirm(32, 0);

      SealedIdentity si;
      si.set_identity_pub(reinterpret_cast<const char*>(real_server_pub.data()), real_server_pub.size());
      si.set_identity_sig(reinterpret_cast<const char*>(bad_sig.data()), bad_sig.size());
      si.set_confirm(reinterpret_cast<const char*>(fake_confirm.data()), fake_confirm.size());
      std::string si_bytes;
      if (!si.SerializeToString(&si_bytes)) return;

      auto nonce = AESGCMCrypto::random_nonce();
      AESGCMCrypto outer(k_outer);
      // AAD = [0x02 (server->client)] || version_be32, matching buildOuterAad
      // in connection_engine.cpp exactly, so the seal opens cleanly.
      std::vector<uint8_t> aad;
      aad.push_back(0x02);
      aad.push_back(static_cast<uint8_t>((protocol::kVersion >> 24) & 0xFF));
      aad.push_back(static_cast<uint8_t>((protocol::kVersion >> 16) & 0xFF));
      aad.push_back(static_cast<uint8_t>((protocol::kVersion >> 8) & 0xFF));
      aad.push_back(static_cast<uint8_t>(protocol::kVersion & 0xFF));
      std::vector<uint8_t> plain(si_bytes.begin(), si_bytes.end());
      auto sealed = outer.encrypt(plain, nonce, aad);

      HandshakeResponse resp;
      resp.set_version(protocol::kVersion);
      resp.set_kem_ciphertext(std::string(reinterpret_cast<const char*>(ct.data()), ct.size()));
      resp.set_sealed_nonce(std::string(reinterpret_cast<const char*>(nonce.data()), nonce.size()));
      resp.set_sealed_identity(std::string(reinterpret_cast<const char*>(sealed.data()), sealed.size()));
      std::string resp_bytes;
      if (!resp.SerializeToString(&resp_bytes)) return;
      send_to(fs2c, std::vector<uint8_t>(resp_bytes.begin(), resp_bytes.end()));
    });

    std::string peer3, cerr3;
    bool ok3 = client3.runClientHandshake(fc_send, fc_recv, peer3, cerr3);
    { std::lock_guard<std::mutex> lk(fc2s.mtx); fc2s.closed = true; fc2s.cv.notify_all(); }
    { std::lock_guard<std::mutex> lk(fs2c.mtx); fs2c.closed = true; fs2c.cv.notify_all(); }
    th_fake.join();

    if (ok3) {
      std::cerr << "SECURITY FAIL: client accepted a server signature from the wrong identity\n";
      return 1;
    }
    if (cerr3 != "Server signature verification failed") {
      std::cerr << "SECURITY FAIL: expected 'Server signature verification failed', got '"
                << cerr3 << "'\n";
      return 1;
    }
    std::cout << "wrong-identity server signature correctly rejected: " << cerr3 << "\n";
  }

  // ---- 9) room_token: opaque relay room token derivation ----
  // The relay room name IS the peer's username in GUI usage, so this must
  // never appear in cleartext on the wire (the WebSocket "room=" query
  // value). room_token() is what stands between the real name and the URL.
  {
    // Deterministic: same (room, secret) -> same token, across repeated calls.
    const std::string t1 = room_token("alice", "shared-secret");
    const std::string t2 = room_token("alice", "shared-secret");
    if (t1 != t2) {
      std::cerr << "SECURITY FAIL: room_token is not deterministic for identical inputs\n";
      return 1;
    }
    std::cout << "room_token: deterministic for identical (room, secret)\n";

    // Distinct room -> distinct token (secret held fixed).
    const std::string t_room_b = room_token("bob", "shared-secret");
    if (t1 == t_room_b) {
      std::cerr << "SECURITY FAIL: different rooms produced the same token\n";
      return 1;
    }
    std::cout << "room_token: different room name changes the token\n";

    // Distinct secret -> distinct token (room held fixed).
    const std::string t_secret_b = room_token("alice", "other-secret");
    if (t1 == t_secret_b) {
      std::cerr << "SECURITY FAIL: different secrets produced the same token\n";
      return 1;
    }
    std::cout << "room_token: different secret changes the token\n";

    // No collision from ambiguous concatenation: length-prefixing must keep
    // ("ab","c") and ("a","bc") from hashing to the same thing.
    const std::string t_ab_c = room_token("ab", "c");
    const std::string t_a_bc = room_token("a", "bc");
    if (t_ab_c == t_a_bc) {
      std::cerr << "SECURITY FAIL: room_token(\"ab\",\"c\") == room_token(\"a\",\"bc\") "
                << "(ambiguous concatenation collision)\n";
      return 1;
    }
    std::cout << "room_token: (\"ab\",\"c\") and (\"a\",\"bc\") do not collide\n";

    // Format: exactly 64 lowercase hex characters (a SHA-256 digest).
    auto is_lower_hex64 = [](const std::string& s) {
      if (s.size() != 64) return false;
      return std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
      });
    };
    if (!is_lower_hex64(t1) || !is_lower_hex64(t_room_b) || !is_lower_hex64(t_ab_c)) {
      std::cerr << "SECURITY FAIL: room_token output is not exactly 64 lowercase hex chars\n";
      return 1;
    }
    std::cout << "room_token: output is exactly 64 lowercase hex characters\n";

    // The whole point: the token must not leak the room name as a substring.
    const std::string sensitive_room = "alice-super-secret-username";
    const std::string sensitive_token = room_token(sensitive_room, "");
    if (sensitive_token.find(sensitive_room) != std::string::npos) {
      std::cerr << "SECURITY FAIL: room_token output contains the room name as a substring\n";
      return 1;
    }
    std::cout << "room_token: token for '" << sensitive_room << "' does not contain the room "
              << "name as a substring\n";
  }

  std::cout << "ALL CHECKS PASSED\n";
  google::protobuf::ShutdownProtobufLibrary();
  return 0;
}
