#include "connection_engine.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>

#include <openssl/crypto.h>

#include "envelope.pb.h"
#include "handshake.pb.h"
#include "hkdf.h"
#include "kem_kyber.h"
#include "messages.pb.h"
#include "crypto.h"
#include "protocol.h"

namespace {
int64_t nowSeconds() {
  using namespace std::chrono;
  return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

// AAD direction tags: 0x01 = client->server, 0x02 = server->client.
constexpr uint8_t kDirC2S = 0x01;
constexpr uint8_t kDirS2C = 0x02;

// Defense-in-depth clock-skew window for message timestamps (seconds).
constexpr int64_t kMaxClockSkewSeconds = 300;

std::vector<uint8_t> concat(const std::string& prefix,
                            const std::vector<uint8_t>& a,
                            const std::vector<uint8_t>& b = {}) {
  std::vector<uint8_t> out;
  out.reserve(prefix.size() + a.size() + b.size());
  out.insert(out.end(), prefix.begin(), prefix.end());
  out.insert(out.end(), a.begin(), a.end());
  out.insert(out.end(), b.begin(), b.end());
  return out;
}

void put_u32_be(std::vector<uint8_t>& v, uint32_t x) {
  v.push_back(static_cast<uint8_t>((x >> 24) & 0xFF));
  v.push_back(static_cast<uint8_t>((x >> 16) & 0xFF));
  v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
  v.push_back(static_cast<uint8_t>(x & 0xFF));
}

void put_u64_be(std::vector<uint8_t>& v, uint64_t x) {
  for (int i = 7; i >= 0; --i) {
    v.push_back(static_cast<uint8_t>((x >> (i * 8)) & 0xFF));
  }
}

// Canonical authenticated header bound as AES-GCM AAD. Both sides reconstruct it
// identically from: direction tag, sequence number, sender id, timestamp. The
// sender_id is length-prefixed so it can never collide with adjacent fields.
std::vector<uint8_t> buildMessageAad(uint8_t dirTag,
                                     uint64_t seq,
                                     const std::string& senderId,
                                     int64_t timestamp) {
  std::vector<uint8_t> aad;
  aad.reserve(1 + 8 + 4 + senderId.size() + 8);
  aad.push_back(dirTag);
  put_u64_be(aad, seq);
  put_u32_be(aad, static_cast<uint32_t>(senderId.size()));
  aad.insert(aad.end(), senderId.begin(), senderId.end());
  put_u64_be(aad, static_cast<uint64_t>(timestamp));
  return aad;
}
}  // namespace

ConnectionEngine::ConnectionEngine() = default;

bool ConnectionEngine::loadOrCreateIdentity(const std::string& path,
                                            const std::string& password,
                                            std::string& fingerprintOut,
                                            std::string& errorOut,
                                            bool* created) {
  try {
    if (created) *created = false;
    if (!std::filesystem::exists(path)) {
      IdentityStore::create_profile(path, password, identity_);
      if (created) *created = true;
    } else {
      IdentityStore::load_profile(path, password, identity_);
    }
    fingerprintOut = IdentityStore::fingerprint_hex(identity_.pub);
    return true;
  } catch (const std::exception& ex) {
    errorOut = ex.what();
    return false;
  }
}

bool ConnectionEngine::runClientHandshake(const SendFrameFn& send,
                                          const RecvFrameFn& recv,
                                          std::string& peerFingerprintOut,
                                          std::string& errorOut) {
  sessionReady_ = false;
  return clientHandshakeInternal(send, recv, peerFingerprintOut, errorOut);
}

bool ConnectionEngine::runServerHandshake(const SendFrameFn& send,
                                          const RecvFrameFn& recv,
                                          std::string& peerFingerprintOut,
                                          std::string& errorOut) {
  sessionReady_ = false;
  return serverHandshakeInternal(send, recv, peerFingerprintOut, errorOut);
}

bool ConnectionEngine::encryptAndSerializeMessage(const std::string& plaintext,
                                                  const std::string& senderId,
                                                  const std::string& toUsername,
                                                  std::vector<uint8_t>& outBytes,
                                                  std::string& errorOut) {
  if (!sessionReady_) {
    errorOut = "Session key not established";
    return false;
  }
  try {
    // Stamp a fresh monotonic sequence number and current timestamp, then bind
    // the direction + seq + sender + timestamp into the AEAD AAD.
    const uint64_t seq = session_.next_send_seq();
    const int64_t ts = nowSeconds();
    const uint8_t dirTag = (role_ == Role::Server) ? kDirS2C : kDirC2S;
    const auto aad = buildMessageAad(dirTag, seq, senderId, ts);

    std::vector<uint8_t> plain(plaintext.begin(), plaintext.end());
    auto nonce = AESGCMCrypto::random_nonce();
    auto ct_tag = session_.encrypt(plain, nonce, aad);

    ChatMessage inner;
    inner.set_sender_id(senderId);
    inner.set_timestamp_unix(ts);
    inner.set_seq(seq);
    inner.set_nonce(reinterpret_cast<const char*>(nonce.data()), nonce.size());
    inner.set_encrypted_content(reinterpret_cast<const char*>(ct_tag.data()), ct_tag.size());

    std::string inner_bytes;
    if (!inner.SerializeToString(&inner_bytes)) {
      errorOut = "Failed to serialize ChatMessage";
      return false;
    }

    Envelope env;
    env.set_version(protocol::kVersion);
    env.set_to_username(toUsername);
    env.set_client_timestamp(nowSeconds());
    env.set_payload_e2e(inner_bytes);

    std::string env_bytes;
    if (!env.SerializeToString(&env_bytes)) {
      errorOut = "Failed to serialize Envelope";
      return false;
    }

    outBytes.assign(env_bytes.begin(), env_bytes.end());
    return true;
  } catch (const std::exception& ex) {
    errorOut = ex.what();
    return false;
  }
}

bool ConnectionEngine::parseAndDecryptMessage(const std::vector<uint8_t>& frame,
                                              std::string& plaintextOut,
                                              std::string& errorOut) {
  if (!sessionReady_) {
    errorOut = "Session key not established";
    return false;
  }
  Envelope env;
  if (!env.ParseFromArray(frame.data(), static_cast<int>(frame.size()))) {
    errorOut = "Malformed Envelope";
    return false;
  }
  ChatMessage inner;
  if (!inner.ParseFromArray(env.payload_e2e().data(), static_cast<int>(env.payload_e2e().size()))) {
    errorOut = "Malformed ChatMessage";
    return false;
  }

  const uint64_t seq = inner.seq();
  const int64_t ts = inner.timestamp_unix();

  // Defense-in-depth: reject messages whose timestamp is implausibly far from
  // local time (either direction).
  int64_t skew = nowSeconds() - ts;
  if (skew < 0) skew = -skew;
  if (skew > kMaxClockSkewSeconds) {
    errorOut = "message timestamp outside allowed window";
    return false;
  }

  // Reconstruct the SAME AAD the sender bound; the peer's sending direction is
  // the opposite of ours.
  const uint8_t dirTag = (role_ == Role::Server) ? kDirC2S : kDirS2C;
  const auto aad = buildMessageAad(dirTag, seq, inner.sender_id(), ts);

  std::vector<uint8_t> nonce(inner.nonce().begin(), inner.nonce().end());
  std::vector<uint8_t> ct_tag(inner.encrypted_content().begin(), inner.encrypted_content().end());
  std::vector<uint8_t> plain;
  try {
    // Authenticate first (this fails on any AAD/metadata tampering)...
    plain = session_.decrypt(ct_tag, nonce, aad);
  } catch (const std::exception& ex) {
    errorOut = ex.what();
    return false;
  }

  // ...then enforce strict monotonic sequencing to reject replays / reordering.
  // Done only after a successful tag check so an unauthenticated frame cannot
  // poison the counter.
  if (!session_.accept_recv_seq(seq)) {
    errorOut = "replay or reordering detected (non-monotonic seq)";
    return false;
  }

  plaintextOut.assign(plain.begin(), plain.end());
  return true;
}

bool ConnectionEngine::clientHandshakeInternal(const SendFrameFn& send,
                                               const RecvFrameFn& recv,
                                               std::string& peerFingerprintOut,
                                               std::string& errorOut) {
  if (!identity_.is_loaded()) {
    errorOut = "Identity not loaded";
    return false;
  }
  try {
    KyberKEM kem;
    kem.init();
    std::vector<uint8_t> pk, sk;
    kem.keypair(pk, sk);

    auto sig_msg = concat("E2EE-HANDSHAKE-v1|client|", pk);
    auto sig = IdentityStore::sign(identity_.priv, sig_msg);

    HandshakeHello hello;
    hello.set_version(protocol::kVersion);
    hello.set_kem_public_key(std::string(reinterpret_cast<const char*>(pk.data()), pk.size()));
    hello.set_identity_pub(std::string(reinterpret_cast<const char*>(identity_.pub.data()), identity_.pub.size()));
    hello.set_identity_sig(std::string(reinterpret_cast<const char*>(sig.data()), sig.size()));

    std::string hello_bytes;
    if (!hello.SerializeToString(&hello_bytes)) {
      errorOut = "Failed to serialize HandshakeHello";
      return false;
    }
    if (!send(std::vector<uint8_t>(hello_bytes.begin(), hello_bytes.end()))) {
      errorOut = "Failed to send HandshakeHello";
      return false;
    }

    std::vector<uint8_t> resp_frame;
    if (!recv(resp_frame)) {
      errorOut = "Failed to receive HandshakeResponse";
      return false;
    }

    HandshakeResponse resp;
    if (!resp.ParseFromArray(resp_frame.data(), static_cast<int>(resp_frame.size()))) {
      errorOut = "Failed to parse HandshakeResponse";
      return false;
    }

    std::vector<uint8_t> server_pub(resp.identity_pub().begin(), resp.identity_pub().end());
    std::vector<uint8_t> server_sig(resp.identity_sig().begin(), resp.identity_sig().end());
    std::vector<uint8_t> ct(resp.kem_ciphertext().begin(), resp.kem_ciphertext().end());

    auto server_sig_msg = concat("E2EE-HANDSHAKE-v1|server|", ct, pk);
    if (!IdentityStore::verify(server_pub, server_sig_msg, server_sig)) {
      errorOut = "Server signature verification failed";
      return false;
    }

    std::vector<uint8_t> ss;
    kem.decapsulate(ct, sk, ss);

    // Expand the single KEM shared secret into two directional keys. The client
    // encrypts with k_c2s (send) and decrypts with k_s2c (recv).
    auto k_c2s = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_c2s(), 32);
    auto k_s2c = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_s2c(), 32);
    session_.set_keys(k_c2s, k_s2c);
    role_ = Role::Client;
    sessionReady_ = true;

    // Zeroize sensitive intermediate key material; the Session keeps its own copy.
    OPENSSL_cleanse(ss.data(), ss.size());
    OPENSSL_cleanse(sk.data(), sk.size());
    OPENSSL_cleanse(k_c2s.data(), k_c2s.size());
    OPENSSL_cleanse(k_s2c.data(), k_s2c.size());

    peerFingerprintOut = IdentityStore::fingerprint_hex(server_pub);
    return true;
  } catch (const std::exception& ex) {
    errorOut = ex.what();
    return false;
  }
}

bool ConnectionEngine::serverHandshakeInternal(const SendFrameFn& send,
                                               const RecvFrameFn& recv,
                                               std::string& peerFingerprintOut,
                                               std::string& errorOut) {
  if (!identity_.is_loaded()) {
    errorOut = "Identity not loaded";
    return false;
  }
  try {
    std::vector<uint8_t> frame;
    if (!recv(frame)) {
      errorOut = "Failed to receive HandshakeHello";
      return false;
    }
    HandshakeHello hello;
    if (!hello.ParseFromArray(frame.data(), static_cast<int>(frame.size()))) {
      errorOut = "Failed to parse HandshakeHello";
      return false;
    }

    std::vector<uint8_t> client_pk(hello.kem_public_key().begin(), hello.kem_public_key().end());
    std::vector<uint8_t> client_pub(hello.identity_pub().begin(), hello.identity_pub().end());
    std::vector<uint8_t> client_sig(hello.identity_sig().begin(), hello.identity_sig().end());

    auto client_sig_msg = concat("E2EE-HANDSHAKE-v1|client|", client_pk);
    if (!IdentityStore::verify(client_pub, client_sig_msg, client_sig)) {
      errorOut = "Client signature verification failed";
      return false;
    }

    KyberKEM kem;
    kem.init();
    std::vector<uint8_t> ct, ss;
    kem.encapsulate(client_pk, ct, ss);

    auto server_sig_msg = concat("E2EE-HANDSHAKE-v1|server|", ct, client_pk);
    auto sig = IdentityStore::sign(identity_.priv, server_sig_msg);

    HandshakeResponse resp;
    resp.set_version(protocol::kVersion);
    resp.set_kem_ciphertext(std::string(reinterpret_cast<const char*>(ct.data()), ct.size()));
    resp.set_identity_pub(std::string(reinterpret_cast<const char*>(identity_.pub.data()), identity_.pub.size()));
    resp.set_identity_sig(std::string(reinterpret_cast<const char*>(sig.data()), sig.size()));

    std::string resp_bytes;
    if (!resp.SerializeToString(&resp_bytes)) {
      errorOut = "Failed to serialize HandshakeResponse";
      return false;
    }
    if (!send(std::vector<uint8_t>(resp_bytes.begin(), resp_bytes.end()))) {
      errorOut = "Failed to send HandshakeResponse";
      return false;
    }

    // Expand the single KEM shared secret into two directional keys. The server
    // encrypts with k_s2c (send) and decrypts with k_c2s (recv) — mirror of the
    // client.
    auto k_c2s = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_c2s(), 32);
    auto k_s2c = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_s2c(), 32);
    session_.set_keys(k_s2c, k_c2s);
    role_ = Role::Server;
    sessionReady_ = true;

    // Zeroize sensitive intermediate key material; the Session keeps its own copy.
    OPENSSL_cleanse(ss.data(), ss.size());
    OPENSSL_cleanse(k_c2s.data(), k_c2s.size());
    OPENSSL_cleanse(k_s2c.data(), k_s2c.size());

    peerFingerprintOut = IdentityStore::fingerprint_hex(client_pub);
    return true;
  } catch (const std::exception& ex) {
    errorOut = ex.what();
    return false;
  }
}
