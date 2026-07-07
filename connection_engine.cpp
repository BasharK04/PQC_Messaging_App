#include "connection_engine.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

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

// Append a length-prefixed (u32 big-endian length) byte string. Length prefixes
// make the concatenation unambiguous so no adjacent field can be shifted across
// a boundary without changing the hash/signature.
void put_lp(std::vector<uint8_t>& v, const std::vector<uint8_t>& d) {
  put_u32_be(v, static_cast<uint32_t>(d.size()));
  v.insert(v.end(), d.begin(), d.end());
}

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
  std::vector<uint8_t> out(SHA256_DIGEST_LENGTH);
  SHA256(data.data(), data.size(), out.data());
  return out;
}

std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key,
                                 const std::vector<uint8_t>& msg) {
  std::vector<uint8_t> out(SHA256_DIGEST_LENGTH);
  unsigned int len = 0;
  if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
           msg.data(), msg.size(), out.data(), &len) == nullptr ||
      len != SHA256_DIGEST_LENGTH) {
    throw std::runtime_error("HMAC-SHA256 failed");
  }
  return out;
}

// Constant-time equality for MAC/tag comparison.
bool ct_equal(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
  if (a.size() != b.size()) return false;
  if (a.empty()) return false;  // empty tag is never a valid confirmation
  return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

// Full mutual-context transcript hash bound into the server signature and the
// key-confirmation MACs. Binds BOTH identity keys, BOTH KEM values, and the
// version, so a relay/forward or identity-misbinding attack changes H and is
// rejected.
//   H = SHA256( version_be32
//               || lp(client_id_pub) || lp(kem_pk)
//               || lp(server_id_pub) || lp(kem_ct) )
std::vector<uint8_t> transcriptHash(uint32_t version,
                                    const std::vector<uint8_t>& client_pub,
                                    const std::vector<uint8_t>& kem_pk,
                                    const std::vector<uint8_t>& server_pub,
                                    const std::vector<uint8_t>& kem_ct) {
  std::vector<uint8_t> t;
  put_u32_be(t, version);
  put_lp(t, client_pub);
  put_lp(t, kem_pk);
  put_lp(t, server_pub);
  put_lp(t, kem_ct);
  return sha256(t);
}

// Message the CLIENT signs. It cannot yet see the server's fields, so it signs
// version + its own identity key + its KEM public key. This still binds the
// client's contribution and the version into the transcript the server hashes.
std::vector<uint8_t> clientSigMsg(uint32_t version,
                                  const std::vector<uint8_t>& client_pub,
                                  const std::vector<uint8_t>& kem_pk) {
  static const char kPrefix[] = "E2EE-HS-v1|client|";
  std::vector<uint8_t> m(kPrefix, kPrefix + sizeof(kPrefix) - 1);
  put_u32_be(m, version);
  put_lp(m, client_pub);
  put_lp(m, kem_pk);
  return m;
}

// Message the SERVER signs: prefix || H (the full transcript hash).
std::vector<uint8_t> serverSigMsg(const std::vector<uint8_t>& H) {
  static const char kPrefix[] = "E2EE-HS-v1|server|";
  std::vector<uint8_t> m(kPrefix, kPrefix + sizeof(kPrefix) - 1);
  m.insert(m.end(), H.begin(), H.end());
  return m;
}

// Key-confirmation MAC input: a one-byte direction tag ('s' or 'c') || H.
std::vector<uint8_t> confirmMsg(char tag, const std::vector<uint8_t>& H) {
  std::vector<uint8_t> m;
  m.reserve(1 + H.size());
  m.push_back(static_cast<uint8_t>(tag));
  m.insert(m.end(), H.begin(), H.end());
  return m;
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

    // Msg 1 (client -> server): sign version + our identity key + our KEM pk.
    auto sig = IdentityStore::sign(identity_.priv,
                                   clientSigMsg(protocol::kVersion, identity_.pub, pk));

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

    // Msg 2 (server -> client): HandshakeResponse.
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

    // Explicit version check (also bound into H, so tampering breaks the sig).
    if (resp.version() != protocol::kVersion) {
      errorOut = "Unsupported/mismatched protocol version in HandshakeResponse";
      return false;
    }

    std::vector<uint8_t> server_pub(resp.identity_pub().begin(), resp.identity_pub().end());
    std::vector<uint8_t> server_sig(resp.identity_sig().begin(), resp.identity_sig().end());
    std::vector<uint8_t> ct(resp.kem_ciphertext().begin(), resp.kem_ciphertext().end());
    std::vector<uint8_t> confirm_s(resp.confirm().begin(), resp.confirm().end());

    // Recompute the full transcript hash from the fields we now hold. Because H
    // binds our OWN hello contribution, a relay/forward that swaps in a
    // different client hello yields a different H and fails signature/confirm.
    const auto H = transcriptHash(protocol::kVersion, identity_.pub, pk, server_pub, ct);

    // Verify the server signature over "E2EE-HS-v1|server|" || H.
    if (!IdentityStore::verify(server_pub, serverSigMsg(H), server_sig)) {
      errorOut = "Server signature verification failed";
      return false;
    }

    std::vector<uint8_t> ss;
    kem.decapsulate(ct, sk, ss);

    // Expand the single KEM shared secret into two directional keys plus an
    // independent key-confirmation key. The client encrypts with k_c2s (send)
    // and decrypts with k_s2c (recv).
    auto k_c2s = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_c2s(), 32);
    auto k_s2c = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_s2c(), 32);
    auto k_confirm = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_confirm(), 32);

    // Verify the server's key confirmation: proves the server derived the same
    // shared secret (catches a KEM/key mismatch or a swapped ciphertext).
    const auto expect_s = hmac_sha256(k_confirm, confirmMsg('s', H));
    if (!ct_equal(confirm_s, expect_s)) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(sk.data(), sk.size());
      OPENSSL_cleanse(k_c2s.data(), k_c2s.size());
      OPENSSL_cleanse(k_s2c.data(), k_s2c.size());
      OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
      errorOut = "Server key confirmation failed";
      return false;
    }

    // Msg 3 (client -> server): send our confirmation, HMAC(k_confirm,"c"||H).
    const auto confirm_c = hmac_sha256(k_confirm, confirmMsg('c', H));
    HandshakeConfirm conf;
    conf.set_confirm(std::string(reinterpret_cast<const char*>(confirm_c.data()), confirm_c.size()));
    std::string conf_bytes;
    if (!conf.SerializeToString(&conf_bytes)) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(sk.data(), sk.size());
      OPENSSL_cleanse(k_c2s.data(), k_c2s.size());
      OPENSSL_cleanse(k_s2c.data(), k_s2c.size());
      OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
      errorOut = "Failed to serialize HandshakeConfirm";
      return false;
    }

    session_.set_keys(k_c2s, k_s2c);
    role_ = Role::Client;

    if (!send(std::vector<uint8_t>(conf_bytes.begin(), conf_bytes.end()))) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(sk.data(), sk.size());
      OPENSSL_cleanse(k_c2s.data(), k_c2s.size());
      OPENSSL_cleanse(k_s2c.data(), k_s2c.size());
      OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
      errorOut = "Failed to send HandshakeConfirm";
      return false;
    }
    sessionReady_ = true;

    // Zeroize sensitive intermediate key material; the Session keeps its own copy.
    OPENSSL_cleanse(ss.data(), ss.size());
    OPENSSL_cleanse(sk.data(), sk.size());
    OPENSSL_cleanse(k_c2s.data(), k_c2s.size());
    OPENSSL_cleanse(k_s2c.data(), k_s2c.size());
    OPENSSL_cleanse(k_confirm.data(), k_confirm.size());

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
    // Msg 1 (client -> server): HandshakeHello.
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

    // Explicit version check (also bound into H, so tampering breaks the sig).
    if (hello.version() != protocol::kVersion) {
      errorOut = "Unsupported/mismatched protocol version in HandshakeHello";
      return false;
    }

    std::vector<uint8_t> client_pk(hello.kem_public_key().begin(), hello.kem_public_key().end());
    std::vector<uint8_t> client_pub(hello.identity_pub().begin(), hello.identity_pub().end());
    std::vector<uint8_t> client_sig(hello.identity_sig().begin(), hello.identity_sig().end());

    if (!IdentityStore::verify(client_pub,
                               clientSigMsg(protocol::kVersion, client_pub, client_pk),
                               client_sig)) {
      errorOut = "Client signature verification failed";
      return false;
    }

    KyberKEM kem;
    kem.init();
    std::vector<uint8_t> ct, ss;
    kem.encapsulate(client_pk, ct, ss);

    // Full transcript hash binds both identities, both KEM values and version.
    const auto H = transcriptHash(protocol::kVersion, client_pub, client_pk, identity_.pub, ct);
    auto sig = IdentityStore::sign(identity_.priv, serverSigMsg(H));

    // Directional data keys + independent key-confirmation key.
    auto k_c2s = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_c2s(), 32);
    auto k_s2c = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_s2c(), 32);
    auto k_confirm = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_confirm(), 32);

    const auto confirm_s = hmac_sha256(k_confirm, confirmMsg('s', H));

    // Msg 2 (server -> client): HandshakeResponse with signature + confirm_s.
    HandshakeResponse resp;
    resp.set_version(protocol::kVersion);
    resp.set_kem_ciphertext(std::string(reinterpret_cast<const char*>(ct.data()), ct.size()));
    resp.set_identity_pub(std::string(reinterpret_cast<const char*>(identity_.pub.data()), identity_.pub.size()));
    resp.set_identity_sig(std::string(reinterpret_cast<const char*>(sig.data()), sig.size()));
    resp.set_confirm(std::string(reinterpret_cast<const char*>(confirm_s.data()), confirm_s.size()));

    std::string resp_bytes;
    if (!resp.SerializeToString(&resp_bytes)) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(k_c2s.data(), k_c2s.size());
      OPENSSL_cleanse(k_s2c.data(), k_s2c.size());
      OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
      errorOut = "Failed to serialize HandshakeResponse";
      return false;
    }
    if (!send(std::vector<uint8_t>(resp_bytes.begin(), resp_bytes.end()))) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(k_c2s.data(), k_c2s.size());
      OPENSSL_cleanse(k_s2c.data(), k_s2c.size());
      OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
      errorOut = "Failed to send HandshakeResponse";
      return false;
    }

    // Msg 3 (client -> server): HandshakeConfirm. Only after verifying the
    // client's confirmation is the server session ready.
    std::vector<uint8_t> conf_frame;
    if (!recv(conf_frame)) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(k_c2s.data(), k_c2s.size());
      OPENSSL_cleanse(k_s2c.data(), k_s2c.size());
      OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
      errorOut = "Failed to receive HandshakeConfirm";
      return false;
    }
    HandshakeConfirm conf;
    if (!conf.ParseFromArray(conf_frame.data(), static_cast<int>(conf_frame.size()))) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(k_c2s.data(), k_c2s.size());
      OPENSSL_cleanse(k_s2c.data(), k_s2c.size());
      OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
      errorOut = "Failed to parse HandshakeConfirm";
      return false;
    }
    std::vector<uint8_t> confirm_c(conf.confirm().begin(), conf.confirm().end());
    const auto expect_c = hmac_sha256(k_confirm, confirmMsg('c', H));
    if (!ct_equal(confirm_c, expect_c)) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(k_c2s.data(), k_c2s.size());
      OPENSSL_cleanse(k_s2c.data(), k_s2c.size());
      OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
      errorOut = "Client key confirmation failed";
      return false;
    }

    // The server encrypts with k_s2c (send) and decrypts with k_c2s (recv) —
    // mirror of the client.
    session_.set_keys(k_s2c, k_c2s);
    role_ = Role::Server;
    sessionReady_ = true;

    // Zeroize sensitive intermediate key material; the Session keeps its own copy.
    OPENSSL_cleanse(ss.data(), ss.size());
    OPENSSL_cleanse(k_c2s.data(), k_c2s.size());
    OPENSSL_cleanse(k_s2c.data(), k_s2c.size());
    OPENSSL_cleanse(k_confirm.data(), k_confirm.size());

    peerFingerprintOut = IdentityStore::fingerprint_hex(client_pub);
    return true;
  } catch (const std::exception& ex) {
    errorOut = ex.what();
    return false;
  }
}
