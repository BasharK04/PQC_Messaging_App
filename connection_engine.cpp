#include "connection_engine.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <system_error>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "envelope.pb.h"
#include "handshake.pb.h"
#include "hkdf.h"
#include "kem_kyber.h"
#include "messages.pb.h"
#include "crypto.h"
#include "file_transfer.h"
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

// v2 transcript hashes. Because the client's identity is not revealed to the
// server until msg3, the transcript is split into two domain-separated
// hashes rather than the single v1 H:
//
//   H_s = SHA256( "E2EE-HS-v2|s" || version_be32
//                 || lp(kem_pk) || lp(kem_ct) || lp(server_id_pub) )
//   H_c = SHA256( "E2EE-HS-v2|c" || version_be32
//                 || lp(kem_pk) || lp(kem_ct) || lp(server_id_pub) || lp(client_id_pub) )
//
// H_s is computable by both sides the moment the server's contribution (KEM
// ciphertext + server identity key) is known -- i.e. before the client's
// identity has been revealed -- and is what the server signs and binds into
// confirm_s. H_c extends H_s with the client's own identity key, so the
// client's signature over H_c commits to exactly which server identity it
// talked to: a relay cannot splice the client's msg3 onto a handshake
// carrying a different server identity without changing H_c and breaking the
// client signature (this is what prevents identity misbinding).
std::vector<uint8_t> transcriptHashServer(uint32_t version,
                                          const std::vector<uint8_t>& kem_pk,
                                          const std::vector<uint8_t>& kem_ct,
                                          const std::vector<uint8_t>& server_pub) {
  static const char kPrefix[] = "E2EE-HS-v2|s";
  std::vector<uint8_t> t(kPrefix, kPrefix + sizeof(kPrefix) - 1);
  put_u32_be(t, version);
  put_lp(t, kem_pk);
  put_lp(t, kem_ct);
  put_lp(t, server_pub);
  return sha256(t);
}

std::vector<uint8_t> transcriptHashClient(uint32_t version,
                                          const std::vector<uint8_t>& kem_pk,
                                          const std::vector<uint8_t>& kem_ct,
                                          const std::vector<uint8_t>& server_pub,
                                          const std::vector<uint8_t>& client_pub) {
  static const char kPrefix[] = "E2EE-HS-v2|c";
  std::vector<uint8_t> t(kPrefix, kPrefix + sizeof(kPrefix) - 1);
  put_u32_be(t, version);
  put_lp(t, kem_pk);
  put_lp(t, kem_ct);
  put_lp(t, server_pub);
  put_lp(t, client_pub);
  return sha256(t);
}

// Message the SERVER signs: prefix || H_s.
std::vector<uint8_t> serverSigMsg(const std::vector<uint8_t>& H_s) {
  static const char kPrefix[] = "E2EE-HS-v2|server|";
  std::vector<uint8_t> m(kPrefix, kPrefix + sizeof(kPrefix) - 1);
  m.insert(m.end(), H_s.begin(), H_s.end());
  return m;
}

// Message the CLIENT signs: prefix || H_c.
std::vector<uint8_t> clientSigMsg(const std::vector<uint8_t>& H_c) {
  static const char kPrefix[] = "E2EE-HS-v2|client|";
  std::vector<uint8_t> m(kPrefix, kPrefix + sizeof(kPrefix) - 1);
  m.insert(m.end(), H_c.begin(), H_c.end());
  return m;
}

// Key-confirmation MAC input: a one-byte direction tag ('s' or 'c') || H
// (H_s for the server's confirmation, H_c for the client's).
std::vector<uint8_t> confirmMsg(char tag, const std::vector<uint8_t>& H) {
  std::vector<uint8_t> m;
  m.reserve(1 + H.size());
  m.push_back(static_cast<uint8_t>(tag));
  m.insert(m.end(), H.begin(), H.end());
  return m;
}

// AAD for the identity-concealing seal (SealedIdentity): a one-byte direction
// tag plus the protocol version. Deliberately a SEPARATE helper from
// buildMessageAad below (even though the byte encoding is the same) because
// the two AAD domains must never be reused across each other -- this one
// authenticates the handshake identity seal, that one authenticates
// post-handshake message traffic.
std::vector<uint8_t> buildOuterAad(uint8_t dirTag, uint32_t version) {
  std::vector<uint8_t> aad;
  aad.reserve(1 + 4);
  aad.push_back(dirTag);
  put_u32_be(aad, version);
  return aad;
}

// Seal a SealedIdentity{identity_pub, identity_sig, confirm} blob under
// k_outer for one direction of the handshake. Throws std::runtime_error on
// serialization failure; AEAD/RNG failures propagate from AESGCMCrypto.
void sealIdentity(const std::vector<uint8_t>& k_outer, uint8_t dirTag, uint32_t version,
                  const std::vector<uint8_t>& id_pub, const std::vector<uint8_t>& id_sig,
                  const std::vector<uint8_t>& confirm,
                  std::vector<uint8_t>& nonceOut, std::vector<uint8_t>& sealedOut) {
  SealedIdentity si;
  si.set_identity_pub(reinterpret_cast<const char*>(id_pub.data()), id_pub.size());
  si.set_identity_sig(reinterpret_cast<const char*>(id_sig.data()), id_sig.size());
  si.set_confirm(reinterpret_cast<const char*>(confirm.data()), confirm.size());

  std::string si_bytes;
  if (!si.SerializeToString(&si_bytes)) {
    throw std::runtime_error("Failed to serialize SealedIdentity");
  }
  const std::vector<uint8_t> plain(si_bytes.begin(), si_bytes.end());

  nonceOut = AESGCMCrypto::random_nonce();
  AESGCMCrypto outer(k_outer);
  sealedOut = outer.encrypt(plain, nonceOut, buildOuterAad(dirTag, version));
}

// Open + parse a SealedIdentity blob sealed under k_outer for one direction.
// Returns false (never throws) on an AEAD open failure or a malformed
// plaintext, so callers can surface a clean handshake error.
bool openIdentity(const std::vector<uint8_t>& k_outer, uint8_t dirTag, uint32_t version,
                  const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& sealed,
                  std::vector<uint8_t>& idPubOut, std::vector<uint8_t>& idSigOut,
                  std::vector<uint8_t>& confirmOut) {
  std::vector<uint8_t> plain;
  try {
    AESGCMCrypto outer(k_outer);
    plain = outer.decrypt(sealed, nonce, buildOuterAad(dirTag, version));
  } catch (const std::exception&) {
    return false;
  }
  SealedIdentity si;
  if (!si.ParseFromArray(plain.data(), static_cast<int>(plain.size()))) {
    return false;
  }
  idPubOut.assign(si.identity_pub().begin(), si.identity_pub().end());
  idSigOut.assign(si.identity_sig().begin(), si.identity_sig().end());
  confirmOut.assign(si.confirm().begin(), si.confirm().end());
  return true;
}

// Canonical AAD bound into the AEAD tag: a per-direction constant plus the
// protocol version. Sealed-sender hardening moved ALL per-message metadata
// (sender id, seq, timestamp, kind, transfer id, chunk index) inside the
// encrypted InnerMessage (see framePlaintext/unframePlaintext below), so it is
// now confidential AND authenticated by the AEAD tag over the ciphertext
// itself. The AAD therefore carries nothing that varies per message — it only
// binds the direction (kills cross-direction reflection) and the version
// (kills cross-version downgrade splicing).
std::vector<uint8_t> buildMessageAad(uint8_t dirTag, uint32_t version) {
  std::vector<uint8_t> aad;
  aad.reserve(1 + 4);
  aad.push_back(dirTag);
  put_u32_be(aad, version);
  return aad;
}

// Padding buckets (bytes) for the framed AEAD plaintext, so ciphertext length
// never reveals the true message size beyond which bucket it landed in.
// Anything larger than the last fixed bucket rounds up to the next multiple
// of that bucket's size (262144), which comfortably covers a 256 KiB file
// chunk plus its InnerMessage/length-prefix overhead.
constexpr size_t kPadBuckets[] = {
    256, 512, 1024, 2048, 4096, 8192, 16384,
    32768, 65536, 131072, 262144,
};

size_t paddedBucketSize(size_t total) {
  for (size_t bucket : kPadBuckets) {
    if (total <= bucket) return bucket;
  }
  constexpr size_t kUnit = 262144;
  return ((total + kUnit - 1) / kUnit) * kUnit;
}

// Frame the serialized InnerMessage as [4-byte BE length][InnerMessage bytes]
// [random padding], padded so the TOTAL length lands exactly on a bucket
// boundary. This is what actually gets AEAD-encrypted, so ciphertext size
// only ever leaks a size bucket, never the true plaintext length.
std::vector<uint8_t> framePlaintext(const std::vector<uint8_t>& innerBytes) {
  const size_t total = 4 + innerBytes.size();
  const size_t bucket = paddedBucketSize(total);

  std::vector<uint8_t> out;
  out.reserve(bucket);
  put_u32_be(out, static_cast<uint32_t>(innerBytes.size()));
  out.insert(out.end(), innerBytes.begin(), innerBytes.end());

  const size_t padLen = bucket - total;
  if (padLen > 0) {
    std::vector<uint8_t> pad(padLen);
    if (RAND_bytes(pad.data(), static_cast<int>(pad.size())) != 1) {
      throw std::runtime_error("RAND_bytes failed (padding)");
    }
    out.insert(out.end(), pad.begin(), pad.end());
  }
  return out;
}

// Inverse of framePlaintext: read the 4-byte BE length prefix, validate it
// against the decrypted plaintext size, and hand back exactly those L bytes
// (the trailing padding is discarded). Returns false on a malformed frame
// (too short, or a declared length that overruns the plaintext).
bool unframePlaintext(const std::vector<uint8_t>& plain,
                      std::vector<uint8_t>& innerOut) {
  if (plain.size() < 4) return false;
  const uint32_t len = (static_cast<uint32_t>(plain[0]) << 24) |
                       (static_cast<uint32_t>(plain[1]) << 16) |
                       (static_cast<uint32_t>(plain[2]) << 8) |
                       static_cast<uint32_t>(plain[3]);
  if (static_cast<uint64_t>(len) > static_cast<uint64_t>(plain.size() - 4)) {
    return false;
  }
  innerOut.assign(plain.begin() + 4, plain.begin() + 4 + len);
  return true;
}

// Random nonzero 64-bit transfer id (0 is reserved for "not a file transfer").
uint64_t randomTransferId() {
  uint64_t v = 0;
  do {
    uint8_t b[8];
    if (RAND_bytes(b, static_cast<int>(sizeof(b))) != 1) {
      throw std::runtime_error("RAND_bytes failed");
    }
    v = 0;
    for (size_t i = 0; i < sizeof(b); ++i) v = (v << 8) | b[i];
  } while (v == 0);
  return v;
}
}  // namespace

// Reduce a possibly-hostile filename (it arrives inside an attacker-controllable
// FileMeta) to a safe basename. Strips every path component (both '/' and '\\'
// separators) and rejects anything that could still escape the downloads
// directory. Returns "" when no safe basename exists; callers must treat "" as
// "reject the transfer".
std::string sanitize_filename(const std::string& raw) {
  if (raw.find('\0') != std::string::npos) return "";
  const size_t pos = raw.find_last_of("/\\");
  std::string base = (pos == std::string::npos) ? raw : raw.substr(pos + 1);
  if (base.empty() || base == "." || base == "..") return "";
  return base;
}

ConnectionEngine::ConnectionEngine() = default;

ConnectionEngine::~ConnectionEngine() {
  // Drop any half-received transfers: close streams and delete partial files.
  while (!inbound_.empty()) abortInboundTransfer(inbound_.begin()->first);
}

void ConnectionEngine::abortInboundTransfer(uint64_t transferId) {
  auto it = inbound_.find(transferId);
  if (it == inbound_.end()) return;
  if (it->second.out.is_open()) it->second.out.close();
  std::error_code ec;
  std::filesystem::remove(it->second.tempPath, ec);  // best effort
  inbound_.erase(it);
}

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

bool ConnectionEngine::encryptAndSerializeKind(uint32_t kind,
                                               uint64_t transferId,
                                               uint64_t chunkIndex,
                                               const std::vector<uint8_t>& body,
                                               const std::string& senderId,
                                               const std::string& toUsername,
                                               std::vector<uint8_t>& outBytes,
                                               std::string& errorOut) {
  if (!sessionReady_) {
    errorOut = "Session key not established";
    return false;
  }
  try {
    // Stamp a fresh monotonic sequence number and current timestamp. Text and
    // file messages share one seq space, so a relay can neither drop nor
    // reorder file chunks relative to chat traffic.
    const uint64_t seq = session_.next_send_seq();
    const int64_t ts = nowSeconds();
    const uint8_t dirTag = (role_ == Role::Server) ? kDirS2C : kDirC2S;

    // ALL per-message metadata (sender, recipient, timestamp, seq, kind,
    // transfer id, chunk index) goes INSIDE the InnerMessage, which is what
    // gets encrypted. Nothing but a direction tag and the version is bound as
    // AAD, so none of this leaks to the relay and none of it can be tampered
    // with independently of the ciphertext it travels in.
    InnerMessage inner;
    inner.set_sender_id(senderId);
    inner.set_recipient_id(toUsername);
    inner.set_timestamp_unix(ts);
    inner.set_seq(seq);
    inner.set_kind(kind);
    inner.set_transfer_id(transferId);
    inner.set_chunk_index(chunkIndex);
    inner.set_body(reinterpret_cast<const char*>(body.data()), body.size());

    std::string inner_bytes;
    if (!inner.SerializeToString(&inner_bytes)) {
      errorOut = "Failed to serialize InnerMessage";
      return false;
    }

    // Frame + pad to a fixed size bucket BEFORE encrypting, so the ciphertext
    // length only ever reveals a size bucket, never the true message length.
    const std::vector<uint8_t> innerVec(inner_bytes.begin(), inner_bytes.end());
    const auto plain = framePlaintext(innerVec);

    auto nonce = AESGCMCrypto::random_nonce();
    auto ct_tag = session_.encrypt(plain, nonce, buildMessageAad(dirTag, protocol::kVersion));

    Envelope env;
    env.set_version(protocol::kVersion);
    env.set_nonce(reinterpret_cast<const char*>(nonce.data()), nonce.size());
    env.set_ciphertext(reinterpret_cast<const char*>(ct_tag.data()), ct_tag.size());

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

bool ConnectionEngine::encryptAndSerializeMessage(const std::string& plaintext,
                                                  const std::string& senderId,
                                                  const std::string& toUsername,
                                                  std::vector<uint8_t>& outBytes,
                                                  std::string& errorOut) {
  // Chat text is just KIND_TEXT with no transfer identity. The real kind is
  // carried inside the encrypted InnerMessage, so an attacker cannot re-label
  // a text message as a file chunk (or vice versa) without breaking the GCM
  // tag over the ciphertext that kind is sealed inside of.
  return encryptAndSerializeKind(static_cast<uint32_t>(KIND_TEXT), 0, 0,
                                 std::vector<uint8_t>(plaintext.begin(), plaintext.end()),
                                 senderId, toUsername, outBytes, errorOut);
}

bool ConnectionEngine::sendFile(const std::string& path,
                                const std::string& senderId,
                                const std::string& toUsername,
                                const SendFrameFn& send,
                                const ProgressFn& progress,
                                std::string& errorOut) {
  if (!sessionReady_) {
    errorOut = "Session key not established";
    return false;
  }
  if (session_.file_key().empty()) {
    errorOut = "file key not established for this session";
    return false;
  }
  try {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec) || ec) {
      errorOut = "not a regular file: " + path;
      return false;
    }
    const auto fsize = std::filesystem::file_size(path, ec);
    if (ec) {
      errorOut = "cannot determine size of " + path + ": " + ec.message();
      return false;
    }
    const uint64_t totalBytes = static_cast<uint64_t>(fsize);
    if (totalBytes == 0) {
      errorOut = "refusing to send an empty file: " + path;
      return false;
    }

    const std::string base = sanitize_filename(std::filesystem::path(path).filename().string());
    if (base.empty()) {
      errorOut = "cannot derive a safe filename from: " + path;
      return false;
    }

    const uint64_t chunkBytes = static_cast<uint64_t>(kFileChunkBytes);
    const uint64_t chunkCount =
        totalBytes / chunkBytes + ((totalBytes % chunkBytes) ? 1 : 0);

    // Pass 1: stream the plaintext through HMAC-SHA256(k_file) so the receiver
    // can verify the whole file. Nothing but one chunk buffer is ever resident.
    std::vector<uint8_t> fileHmac;
    {
      std::ifstream in(path, std::ios::binary);
      if (!in) {
        errorOut = "cannot open file for reading: " + path;
        return false;
      }
      HmacSha256Stream mac(session_.file_key());
      std::vector<uint8_t> buf(kFileChunkBytes);
      uint64_t hashed = 0;
      while (in.read(reinterpret_cast<char*>(buf.data()),
                     static_cast<std::streamsize>(buf.size())) ||
             in.gcount() > 0) {
        const uint64_t got = static_cast<uint64_t>(in.gcount());
        if (got == 0) break;
        if (hashed + got > totalBytes) {
          errorOut = "file changed size while it was being sent: " + path;
          return false;
        }
        mac.update(buf.data(), static_cast<std::size_t>(got));
        hashed += got;
      }
      if (in.bad()) {
        errorOut = "read error while hashing " + path;
        return false;
      }
      if (hashed != totalBytes) {
        errorOut = "file changed size while it was being sent: " + path;
        return false;
      }
      fileHmac = mac.final_tag();
    }

    const uint64_t transferId = randomTransferId();

    // The offer (filename + size + whole-file HMAC) travels INSIDE the encrypted
    // payload, so the relay never learns what is being transferred.
    FileMeta meta;
    meta.set_filename(base);
    meta.set_size_bytes(totalBytes);
    meta.set_chunk_count(chunkCount);
    meta.set_chunk_bytes(static_cast<uint32_t>(chunkBytes));
    meta.set_file_hmac(reinterpret_cast<const char*>(fileHmac.data()), fileHmac.size());

    std::string meta_bytes;
    if (!meta.SerializeToString(&meta_bytes)) {
      errorOut = "Failed to serialize FileMeta";
      return false;
    }

    std::vector<uint8_t> frame;
    if (!encryptAndSerializeKind(static_cast<uint32_t>(KIND_FILE_OFFER), transferId, 0,
                                 std::vector<uint8_t>(meta_bytes.begin(), meta_bytes.end()),
                                 senderId, toUsername, frame, errorOut)) {
      return false;
    }
    if (!send(frame)) {
      errorOut = "failed to send file offer for " + base;
      return false;
    }

    // Pass 2: re-read and ship the chunks.
    std::ifstream in(path, std::ios::binary);
    if (!in) {
      errorOut = "cannot reopen file for reading: " + path;
      return false;
    }
    std::vector<uint8_t> buf(kFileChunkBytes);
    uint64_t sent = 0;
    uint64_t index = 0;
    while (sent < totalBytes) {
      const uint64_t want = std::min<uint64_t>(chunkBytes, totalBytes - sent);
      in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(want));
      if (static_cast<uint64_t>(in.gcount()) != want) {
        errorOut = "file changed size while it was being sent: " + path;
        return false;
      }
      std::vector<uint8_t> chunk(buf.begin(),
                                 buf.begin() + static_cast<std::ptrdiff_t>(want));
      if (!encryptAndSerializeKind(static_cast<uint32_t>(KIND_FILE_CHUNK), transferId, index,
                                   chunk, senderId, toUsername, frame, errorOut)) {
        return false;
      }
      if (!send(frame)) {
        errorOut = "failed to send file chunk " + std::to_string(index) + " of " + base;
        return false;
      }
      sent += want;
      ++index;
      if (progress) progress(sent, totalBytes);
    }
    // A file that grew between the two passes would desynchronise the HMAC the
    // receiver is about to check; fail loudly instead of shipping a bad file.
    if (index != chunkCount || in.peek() != std::char_traits<char>::eof()) {
      errorOut = "file changed size while it was being sent: " + path;
      return false;
    }

    if (!encryptAndSerializeKind(static_cast<uint32_t>(KIND_FILE_FIN), transferId, 0,
                                 std::vector<uint8_t>(), senderId, toUsername, frame,
                                 errorOut)) {
      return false;
    }
    if (!send(frame)) {
      errorOut = "failed to send file completion for " + base;
      return false;
    }
    return true;
  } catch (const std::exception& ex) {
    errorOut = ex.what();
    return false;
  }
}

bool ConnectionEngine::parseAndDecryptEvent(const std::vector<uint8_t>& frame,
                                            IncomingEvent& ev,
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
  if (env.version() != protocol::kVersion) {
    errorOut = "Unsupported/mismatched protocol version in Envelope";
    return false;
  }

  // Reconstruct the SAME AAD the sender bound: direction + version only. The
  // peer's sending direction is the opposite of ours. Everything else that
  // used to be bound as AAD (seq/sender/timestamp/kind/transfer id/chunk
  // index) is now confidential AND authenticated because it sits INSIDE the
  // ciphertext, sealed by the same GCM tag.
  const uint8_t dirTag = (role_ == Role::Server) ? kDirC2S : kDirS2C;
  const std::vector<uint8_t> nonce(env.nonce().begin(), env.nonce().end());
  const std::vector<uint8_t> ct_tag(env.ciphertext().begin(), env.ciphertext().end());
  std::vector<uint8_t> plain;
  try {
    // Authenticate first (this fails on any ciphertext/version tampering)...
    plain = session_.decrypt(ct_tag, nonce, buildMessageAad(dirTag, env.version()));
  } catch (const std::exception& ex) {
    errorOut = ex.what();
    return false;
  }

  std::vector<uint8_t> innerBytes;
  if (!unframePlaintext(plain, innerBytes)) {
    errorOut = "Malformed padded plaintext frame";
    return false;
  }
  InnerMessage inner;
  if (!inner.ParseFromArray(innerBytes.data(), static_cast<int>(innerBytes.size()))) {
    errorOut = "Malformed InnerMessage";
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

  // ...then enforce strict monotonic sequencing to reject replays / reordering.
  // Done only after a successful tag check (and after parsing the now-trusted
  // metadata out of it) so an unauthenticated frame cannot poison the counter.
  if (!session_.accept_recv_seq(seq)) {
    errorOut = "replay or reordering detected (non-monotonic seq)";
    return false;
  }

  ev = IncomingEvent{};
  const uint32_t kind = inner.kind();
  const uint64_t transferId = inner.transfer_id();
  const std::vector<uint8_t> body(inner.body().begin(), inner.body().end());

  // KIND_UNSPECIFIED (0) is treated as text for wire compatibility with peers
  // that predate the file-transfer kinds.
  if (kind == static_cast<uint32_t>(KIND_UNSPECIFIED) ||
      kind == static_cast<uint32_t>(KIND_TEXT)) {
    ev.type = IncomingEvent::Type::Text;
    ev.text.assign(body.begin(), body.end());
    return true;
  }

  if (kind == static_cast<uint32_t>(KIND_FILE_OFFER)) {
    if (transferId == 0) {
      errorOut = "file offer with reserved transfer id 0";
      return false;
    }
    if (inbound_.find(transferId) != inbound_.end()) {
      errorOut = "duplicate transfer id in file offer";
      return false;
    }
    if (session_.file_key().empty()) {
      errorOut = "file key not established for this session";
      return false;
    }

    FileMeta meta;
    if (!meta.ParseFromArray(body.data(), static_cast<int>(body.size()))) {
      errorOut = "Malformed FileMeta in file offer";
      return false;
    }

    // The filename is fully attacker-controlled: reduce it to a basename and
    // reject anything that could escape the downloads directory.
    const std::string base = sanitize_filename(meta.filename());
    if (base.empty()) {
      errorOut = "unsafe filename in file offer";
      return false;
    }

    const uint32_t chunkBytes = meta.chunk_bytes();
    if (chunkBytes == 0 || chunkBytes > kFileChunkBytes) {
      errorOut = "invalid chunk size in file offer";
      return false;
    }
    const uint64_t sizeBytes = meta.size_bytes();
    if (sizeBytes == 0) {
      errorOut = "invalid file size in file offer";
      return false;
    }
    // Recompute the chunk count instead of trusting it (division first so a
    // huge declared size cannot overflow the round-up).
    const uint64_t expectedChunks =
        sizeBytes / chunkBytes + ((sizeBytes % chunkBytes) ? 1 : 0);
    if (meta.chunk_count() != expectedChunks) {
      errorOut = "inconsistent chunk count in file offer";
      return false;
    }
    if (meta.file_hmac().size() != 32) {
      errorOut = "invalid file HMAC in file offer";
      return false;
    }

    std::error_code ec;
    std::filesystem::create_directories(downloadDir_, ec);
    if (!std::filesystem::is_directory(downloadDir_)) {
      errorOut = "cannot create downloads directory " + downloadDir_ +
                 (ec ? (": " + ec.message()) : std::string());
      return false;
    }

    std::filesystem::path finalPath = std::filesystem::path(downloadDir_) / base;
    if (std::filesystem::exists(finalPath)) {
      // Never clobber an existing download; disambiguate with the transfer id.
      finalPath = std::filesystem::path(downloadDir_) /
                  (std::to_string(transferId) + "_" + base);
    }

    InboundTransfer t;
    t.filename = base;
    t.finalPath = finalPath.string();
    t.tempPath = t.finalPath + ".part";
    t.sizeBytes = sizeBytes;
    t.chunkCount = expectedChunks;
    t.chunkBytes = chunkBytes;
    t.expectedHmac.assign(meta.file_hmac().begin(), meta.file_hmac().end());
    t.out.open(t.tempPath, std::ios::binary | std::ios::trunc);
    if (!t.out) {
      errorOut = "cannot open " + t.tempPath + " for writing";
      return false;
    }
    try {
      t.hmac = std::make_unique<HmacSha256Stream>(session_.file_key());
    } catch (const std::exception& ex) {
      t.out.close();
      std::filesystem::remove(t.tempPath, ec);
      errorOut = ex.what();
      return false;
    }

    ev.type = IncomingEvent::Type::FileOffer;
    ev.filename = t.filename;
    ev.transferId = transferId;
    ev.sizeBytes = t.sizeBytes;
    ev.chunkCount = t.chunkCount;
    inbound_.emplace(transferId, std::move(t));
    return true;
  }

  if (kind == static_cast<uint32_t>(KIND_FILE_CHUNK)) {
    auto it = inbound_.find(transferId);
    if (it == inbound_.end()) {
      errorOut = "file chunk for an unknown transfer";
      return false;
    }
    InboundTransfer& t = it->second;
    const uint64_t idx = inner.chunk_index();
    const uint64_t len = static_cast<uint64_t>(body.size());

    // Chunks must arrive in exactly the order they were produced, and the
    // declared geometry from the offer is the only thing we will write.
    if (idx != t.nextChunkIndex || idx >= t.chunkCount) {
      abortInboundTransfer(transferId);
      errorOut = "out-of-order file chunk";
      return false;
    }
    const bool isFinal = (idx + 1 == t.chunkCount);
    if (len == 0 || len > t.chunkBytes || (!isFinal && len != t.chunkBytes) ||
        t.bytesWritten + len > t.sizeBytes) {
      abortInboundTransfer(transferId);
      errorOut = "file chunk size does not match the offer";
      return false;
    }

    t.out.write(reinterpret_cast<const char*>(body.data()),
                static_cast<std::streamsize>(len));
    if (!t.out) {
      const std::string tmp = t.tempPath;
      abortInboundTransfer(transferId);
      errorOut = "failed writing to " + tmp;
      return false;
    }
    try {
      t.hmac->update(body.data(), body.size());
    } catch (const std::exception& ex) {
      abortInboundTransfer(transferId);
      errorOut = ex.what();
      return false;
    }
    t.nextChunkIndex = idx + 1;
    t.bytesWritten += len;

    ev.type = IncomingEvent::Type::FileChunk;
    ev.filename = t.filename;
    ev.transferId = transferId;
    ev.sizeBytes = t.sizeBytes;
    ev.chunkIndex = idx;
    ev.chunkCount = t.chunkCount;
    return true;
  }

  if (kind == static_cast<uint32_t>(KIND_FILE_FIN)) {
    auto it = inbound_.find(transferId);
    if (it == inbound_.end()) {
      errorOut = "file completion for an unknown transfer";
      return false;
    }
    InboundTransfer& t = it->second;
    if (!body.empty() || t.nextChunkIndex != t.chunkCount ||
        t.bytesWritten != t.sizeBytes) {
      abortInboundTransfer(transferId);
      errorOut = "incomplete file transfer";
      return false;
    }

    t.out.flush();
    t.out.close();
    if (!t.out) {
      const std::string tmp = t.tempPath;
      abortInboundTransfer(transferId);
      errorOut = "failed to finalize " + tmp;
      return false;
    }

    std::vector<uint8_t> tag;
    try {
      tag = t.hmac->final_tag();
    } catch (const std::exception& ex) {
      abortInboundTransfer(transferId);
      errorOut = ex.what();
      return false;
    }
    // Constant-time compare of the whole-file HMAC; a mismatch means the file
    // was corrupted or tampered with, so the partial file is deleted.
    if (tag.size() != t.expectedHmac.size() ||
        CRYPTO_memcmp(tag.data(), t.expectedHmac.data(), tag.size()) != 0) {
      abortInboundTransfer(transferId);
      errorOut = "file integrity check failed";
      return false;
    }

    const std::string filename = t.filename;
    const std::string tempPath = t.tempPath;
    const std::string finalPath = t.finalPath;
    const uint64_t sizeBytes = t.sizeBytes;
    const uint64_t chunkCount = t.chunkCount;

    std::error_code ec;
    std::filesystem::rename(tempPath, finalPath, ec);
    if (ec) {
      abortInboundTransfer(transferId);
      errorOut = "failed to move the received file into place: " + ec.message();
      return false;
    }
    inbound_.erase(transferId);

    ev.type = IncomingEvent::Type::FileDone;
    ev.filename = filename;
    ev.transferId = transferId;
    ev.sizeBytes = sizeBytes;
    ev.chunkCount = chunkCount;
    ev.savedPath = finalPath;
    return true;
  }

  errorOut = "unknown message kind " + std::to_string(kind);
  return false;
}

bool ConnectionEngine::parseAndDecryptMessage(const std::vector<uint8_t>& frame,
                                              std::string& plaintextOut,
                                              std::string& errorOut) {
  IncomingEvent ev;
  if (!parseAndDecryptEvent(frame, ev, errorOut)) return false;
  switch (ev.type) {
    case IncomingEvent::Type::Text:
      plaintextOut = ev.text;
      break;
    case IncomingEvent::Type::FileOffer:
      plaintextOut = "[file] incoming " + ev.filename + " (" +
                     std::to_string(ev.sizeBytes) + " bytes)";
      break;
    case IncomingEvent::Type::FileChunk:
      plaintextOut = "[file] " + ev.filename + " chunk " +
                     std::to_string(ev.chunkIndex + 1) + "/" +
                     std::to_string(ev.chunkCount);
      break;
    case IncomingEvent::Type::FileDone:
      plaintextOut = "[file] saved to " + ev.savedPath;
      break;
  }
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

    // Msg 1 (client -> server): fully anonymous -- version + our ephemeral KEM
    // public key only. No identity material of any kind travels in msg1, so a
    // relay/observer learns nothing about who is connecting.
    HandshakeHello hello;
    hello.set_version(protocol::kVersion);
    hello.set_kem_public_key(std::string(reinterpret_cast<const char*>(pk.data()), pk.size()));

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

    // Explicit version check (also bound into the outer AAD and H_s, so
    // tampering breaks either the identity seal or the server signature).
    if (resp.version() != protocol::kVersion) {
      errorOut = "Unsupported/mismatched protocol version in HandshakeResponse";
      return false;
    }

    std::vector<uint8_t> ct(resp.kem_ciphertext().begin(), resp.kem_ciphertext().end());
    std::vector<uint8_t> sealed_nonce(resp.sealed_nonce().begin(), resp.sealed_nonce().end());
    std::vector<uint8_t> sealed_identity(resp.sealed_identity().begin(), resp.sealed_identity().end());

    std::vector<uint8_t> ss;
    kem.decapsulate(ct, sk, ss);

    // Derive the identity-concealing key the instant the shared secret
    // exists -- BEFORE either side's long-term identity has been exchanged --
    // so the server's identity material can be opened.
    auto k_outer = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_outer(), 32);

    std::vector<uint8_t> server_pub, server_sig, confirm_s;
    if (!openIdentity(k_outer, kDirS2C, protocol::kVersion, sealed_nonce, sealed_identity,
                      server_pub, server_sig, confirm_s)) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(sk.data(), sk.size());
      OPENSSL_cleanse(k_outer.data(), k_outer.size());
      errorOut = "failed to open server identity";
      return false;
    }

    // Recompute H_s from the fields we now hold and verify the server
    // signature over "E2EE-HS-v2|server|" || H_s.
    const auto H_s = transcriptHashServer(protocol::kVersion, pk, ct, server_pub);
    if (!IdentityStore::verify(server_pub, serverSigMsg(H_s), server_sig)) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(sk.data(), sk.size());
      OPENSSL_cleanse(k_outer.data(), k_outer.size());
      errorOut = "Server signature verification failed";
      return false;
    }

    // Independent key-confirmation key, derived from the same shared secret.
    auto k_confirm = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_confirm(), 32);

    // Verify the server's key confirmation: proves the server derived the same
    // shared secret (catches a KEM/key mismatch or a swapped ciphertext).
    const auto expect_s = hmac_sha256(k_confirm, confirmMsg('s', H_s));
    if (!ct_equal(confirm_s, expect_s)) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(sk.data(), sk.size());
      OPENSSL_cleanse(k_outer.data(), k_outer.size());
      OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
      errorOut = "Server key confirmation failed";
      return false;
    }

    // H_c extends H_s with our own identity key, so our signature over it
    // commits to exactly which server identity we talked to (prevents
    // identity misbinding by a relay/forward).
    const auto H_c = transcriptHashClient(protocol::kVersion, pk, ct, server_pub, identity_.pub);
    auto client_sig = IdentityStore::sign(identity_.priv, clientSigMsg(H_c));
    const auto confirm_c = hmac_sha256(k_confirm, confirmMsg('c', H_c));

    // Msg 3 (client -> server): seal our identity + confirmation under k_outer.
    std::vector<uint8_t> conf_nonce, conf_sealed;
    try {
      sealIdentity(k_outer, kDirC2S, protocol::kVersion, identity_.pub, client_sig, confirm_c,
                  conf_nonce, conf_sealed);
    } catch (const std::exception& ex) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(sk.data(), sk.size());
      OPENSSL_cleanse(k_outer.data(), k_outer.size());
      OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
      errorOut = ex.what();
      return false;
    }

    HandshakeConfirm conf;
    conf.set_sealed_nonce(std::string(reinterpret_cast<const char*>(conf_nonce.data()), conf_nonce.size()));
    conf.set_sealed_identity(std::string(reinterpret_cast<const char*>(conf_sealed.data()), conf_sealed.size()));
    std::string conf_bytes;
    if (!conf.SerializeToString(&conf_bytes)) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(sk.data(), sk.size());
      OPENSSL_cleanse(k_outer.data(), k_outer.size());
      OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
      errorOut = "Failed to serialize HandshakeConfirm";
      return false;
    }
    if (!send(std::vector<uint8_t>(conf_bytes.begin(), conf_bytes.end()))) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(sk.data(), sk.size());
      OPENSSL_cleanse(k_outer.data(), k_outer.size());
      OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
      errorOut = "Failed to send HandshakeConfirm";
      return false;
    }

    // Only after msg3 is safely sent do we derive and install the directional
    // session keys and the file key.
    auto k_c2s = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_c2s(), 32);
    auto k_s2c = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_s2c(), 32);
    // Independent whole-file HMAC key: same shared secret, different info
    // string, so a file tag can never be confused with a data-key operation.
    auto k_file = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_file(), 32);

    session_.set_keys(k_c2s, k_s2c);
    session_.set_file_key(k_file);
    role_ = Role::Client;
    sessionReady_ = true;

    // Zeroize sensitive intermediate key material; the Session keeps its own copy.
    OPENSSL_cleanse(ss.data(), ss.size());
    OPENSSL_cleanse(sk.data(), sk.size());
    OPENSSL_cleanse(k_outer.data(), k_outer.size());
    OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
    OPENSSL_cleanse(k_c2s.data(), k_c2s.size());
    OPENSSL_cleanse(k_s2c.data(), k_s2c.size());
    OPENSSL_cleanse(k_file.data(), k_file.size());

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
    // Msg 1 (client -> server): HandshakeHello -- fully anonymous, no identity
    // material of any kind.
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

    // Explicit version check (also bound into H_s/H_c and the outer AAD, so
    // tampering breaks either the identity seal or a signature).
    if (hello.version() != protocol::kVersion) {
      errorOut = "Unsupported/mismatched protocol version in HandshakeHello";
      return false;
    }

    std::vector<uint8_t> client_pk(hello.kem_public_key().begin(), hello.kem_public_key().end());

    KyberKEM kem;
    kem.init();
    // Reject an empty or wrong-size (including grossly oversized) KEM public
    // key up front, before doing any further work with attacker-controlled
    // bytes.
    if (client_pk.empty() || client_pk.size() != kem.pk_len()) {
      errorOut = "invalid or missing client KEM public key in HandshakeHello";
      return false;
    }

    std::vector<uint8_t> ct, ss;
    kem.encapsulate(client_pk, ct, ss);

    // Derive the identity-concealing key and the key-confirmation key the
    // instant the shared secret exists.
    auto k_outer = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_outer(), 32);
    auto k_confirm = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_confirm(), 32);

    // H_s binds version + both KEM values + our OWN identity key. The
    // client's identity is not yet known to us at this point.
    const auto H_s = transcriptHashServer(protocol::kVersion, client_pk, ct, identity_.pub);
    auto server_sig = IdentityStore::sign(identity_.priv, serverSigMsg(H_s));
    const auto confirm_s = hmac_sha256(k_confirm, confirmMsg('s', H_s));

    // Msg 2 (server -> client): seal our identity + signature + confirmation
    // under k_outer instead of sending them in the clear.
    std::vector<uint8_t> sealed_nonce, sealed_identity;
    try {
      sealIdentity(k_outer, kDirS2C, protocol::kVersion, identity_.pub, server_sig, confirm_s,
                  sealed_nonce, sealed_identity);
    } catch (const std::exception& ex) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(k_outer.data(), k_outer.size());
      OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
      errorOut = ex.what();
      return false;
    }

    HandshakeResponse resp;
    resp.set_version(protocol::kVersion);
    resp.set_kem_ciphertext(std::string(reinterpret_cast<const char*>(ct.data()), ct.size()));
    resp.set_sealed_nonce(std::string(reinterpret_cast<const char*>(sealed_nonce.data()), sealed_nonce.size()));
    resp.set_sealed_identity(std::string(reinterpret_cast<const char*>(sealed_identity.data()), sealed_identity.size()));

    std::string resp_bytes;
    if (!resp.SerializeToString(&resp_bytes)) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(k_outer.data(), k_outer.size());
      OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
      errorOut = "Failed to serialize HandshakeResponse";
      return false;
    }
    if (!send(std::vector<uint8_t>(resp_bytes.begin(), resp_bytes.end()))) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(k_outer.data(), k_outer.size());
      OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
      errorOut = "Failed to send HandshakeResponse";
      return false;
    }

    // Msg 3 (client -> server): HandshakeConfirm. Only after verifying the
    // client's identity, signature, and confirmation is the server session
    // ready.
    std::vector<uint8_t> conf_frame;
    if (!recv(conf_frame)) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(k_outer.data(), k_outer.size());
      OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
      errorOut = "Failed to receive HandshakeConfirm";
      return false;
    }
    HandshakeConfirm conf;
    if (!conf.ParseFromArray(conf_frame.data(), static_cast<int>(conf_frame.size()))) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(k_outer.data(), k_outer.size());
      OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
      errorOut = "Failed to parse HandshakeConfirm";
      return false;
    }

    std::vector<uint8_t> conf_nonce(conf.sealed_nonce().begin(), conf.sealed_nonce().end());
    std::vector<uint8_t> conf_sealed(conf.sealed_identity().begin(), conf.sealed_identity().end());

    std::vector<uint8_t> client_pub, client_sig, confirm_c;
    if (!openIdentity(k_outer, kDirC2S, protocol::kVersion, conf_nonce, conf_sealed,
                      client_pub, client_sig, confirm_c)) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(k_outer.data(), k_outer.size());
      OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
      errorOut = "failed to open client identity";
      return false;
    }

    // H_c extends H_s with the client's identity key: verify the client
    // committed to exactly OUR identity (prevents identity misbinding) and
    // that it derived the same shared secret.
    const auto H_c = transcriptHashClient(protocol::kVersion, client_pk, ct, identity_.pub, client_pub);
    if (!IdentityStore::verify(client_pub, clientSigMsg(H_c), client_sig)) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(k_outer.data(), k_outer.size());
      OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
      errorOut = "Client signature verification failed";
      return false;
    }
    const auto expect_c = hmac_sha256(k_confirm, confirmMsg('c', H_c));
    if (!ct_equal(confirm_c, expect_c)) {
      OPENSSL_cleanse(ss.data(), ss.size());
      OPENSSL_cleanse(k_outer.data(), k_outer.size());
      OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
      errorOut = "Client key confirmation failed";
      return false;
    }

    // Only now, after mutual authentication is fully complete, derive and
    // install the directional session keys and the file key.
    auto k_c2s = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_c2s(), 32);
    auto k_s2c = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_s2c(), 32);
    // Independent whole-file HMAC key: same shared secret, different info
    // string, so a file tag can never be confused with a data-key operation.
    auto k_file = hkdf_sha256(ss, protocol::hkdf_salt(), protocol::hkdf_info_file(), 32);

    // The server encrypts with k_s2c (send) and decrypts with k_c2s (recv) —
    // mirror of the client.
    session_.set_keys(k_s2c, k_c2s);
    session_.set_file_key(k_file);
    role_ = Role::Server;
    sessionReady_ = true;

    // Zeroize sensitive intermediate key material; the Session keeps its own copy.
    OPENSSL_cleanse(ss.data(), ss.size());
    OPENSSL_cleanse(k_outer.data(), k_outer.size());
    OPENSSL_cleanse(k_confirm.data(), k_confirm.size());
    OPENSSL_cleanse(k_c2s.data(), k_c2s.size());
    OPENSSL_cleanse(k_s2c.data(), k_s2c.size());
    OPENSSL_cleanse(k_file.data(), k_file.size());

    peerFingerprintOut = IdentityStore::fingerprint_hex(client_pub);
    return true;
  } catch (const std::exception& ex) {
    errorOut = ex.what();
    return false;
  }
}
