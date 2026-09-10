#pragma once
#include <vector>
#include <cstdint>
#include <stdexcept>

#include <openssl/crypto.h>

#include "crypto.h"

// Directional session state established by the Kyber handshake.
//
// The KEM shared secret is expanded (via HKDF) into TWO independent AES-256-GCM
// keys, one per direction. Each side encrypts with its "send" key and decrypts
// with its "recv" key; the peer has them swapped. This kills reflection attacks
// where an attacker bounces a captured frame back at its sender.
//
// The session also owns a monotonic send counter and a last-received counter so
// callers can bind a sequence number into the AEAD AAD and reject replays /
// reordering on an already-ordered transport (WebSocket / TCP).
class Session {
public:
  Session() = default;

  // Zeroize every key buffer this session ever held. Unlike the ephemeral
  // handshake material (cleansed right after key derivation), the Session keeps
  // live keys for the whole connection, so they are wiped only at teardown.
  ~Session() {
    if (!sendKey_.empty()) OPENSSL_cleanse(sendKey_.data(), sendKey_.size());
    if (!recvKey_.empty()) OPENSSL_cleanse(recvKey_.data(), recvKey_.size());
    if (!fileKey_.empty()) OPENSSL_cleanse(fileKey_.data(), fileKey_.size());
  }

  // Session owns live key material; copying it would duplicate secrets. Nobody
  // copies a Session today, so make that explicit rather than leave a footgun.
  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;

  // Install the directional keys derived from the handshake.
  void set_keys(const std::vector<uint8_t>& sendKey,
                const std::vector<uint8_t>& recvKey) {
    sendKey_ = sendKey;
    recvKey_ = recvKey;
  }

  // Install the whole-file HMAC key derived from the handshake. Kept alongside
  // the data keys and wiped only in the destructor.
  void set_file_key(const std::vector<uint8_t>& fileKey) { fileKey_ = fileKey; }

  bool ready() const { return !sendKey_.empty() && !recvKey_.empty(); }

  const std::vector<uint8_t>& send_key() const { return sendKey_; }
  const std::vector<uint8_t>& recv_key() const { return recvKey_; }
  const std::vector<uint8_t>& file_key() const { return fileKey_; }

  // Encrypt with the send key; decrypt with the recv key. Optional AAD is bound
  // into the GCM tag so any tampering of the associated metadata is detected.
  std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                               const std::vector<uint8_t>& nonce,
                               const std::vector<uint8_t>& aad = {}) const {
    if (sendKey_.empty()) throw std::runtime_error("Session send key not set");
    AESGCMCrypto crypto(sendKey_);
    return crypto.encrypt(plaintext, nonce, aad);
  }

  std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ct_tag,
                               const std::vector<uint8_t>& nonce,
                               const std::vector<uint8_t>& aad = {}) const {
    if (recvKey_.empty()) throw std::runtime_error("Session recv key not set");
    AESGCMCrypto crypto(recvKey_);
    return crypto.decrypt(ct_tag, nonce, aad);
  }

  // Returns the next sequence number to stamp on an outgoing message. Starts at
  // 1 and increases by 1 for every encrypted message.
  uint64_t next_send_seq() { return ++sendSeq_; }

  // Accepts an incoming sequence number iff it is strictly greater than the last
  // one accepted (transport is ordered, so a strict increase is required).
  // Returns false for replays or reordering.
  bool accept_recv_seq(uint64_t seq) {
    if (seq <= lastRecvSeq_) return false;
    lastRecvSeq_ = seq;
    return true;
  }

  uint64_t last_recv_seq() const { return lastRecvSeq_; }

private:
  std::vector<uint8_t> sendKey_;
  std::vector<uint8_t> recvKey_;
  std::vector<uint8_t> fileKey_;  // whole-file HMAC key (k_file); wiped at teardown
  uint64_t sendSeq_ = 0;      // pre-increment => first sent message is seq 1
  uint64_t lastRecvSeq_ = 0;  // 0 means "nothing accepted yet"; first valid seq is >= 1
};
