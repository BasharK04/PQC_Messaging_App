#pragma once
#include <vector>
#include <cstdint>
#include "crypto.h"

// Minimal wrapper so Phase 4 (Kyber) can just call set_key()
class Session {
public:
  Session() = default;

  void set_key(const std::vector<uint8_t>& key) { key_ = key; }
  const std::vector<uint8_t>& key() const { return key_; }

  // Encrypt/decrypt via AES-GCM (nonce management stays with caller for now)
  std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                               const std::vector<uint8_t>& nonce) const {
    if (key_.empty()) throw std::runtime_error("Session key not set");
    AESGCMCrypto crypto(key_);
    return crypto.encrypt(plaintext, nonce);
  }

  std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ct_tag,
                               const std::vector<uint8_t>& nonce) const {
    if (key_.empty()) throw std::runtime_error("Session key not set");
    AESGCMCrypto crypto(key_);
    return crypto.decrypt(ct_tag, nonce);
  }

private:
  std::vector<uint8_t> key_; // will be filled by Kyber in Phase 4
};
