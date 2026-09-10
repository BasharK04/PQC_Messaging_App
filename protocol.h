#pragma once
#include <cstdint>
#include <vector>

namespace protocol {
constexpr uint32_t kVersion = 1;

inline const std::vector<uint8_t>& hkdf_salt() {
  static const std::vector<uint8_t> k = {'E','2','E','E','-','v','1'};
  return k;
}

inline const std::vector<uint8_t>& hkdf_info() {
  static const std::vector<uint8_t> k = {'A','E','S','-','2','5','6','-','G','C','M'};
  return k;
}

// Directional HKDF info labels. The single KEM shared secret is expanded into
// two independent AES-256-GCM keys, one per direction, so the client and server
// never share a single symmetric key (kills reflection attacks).
inline const std::vector<uint8_t>& hkdf_info_c2s() {
  // "E2EE-v1|key|c2s"
  static const std::vector<uint8_t> k = {'E','2','E','E','-','v','1','|','k','e','y','|','c','2','s'};
  return k;
}

inline const std::vector<uint8_t>& hkdf_info_s2c() {
  // "E2EE-v1|key|s2c"
  static const std::vector<uint8_t> k = {'E','2','E','E','-','v','1','|','k','e','y','|','s','2','c'};
  return k;
}

// HKDF info label for the handshake key-confirmation key. Derived from the same
// KEM shared secret but with a distinct info so it is independent of the
// directional data keys. Used to prove both sides derived the same secret.
inline const std::vector<uint8_t>& hkdf_info_confirm() {
  // "E2EE-v1|confirm"
  static const std::vector<uint8_t> k = {'E','2','E','E','-','v','1','|','c','o','n','f','i','r','m'};
  return k;
}

// HKDF info label for the whole-file integrity key. Derived from the same KEM
// shared secret but with a distinct info so it is independent of the directional
// data keys and the confirmation key. Both sides derive the same k_file, so the
// sender's HMAC over the plaintext file verifies on the receiver.
inline const std::vector<uint8_t>& hkdf_info_file() {
  // "E2EE-v1|file-hmac"
  static const std::vector<uint8_t> k =
      {'E','2','E','E','-','v','1','|','f','i','l','e','-','h','m','a','c'};
  return k;
}

// HKDF info label for the handshake identity-concealing key (k_outer). Derived
// from the same KEM shared secret the moment it is available, before either
// side's long-term identity key has been exchanged, so both parties' Ed25519
// identity keys and signatures can be sealed under it rather than sent in the
// clear. Independent of the directional data keys, the confirmation key, and
// the file key.
inline const std::vector<uint8_t>& hkdf_info_outer() {
  // "E2EE-v1|outer"
  static const std::vector<uint8_t> k =
      {'E','2','E','E','-','v','1','|','o','u','t','e','r'};
  return k;
}
} // namespace protocol

