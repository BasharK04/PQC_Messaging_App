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
} // namespace protocol

