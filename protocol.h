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
} // namespace protocol

