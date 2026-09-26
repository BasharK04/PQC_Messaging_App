// Derive cryptographic keys (32-byte AES) from the ML-KEM shared secret.

#pragma once
#include <vector>
#include <cstddef>
#include <cstdint>
#include <string>

std::vector<uint8_t> hkdf_sha256(const std::vector<uint8_t>& ikm,
                                 const std::vector<uint8_t>& salt,
                                 const std::vector<uint8_t>& info,
                                 size_t out_len);
