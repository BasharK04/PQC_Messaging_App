#pragma once
//
// Shared helpers for the encrypted, chunked file-transfer protocol:
//   - kFileChunkBytes: the fixed 256 KiB plaintext chunk size.
//   - HmacSha256Stream: streaming HMAC-SHA256 so the whole-file integrity tag can
//     be computed without ever holding the whole file in memory.
//   - sanitize_filename: reduce an attacker-controlled name to a safe basename.
//
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

// 256 KiB plaintext chunk size. Each encrypted chunk (chunk + 16-byte tag, plus
// protobuf/envelope overhead) stays far below the 16 MiB transport frame cap.
inline constexpr std::size_t kFileChunkBytes = 256 * 1024;

// Streaming HMAC-SHA256 over the OpenSSL 3 EVP_MAC API (no deprecated HMAC_CTX,
// so the build stays warning-clean). update() may be called many times; final()
// returns the 32-byte tag exactly once.
class HmacSha256Stream {
public:
  explicit HmacSha256Stream(const std::vector<uint8_t>& key) {
    mac_ = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!mac_) throw std::runtime_error("EVP_MAC_fetch(HMAC) failed");
    ctx_ = EVP_MAC_CTX_new(mac_);
    if (!ctx_) {
      EVP_MAC_free(mac_);
      mac_ = nullptr;
      throw std::runtime_error("EVP_MAC_CTX_new failed");
    }
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_end(),
    };
    if (EVP_MAC_init(ctx_, key.data(), key.size(), params) != 1) {
      EVP_MAC_CTX_free(ctx_);
      EVP_MAC_free(mac_);
      ctx_ = nullptr;
      mac_ = nullptr;
      throw std::runtime_error("EVP_MAC_init failed");
    }
  }

  ~HmacSha256Stream() {
    if (ctx_) EVP_MAC_CTX_free(ctx_);
    if (mac_) EVP_MAC_free(mac_);
  }

  HmacSha256Stream(const HmacSha256Stream&) = delete;
  HmacSha256Stream& operator=(const HmacSha256Stream&) = delete;

  void update(const uint8_t* data, std::size_t len) {
    if (len == 0) return;
    if (EVP_MAC_update(ctx_, data, len) != 1)
      throw std::runtime_error("EVP_MAC_update failed");
  }

  std::vector<uint8_t> final_tag() {
    std::vector<uint8_t> out(32);
    std::size_t outl = 0;
    if (EVP_MAC_final(ctx_, out.data(), &outl, out.size()) != 1 || outl != out.size())
      throw std::runtime_error("EVP_MAC_final failed");
    return out;
  }

private:
  EVP_MAC* mac_ = nullptr;
  EVP_MAC_CTX* ctx_ = nullptr;
};

// Reduce a possibly-hostile filename to a safe basename: strips any directory
// components and rejects empty, ".", "..", or names containing path separators
// or NUL. Returns "" for anything that cannot be made into a safe basename.
// Callers must treat "" as "reject this transfer".
std::string sanitize_filename(const std::string& raw);
