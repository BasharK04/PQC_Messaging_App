#include "hkdf.h"
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/kdf.h>   // <-- required for HKDF APIs

std::vector<uint8_t> hkdf_sha256(const std::vector<uint8_t>& ikm,
                                 const std::vector<uint8_t>& salt,
                                 const std::vector<uint8_t>& info,
                                 size_t out_len) {
  std::vector<uint8_t> out(out_len);

  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (!pctx) throw std::runtime_error("HKDF: ctx new failed");

  if (EVP_PKEY_derive_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); throw std::runtime_error("HKDF: derive_init failed"); }
  if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) { EVP_PKEY_CTX_free(pctx); throw std::runtime_error("HKDF: set md failed"); }
  if (!salt.empty() && EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), (int)salt.size()) <= 0) { EVP_PKEY_CTX_free(pctx); throw std::runtime_error("HKDF: set salt failed"); }
  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), (int)ikm.size()) <= 0) { EVP_PKEY_CTX_free(pctx); throw std::runtime_error("HKDF: set key failed"); }
  if (!info.empty() && EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), (int)info.size()) <= 0) { EVP_PKEY_CTX_free(pctx); throw std::runtime_error("HKDF: set info failed"); }

  size_t len = out.size();
  if (EVP_PKEY_derive(pctx, out.data(), &len) <= 0 || len != out_len) {
    EVP_PKEY_CTX_free(pctx);
    throw std::runtime_error("HKDF: derive failed");
  }
  EVP_PKEY_CTX_free(pctx);
  return out;
}
