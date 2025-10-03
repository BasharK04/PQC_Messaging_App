#include "identity.h"
#include "crypto.h"
#include <stdexcept>
#include <fstream>
#include <cstring>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#if defined(_WIN32)
  #include <winsock2.h>
#else
  #include <arpa/inet.h>
#endif

static constexpr uint32_t FILE_VERSION = 1;
static constexpr uint32_t PBKDF2_ITERS = 200000;  // tweak as desired

void IdentityStore::random_bytes(std::vector<uint8_t>& buf) {
  if (RAND_bytes(buf.data(), (int)buf.size()) != 1) {
    throw std::runtime_error("RAND_bytes failed");
  }
}

void IdentityStore::gen_ed25519(Identity& out) {
  EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
  if (!kctx) throw std::runtime_error("EVP_PKEY_CTX_new_id ED25519 failed");
  if (EVP_PKEY_keygen_init(kctx) <= 0) { EVP_PKEY_CTX_free(kctx); throw std::runtime_error("keygen_init failed"); }

  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen(kctx, &pkey) <= 0) { EVP_PKEY_CTX_free(kctx); throw std::runtime_error("keygen failed"); }
  EVP_PKEY_CTX_free(kctx);

  size_t pub_len = 0, priv_len = 0;
  if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &pub_len) <= 0) { EVP_PKEY_free(pkey); throw std::runtime_error("get_raw_public_key len failed"); }
  if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &priv_len) <= 0) { EVP_PKEY_free(pkey); throw std::runtime_error("get_raw_private_key len failed"); }
  out.pub.resize(pub_len);
  out.priv.resize(priv_len);
  if (EVP_PKEY_get_raw_public_key(pkey, out.pub.data(), &pub_len) <= 0) { EVP_PKEY_free(pkey); throw std::runtime_error("get_raw_public_key failed"); }
  if (EVP_PKEY_get_raw_private_key(pkey, out.priv.data(), &priv_len) <= 0) { EVP_PKEY_free(pkey); throw std::runtime_error("get_raw_private_key failed"); }

  EVP_PKEY_free(pkey);
}

std::vector<uint8_t> IdentityStore::pbkdf2_sha256(const std::string& password,
                                                  const std::vector<uint8_t>& salt,
                                                  uint32_t iters,
                                                  size_t out_len) {
  std::vector<uint8_t> key(out_len);
  if (PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(),
                        salt.data(), (int)salt.size(),
                        (int)iters, EVP_sha256(),
                        (int)out_len, key.data()) != 1) {
    throw std::runtime_error("PBKDF2 failed");
  }
  return key;
}

void IdentityStore::create_profile(const std::string& path, const std::string& password, Identity& out) {
  gen_ed25519(out);

  std::vector<uint8_t> salt(16); random_bytes(salt);
  std::vector<uint8_t> aes_key = pbkdf2_sha256(password, salt, PBKDF2_ITERS, 32);

  std::vector<uint8_t> nonce(AESGCMCrypto::NONCE_SIZE); random_bytes(nonce);
  AESGCMCrypto crypto(aes_key);
  std::vector<uint8_t> ct = crypto.encrypt(out.priv, nonce);

  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f) throw std::runtime_error("open profile for write failed");

  const char magic[8] = {'E','2','E','E','I','D','0','1'};
  f.write(magic, 8);
  uint32_t v = htonl(FILE_VERSION);
  f.write(reinterpret_cast<const char*>(&v), 4);

  uint32_t it = htonl(PBKDF2_ITERS);
  f.write(reinterpret_cast<const char*>(&it), 4);

  uint32_t sl = htonl((uint32_t)salt.size());
  f.write(reinterpret_cast<const char*>(&sl), 4);
  f.write(reinterpret_cast<const char*>(salt.data()), salt.size());

  uint32_t nl = htonl((uint32_t)nonce.size());
  f.write(reinterpret_cast<const char*>(&nl), 4);
  f.write(reinterpret_cast<const char*>(nonce.data()), nonce.size());

  uint32_t pl = htonl((uint32_t)out.pub.size());
  f.write(reinterpret_cast<const char*>(&pl), 4);
  f.write(reinterpret_cast<const char*>(out.pub.data()), out.pub.size());

  uint32_t cl = htonl((uint32_t)ct.size());
  f.write(reinterpret_cast<const char*>(&cl), 4);
  f.write(reinterpret_cast<const char*>(ct.data()), ct.size());

  if (!f.good()) throw std::runtime_error("write profile failed");
}

void IdentityStore::load_profile(const std::string& path, const std::string& password, Identity& out) {
  std::ifstream f(path, std::ios::binary);
  if (!f) throw std::runtime_error("open profile for read failed");

  char magic[8]; f.read(magic, 8);
  if (std::string(magic, 8) != "E2EEID01") throw std::runtime_error("bad magic");
  uint32_t v=0; f.read(reinterpret_cast<char*>(&v), 4); v = ntohl(v);
  if (v != FILE_VERSION) throw std::runtime_error("unsupported version");

  uint32_t it=0; f.read(reinterpret_cast<char*>(&it), 4); it = ntohl(it);

  uint32_t sl=0; f.read(reinterpret_cast<char*>(&sl), 4); sl = ntohl(sl);
  if (sl == 0 || sl > 1024) throw std::runtime_error("profile corrupt (salt)");
  std::vector<uint8_t> salt(sl); f.read(reinterpret_cast<char*>(salt.data()), sl);

  uint32_t nl=0; f.read(reinterpret_cast<char*>(&nl), 4); nl = ntohl(nl);
  if (nl != AESGCMCrypto::NONCE_SIZE) throw std::runtime_error("profile corrupt (nonce)");
  std::vector<uint8_t> nonce(nl); f.read(reinterpret_cast<char*>(nonce.data()), nl);

  uint32_t pl=0; f.read(reinterpret_cast<char*>(&pl), 4); pl = ntohl(pl);
  if (pl != 32) throw std::runtime_error("profile corrupt (pub)");
  out.pub.resize(pl); f.read(reinterpret_cast<char*>(out.pub.data()), pl);

  uint32_t cl=0; f.read(reinterpret_cast<char*>(&cl), 4); cl = ntohl(cl);
  if (cl < AESGCMCrypto::TAG_SIZE || cl > 4096) throw std::runtime_error("profile corrupt (ct)");
  std::vector<uint8_t> ct(cl); f.read(reinterpret_cast<char*>(ct.data()), cl);

  if (!f.good()) throw std::runtime_error("read profile failed");

  std::vector<uint8_t> aes_key = pbkdf2_sha256(password, salt, it, 32);
  AESGCMCrypto crypto(aes_key);
  out.priv = crypto.decrypt(ct, nonce);
}

std::vector<uint8_t> IdentityStore::sign(const std::vector<uint8_t>& priv32,
                                         const std::vector<uint8_t>& msg) {
  EVP_PKEY* sk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                              priv32.data(), priv32.size());
  if (!sk) throw std::runtime_error("new_raw_private_key failed");

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) { EVP_PKEY_free(sk); throw std::runtime_error("MD_CTX_new failed"); }

  size_t siglen = 0;
  if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, sk) <= 0 ||
      EVP_DigestSign(mdctx, nullptr, &siglen, msg.data(), msg.size()) <= 0) {
    EVP_MD_CTX_free(mdctx); EVP_PKEY_free(sk); throw std::runtime_error("sign precompute failed");
  }
  std::vector<uint8_t> sig(siglen);
  if (EVP_DigestSign(mdctx, sig.data(), &siglen, msg.data(), msg.size()) <= 0) {
    EVP_MD_CTX_free(mdctx); EVP_PKEY_free(sk); throw std::runtime_error("sign failed");
  }
  sig.resize(siglen);
  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(sk);
  return sig;
}

bool IdentityStore::verify(const std::vector<uint8_t>& pub32,
                           const std::vector<uint8_t>& msg,
                           const std::vector<uint8_t>& sig) {
  EVP_PKEY* pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                             pub32.data(), pub32.size());
  if (!pk) return false;

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) { EVP_PKEY_free(pk); return false; }

  bool ok = (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pk) > 0) &&
            (EVP_DigestVerify(mdctx, sig.data(), sig.size(), msg.data(), msg.size()) > 0);

  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pk);
  return ok;
}

std::string IdentityStore::fingerprint_hex(const std::vector<uint8_t>& pub32) {
  unsigned char h[SHA256_DIGEST_LENGTH];
  SHA256(pub32.data(), pub32.size(), h);
  static const char* HEX = "0123456789abcdef";
  std::ostringstream oss;
  for (size_t i=0;i<SHA256_DIGEST_LENGTH;i++) {
    oss << HEX[h[i]>>4] << HEX[h[i]&0xF];
  }
  return oss.str();
}
