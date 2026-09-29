#include "kem_kyber.h"
#include <stdexcept>
#include <cstring>
#include <vector>

extern "C" {
#include <oqs/oqs.h>
}

KyberKEM::KyberKEM() = default;
KyberKEM::~KyberKEM() {
  if (kem_) { OQS_KEM_free(kem_); kem_ = nullptr; }
}

void KyberKEM::init() {
  // ML-KEM-768 (FIPS 203), the NIST-standardized form of CRYSTALS-Kyber. Note
  // this is a DIFFERENT algorithm from liboqs' OQS_KEM_alg_kyber_768, which is
  // the superseded Round 3 draft: the two differ in key-generation domain
  // separation and hashing and are not interchangeable on the wire.
  //
  // 768 targets NIST security category 3 and is the parameter set deployed in
  // practice (TLS hybrids, Signal's PQXDH), rather than the category-1 512 set.
  // It also balances the KEM against the AES-256-GCM data layer instead of
  // leaving key establishment as the weaker link.
  //
  // Sizes are 1184-byte encapsulation key / 1088-byte ciphertext / 32-byte
  // shared secret, but every length below is queried from liboqs rather than
  // hardcoded, so the parameter set can be changed here alone.
  // The Kyber* type names are retained for source continuity.
  kem_ = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!kem_) throw std::runtime_error("OQS_KEM_new ml_kem_768 failed");
}

size_t KyberKEM::pk_len() const { return kem_->length_public_key; }
size_t KyberKEM::sk_len() const { return kem_->length_secret_key; }
size_t KyberKEM::ct_len() const { return kem_->length_ciphertext; }
size_t KyberKEM::ss_len() const { return kem_->length_shared_secret; }

void KyberKEM::keypair(std::vector<uint8_t>& pk, std::vector<uint8_t>& sk) {
  if (!kem_) throw std::runtime_error("KEM not initialized");
  pk.resize(pk_len());
  sk.resize(sk_len());
  if (OQS_KEM_keypair(kem_, pk.data(), sk.data()) != OQS_SUCCESS)
    throw std::runtime_error("OQS_KEM_keypair failed");
}

void KyberKEM::encapsulate(const std::vector<uint8_t>& peer_pk,
                           std::vector<uint8_t>& ct,
                           std::vector<uint8_t>& ss) {
  if (!kem_) throw std::runtime_error("KEM not initialized");
  if (peer_pk.size() != pk_len()) throw std::runtime_error("peer pk size mismatch");
  ct.resize(ct_len());
  ss.resize(ss_len());
  if (OQS_KEM_encaps(kem_, ct.data(), ss.data(), peer_pk.data()) != OQS_SUCCESS)
    throw std::runtime_error("OQS_KEM_encaps failed");
}

void KyberKEM::decapsulate(const std::vector<uint8_t>& ct,
                           const std::vector<uint8_t>& sk,
                           std::vector<uint8_t>& ss) {
  if (!kem_) throw std::runtime_error("KEM not initialized");
  if (ct.size() != ct_len() || sk.size() != sk_len()) throw std::runtime_error("ct/sk size mismatch");
  ss.resize(ss_len());
  if (OQS_KEM_decaps(kem_, ss.data(), ct.data(), sk.data()) != OQS_SUCCESS)
    throw std::runtime_error("OQS_KEM_decaps failed");
}
