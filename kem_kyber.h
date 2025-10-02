#pragma once
#include <vector>
#include <cstdint>

// Forward-declare OQS type to avoid leaking headers here
struct OQS_KEM;

class KyberKEM {
public:
  KyberKEM();
  ~KyberKEM();

  // create a Kyber-512 KEM instance
  void init();

  // sizes
  size_t pk_len() const;
  size_t sk_len() const;
  size_t ct_len() const;
  size_t ss_len() const;

  // keypair
  void keypair(std::vector<uint8_t>& pk, std::vector<uint8_t>& sk);

  // server side: encapsulate to peer's pk -> ct, ss
  void encapsulate(const std::vector<uint8_t>& peer_pk,
                   std::vector<uint8_t>& ct,
                   std::vector<uint8_t>& ss);

  // client side: decapsulate using our sk -> ss
  void decapsulate(const std::vector<uint8_t>& ct,
                   const std::vector<uint8_t>& sk,
                   std::vector<uint8_t>& ss);

private:
  OQS_KEM* kem_ = nullptr;
};
