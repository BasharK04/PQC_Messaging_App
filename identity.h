#pragma once
#include <vector>
#include <string>
#include <cstdint>

struct Identity {
  std::vector<uint8_t> pub;   // 32 bytes
  std::vector<uint8_t> priv;  // 32 bytes (raw Ed25519 seed)
  bool is_loaded() const { return !pub.empty() && !priv.empty(); }
};

// File format (binary):
// magic[8] = "E2EEID01"
// uint32 version = 1
// uint32 pbkdf2_iters
// uint32 salt_len (16) + salt
// uint32 nonce_len (12) + nonce
// uint32 pub_len (32)  + pub
// uint32 ct_len        + ct||tag  (GCM tag appended)
class IdentityStore {
public:
  static void create_profile(const std::string& path, const std::string& password, Identity& out);
  static void load_profile(const std::string& path, const std::string& password, Identity& out);

  // Sign/verify with Ed25519 raw keys
  static std::vector<uint8_t> sign(const std::vector<uint8_t>& priv32,
                                   const std::vector<uint8_t>& msg);
  static bool verify(const std::vector<uint8_t>& pub32,
                     const std::vector<uint8_t>& msg,
                     const std::vector<uint8_t>& sig);

  // Utility: SHA-256 fingerprint (hex, first 16 bytes shown typically)
  static std::string fingerprint_hex(const std::vector<uint8_t>& pub32);

private:
  static void gen_ed25519(Identity& out);
  static void random_bytes(std::vector<uint8_t>& buf);
  static std::vector<uint8_t> pbkdf2_sha256(const std::string& password,
                                            const std::vector<uint8_t>& salt,
                                            uint32_t iters,
                                            size_t out_len);
};
