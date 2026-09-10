#pragma once
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/sha.h>

// Derives the opaque relay room token that is actually put on the wire (the
// WebSocket "room=" query value), so the relay operator and any on-path
// observer never see the real room name -- which, in GUI usage, IS the
// peer's username -- in the URL or in relay access logs.
//
//   token = lowercase hex( SHA256( "E2EE-room-v1" || lp(room) || lp(secret) ) )
//
// where lp(x) is a 4-byte big-endian length prefix followed by the raw bytes
// of x. Length-prefixing both inputs (rather than just concatenating them)
// means the boundary between `room` and `secret` is unambiguous, so e.g.
// room_token("ab","c") and room_token("a","bc") can never collide by having
// their concatenations coincide.
//
// Honest limitation: with a non-empty `secret` shared with your peer
// out-of-band, the token is opaque to the relay -- it cannot be reversed to
// the room name without knowing the secret. With an EMPTY secret, the token
// is only a keyless hash of a possibly-guessable room name: it stops casual
// log reading and trivial enumeration of the raw name, but it does NOT
// resist an offline dictionary attack that hashes a list of likely
// usernames/room names and compares against observed tokens. Use a shared
// secret when the room name itself must stay confidential against a
// dedicated adversary.

namespace room_token_detail {

inline void append_u32_be(std::vector<uint8_t>& out, uint32_t v) {
  out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
  out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
  out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(v & 0xFF));
}

// 4-byte big-endian length prefix followed by the raw bytes of `s`.
inline void append_length_prefixed(std::vector<uint8_t>& out, const std::string& s) {
  append_u32_be(out, static_cast<uint32_t>(s.size()));
  out.insert(out.end(), s.begin(), s.end());
}

}  // namespace room_token_detail

inline std::string room_token(const std::string& room, const std::string& secret) {
  static const std::string kDomainSep = "E2EE-room-v1";

  std::vector<uint8_t> msg;
  msg.reserve(kDomainSep.size() + 4 + room.size() + 4 + secret.size());
  msg.insert(msg.end(), kDomainSep.begin(), kDomainSep.end());
  room_token_detail::append_length_prefixed(msg, room);
  room_token_detail::append_length_prefixed(msg, secret);

  unsigned char digest[SHA256_DIGEST_LENGTH];
  unsigned int digest_len = 0;

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) throw std::runtime_error("room_token: EVP_MD_CTX_new failed");

  bool ok = (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) == 1) &&
            (EVP_DigestUpdate(mdctx, msg.data(), msg.size()) == 1) &&
            (EVP_DigestFinal_ex(mdctx, digest, &digest_len) == 1);
  EVP_MD_CTX_free(mdctx);

  if (!ok || digest_len != SHA256_DIGEST_LENGTH) {
    throw std::runtime_error("room_token: SHA256 digest failed");
  }

  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(SHA256_DIGEST_LENGTH * 2);
  for (unsigned int i = 0; i < digest_len; ++i) {
    out.push_back(kHex[(digest[i] >> 4) & 0xF]);
    out.push_back(kHex[digest[i] & 0xF]);
  }
  return out;
}
