#pragma once

#include <functional>
#include <string>
#include <vector>

#include "identity.h"
#include "session.h"

class ConnectionEngine {
public:
  using SendFrameFn = std::function<bool(const std::vector<uint8_t>&)>;
  using RecvFrameFn = std::function<bool(std::vector<uint8_t>&)>;

  ConnectionEngine();

  // Loads the identity from disk, or creates it if missing. Returns false on error and fills errorOut.
  bool loadOrCreateIdentity(const std::string& path,
                            const std::string& password,
                            std::string& fingerprintOut,
                            std::string& errorOut,
                            bool* created = nullptr);

  const Identity& identity() const { return identity_; }

  // Client role: send HandshakeHello, receive HandshakeResponse.
  bool runClientHandshake(const SendFrameFn& send,
                          const RecvFrameFn& recv,
                          std::string& peerFingerprintOut,
                          std::string& errorOut);

  // Server role: receive HandshakeHello, send HandshakeResponse.
  bool runServerHandshake(const SendFrameFn& send,
                          const RecvFrameFn& recv,
                          std::string& peerFingerprintOut,
                          std::string& errorOut);

  bool hasSession() const { return sessionReady_; }
  const Session& session() const { return session_; }

  // Encrypts plaintext and produces a serialized Envelope ready for transport.
  bool encryptAndSerializeMessage(const std::string& plaintext,
                                  const std::string& senderId,
                                  const std::string& toUsername,
                                  std::vector<uint8_t>& outBytes,
                                  std::string& errorOut) const;

  // Parses an incoming frame and decrypts the inner ChatMessage, returning plaintext.
  bool parseAndDecryptMessage(const std::vector<uint8_t>& frame,
                              std::string& plaintextOut,
                              std::string& errorOut) const;

private:
  bool clientHandshakeInternal(const SendFrameFn& send,
                               const RecvFrameFn& recv,
                               std::string& peerFingerprintOut,
                               std::string& errorOut);
  bool serverHandshakeInternal(const SendFrameFn& send,
                               const RecvFrameFn& recv,
                               std::string& peerFingerprintOut,
                               std::string& errorOut);

  Identity identity_;
  Session session_;
  bool sessionReady_ = false;
};
