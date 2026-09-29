#pragma once

#include <cstdint>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "file_transfer.h"
#include "identity.h"
#include "session.h"

// One observable milestone of the handshake, reported to an OPTIONAL observer
// (see ConnectionEngine::setHandshakeObserver) purely for UI visualization.
//
// SECURITY: a HandshakeStep never carries key material, the KEM shared
// secret, or any private key -- only algorithm/step names, PUBLIC byte
// counts (KEM public key / ciphertext / signature sizes), and fingerprint
// hex (already public; the same value IdentityStore::fingerprint_hex()
// produces elsewhere). Every call site in connection_engine.cpp that reports
// a step was reviewed against this rule.
struct HandshakeStep {
  enum class Id {
    IdentityReady, KemKeypair, HelloSent, HelloReceived, Encapsulated,
    Decapsulated, IdentitySealed, IdentityOpened, SignatureVerified,
    KeysDerived, ConfirmVerified, Complete
  };
  Id id;
  std::string detail;   // short human-readable, e.g. "ML-KEM-768 public key: 1184 bytes"
  uint64_t bytes = 0;   // 0 when not applicable
};
using HandshakeObserverFn = std::function<void(const HandshakeStep&)>;

class ConnectionEngine {
public:
  using SendFrameFn = std::function<bool(const std::vector<uint8_t>&)>;
  using RecvFrameFn = std::function<bool(std::vector<uint8_t>&)>;
  // Progress callback for sendFile: (bytesSent, totalBytes). May be null.
  using ProgressFn = std::function<void(uint64_t, uint64_t)>;

  // A decoded incoming frame: either chat text or a file-transfer event.
  struct IncomingEvent {
    enum class Type { Text, FileOffer, FileChunk, FileDone };
    Type type = Type::Text;
    std::string text;         // Type::Text only
    std::string filename;     // file events: sanitized basename
    uint64_t transferId = 0;  // file events
    uint64_t sizeBytes = 0;   // file events: total plaintext size
    uint64_t chunkIndex = 0;  // Type::FileChunk: 0-based index just received
    uint64_t chunkCount = 0;  // file events: total number of chunks
    std::string savedPath;    // Type::FileDone: final path under the downloads dir
  };

  ConnectionEngine();
  ~ConnectionEngine();

  // Loads the identity from disk, or creates it if missing. Returns false on error and fills errorOut.
  bool loadOrCreateIdentity(const std::string& path,
                            const std::string& password,
                            std::string& fingerprintOut,
                            std::string& errorOut,
                            bool* created = nullptr);

  const Identity& identity() const { return identity_; }

  // Optional observer invoked at real handshake milestones (see HandshakeStep
  // above), purely so a GUI can render genuine progress instead of faking it.
  // Default is none (null), which is a complete no-op: every call site checks
  // the observer before doing any extra work, so a null observer costs
  // nothing and changes zero handshake behavior. The observer is invoked
  // synchronously on whichever thread runs the handshake; a caller crossing
  // into a GUI thread must hop via a queued connection itself. Any exception
  // thrown by the observer is caught and discarded inside the engine so a
  // misbehaving GUI callback can never alter handshake control flow or skip
  // a cleanse.
  void setHandshakeObserver(HandshakeObserverFn fn);

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
  // Non-const: advances the per-session send sequence counter.
  bool encryptAndSerializeMessage(const std::string& plaintext,
                                  const std::string& senderId,
                                  const std::string& toUsername,
                                  std::vector<uint8_t>& outBytes,
                                  std::string& errorOut);

  // Streams a file to the peer as offer -> 256 KiB chunks -> fin, all through the
  // normal Session encrypt path (fresh nonce, directional key, shared monotonic
  // seq space with text messages). Two passes over the file: first to compute the
  // whole-file HMAC (carried inside the encrypted offer), then to send chunks.
  // Never loads the whole file into memory. progress may be null.
  bool sendFile(const std::string& path,
                const std::string& senderId,
                const std::string& toUsername,
                const SendFrameFn& send,
                const ProgressFn& progress,
                std::string& errorOut);

  // Parses an incoming frame, decrypts it and classifies it as text or a file
  // event. File chunks are streamed to disk under the downloads directory
  // (default "./received/"); on the FIN message the whole-file HMAC is verified
  // before Type::FileDone is reported. Any per-transfer violation (out-of-order
  // chunk, size mismatch, bad HMAC, ...) aborts that transfer, deletes the
  // partial file and returns false — the session itself stays usable.
  bool parseAndDecryptEvent(const std::vector<uint8_t>& frame,
                            IncomingEvent& ev,
                            std::string& errorOut);

  // Compatibility wrapper over parseAndDecryptEvent: returns the plaintext for
  // text messages and a human-readable status line for file events, so existing
  // text-only callers (CLI/GUI receive loops) keep working unchanged.
  bool parseAndDecryptMessage(const std::vector<uint8_t>& frame,
                              std::string& plaintextOut,
                              std::string& errorOut);

  // Where received files are written (created on demand). Default "./received".
  void setDownloadDirectory(const std::string& dir) { downloadDir_ = dir; }
  const std::string& downloadDirectory() const { return downloadDir_; }

private:
  bool clientHandshakeInternal(const SendFrameFn& send,
                               const RecvFrameFn& recv,
                               std::string& peerFingerprintOut,
                               std::string& errorOut);
  bool serverHandshakeInternal(const SendFrameFn& send,
                               const RecvFrameFn& recv,
                               std::string& peerFingerprintOut,
                               std::string& errorOut);

  // State of one active inbound transfer, keyed by transfer_id. Chunks are
  // streamed straight to disk and into the running HMAC; nothing is buffered.
  struct InboundTransfer {
    std::string filename;      // sanitized basename from the offer
    std::string tempPath;      // in-progress file (deleted on any failure)
    std::string finalPath;     // destination path inside the downloads dir
    uint64_t sizeBytes = 0;
    uint64_t chunkCount = 0;
    uint32_t chunkBytes = 0;
    uint64_t nextChunkIndex = 0;
    uint64_t bytesWritten = 0;
    std::vector<uint8_t> expectedHmac;
    std::ofstream out;
    std::unique_ptr<HmacSha256Stream> hmac;
  };

  // Encrypt one protocol message of the given kind into a serialized Envelope
  // (shared by the text and file send paths). Advances the send seq counter.
  // `body` becomes InnerMessage.body; all other metadata (sender/recipient,
  // timestamp, seq, kind, transfer id, chunk index) is sealed inside the same
  // encrypted InnerMessage rather than sent as plaintext (sealed sender).
  bool encryptAndSerializeKind(uint32_t kind,
                               uint64_t transferId,
                               uint64_t chunkIndex,
                               const std::vector<uint8_t>& body,
                               const std::string& senderId,
                               const std::string& toUsername,
                               std::vector<uint8_t>& outBytes,
                               std::string& errorOut);

  // Abort an inbound transfer: close and delete the partial file, forget it.
  void abortInboundTransfer(uint64_t transferId);

  // Report one handshake milestone to handshakeObserver_ if one is set.
  // No-op when null. Never throws (catches/discards any exception the
  // observer raises) so a GUI callback can never affect handshake control
  // flow, timing, or the cleanse ordering around it. `detail` must already be
  // fully built by the caller -- only public sizes/names/fingerprints, never
  // key material.
  void emitStep(HandshakeStep::Id id, std::string detail, uint64_t bytes = 0) const noexcept;

  // Which side of the handshake we are; determines the AAD direction tag and
  // which derived key is used for send vs. receive.
  enum class Role { None, Client, Server };

  Identity identity_;
  Session session_;
  Role role_ = Role::None;
  bool sessionReady_ = false;
  std::string downloadDir_ = "./received";
  std::map<uint64_t, InboundTransfer> inbound_;

  // Optional handshake progress observer; see setHandshakeObserver above.
  // Default-constructed std::function is null/empty -- zero behavior change
  // until a caller opts in.
  HandshakeObserverFn handshakeObserver_;
};
