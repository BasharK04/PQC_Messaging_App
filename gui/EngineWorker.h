#pragma once
#include <QObject>
#include <QString>
#include <QMetaType>
#include <atomic>
#include <thread>
#include <mutex>
#include <vector>
#include <cstdint>
#include <memory>

#include "tcp_transport.h"
#include "connection_engine.h"

// HandshakeStep (connection_engine.h) travels from the worker thread to the
// GUI thread as a queued-signal argument, so it needs to be a registered Qt
// metatype (see qRegisterMetaType<HandshakeStep>() in the .cpp constructor).
Q_DECLARE_METATYPE(HandshakeStep)

// No protobuf in header
class EngineWorker : public QObject {
  Q_OBJECT
public:
  explicit EngineWorker(QObject* parent = nullptr);
  ~EngineWorker();

public slots:
  // Old P2P TCP:
  void startConnect(const QString& endpoint, const QString& password);
  void startHost(quint16 port, const QString& password);

  // New Relay over WebSocket:
  // relayUrl: e.g. ws://127.0.0.1:8080   (we append /ws?room=<opaque token>,
  // a token derived from the username via room_token() -- see roomSecret_
  // below -- never the raw username itself)
  void startRelayHost(const QString& relayUrl, const QString& myUsername, const QString& password);
  void startRelayConnect(const QString& relayUrl, const QString& peerUsername, const QString& password);

  void disconnectFromPeer();
  void sendMessage(const QString& text);

signals:
  void status(const QString& line);
  void error(const QString& msg);
  void connected();
  void disconnected();
  void identityReady(const QString& fingerprintHex);
  void messageReceived(const QString& text);

  // ---- Key-exchange visualization (Key Exchange dock panel) ----
  // All of these are emitted from whichever handshake call runs on THIS
  // worker's thread; Qt auto-queues them across to the GUI thread since
  // EngineWorker lives on workerThread_ (same pattern as status()/error()
  // above -- no explicit Qt::QueuedConnection needed at the connect() site,
  // it is selected automatically because sender and receiver live in
  // different threads).

  // Fired right before the real cryptographic handshake begins (after any
  // transport-level connect has already succeeded), so the panel knows
  // whether to lay out the client-role or server-role step sequence.
  void handshakeStarted(bool asClient);

  // One genuine handshake milestone, forwarded verbatim from
  // ConnectionEngine's observer (see connection_engine.h HandshakeStep).
  // Never carries key material -- see the security note on HandshakeStep.
  void handshakeStepOccurred(const HandshakeStep& step);

  // Our own identity fingerprint (full hex), for the panel's "Peer
  // Verification" section. identityReady() above still carries the
  // shortened form used in the chat log / status bar; this is additive.
  void ownFingerprintReady(const QString& fingerprintHexFull);

  // The peer's fingerprint (full hex) as soon as the handshake reports it,
  // before the TOFU pin check runs.
  void peerFingerprintReady(const QString& peerLabel, const QString& fingerprintHexFull);

  // Structured result of the TOFU pin check that checkPeerPin() already
  // performs and acts on (abort-on-mismatch behavior is unchanged); this is
  // purely an additional, more structured signal for the panel so it does
  // not have to pattern-match the free-text status()/error() strings.
  // result: 0 = Pinned (first use), 1 = Matched, 2 = Mismatch.
  void peerPinResult(const QString& peerLabel, const QString& fingerprintHexFull, int result);

private:
  bool parseEndpoint(const QString& endpoint, std::string& host, uint16_t& port);
  void recvLoop();

  // Shared TOFU peer pinning (same PinStore the CLI uses). Returns true if the
  // caller may proceed to messaging; false if the connection must be aborted
  // (fingerprint mismatch). Emits status/error to the UI as appropriate.
  bool checkPeerPin(const QString& peerLabel, const std::string& peerFingerprint);

  // transport selection
  enum class Mode { None, TCP, WS };
  Mode mode_{Mode::None};

  // crypto/session/identity
  ConnectionEngine engine_;

  // transports
  TcpTransport tcp_;
  std::unique_ptr<class WebSocketTransport> ws_; // defined in ws_transport.h

  // Out-of-band secret mixed into the relay room token (see room_token.h) so
  // the relay never sees the real room name/username in the URL or its logs.
  // The GUI has no input for this yet, so it defaults to empty -- the same
  // "obfuscated, not secret" caveat documented in room_token.h applies until
  // a UI is added to set it.
  QString roomSecret_;

  // loop
  std::atomic<bool> running_{false};
  std::atomic<bool> isConnected_{false};
  std::thread rxThread_;
  std::mutex sendMtx_;
};
