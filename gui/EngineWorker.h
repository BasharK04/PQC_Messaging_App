#pragma once
#include <QObject>
#include <QString>
#include <atomic>
#include <thread>
#include <mutex>
#include <vector>
#include <cstdint>
#include <memory>

#include "tcp_transport.h"
#include "connection_engine.h"

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
  // relayUrl: e.g. ws://127.0.0.1:8080   (we append /ws?room=<username>)
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

private:
  bool parseEndpoint(const QString& endpoint, std::string& host, uint16_t& port);
  void recvLoop();

  // transport selection
  enum class Mode { None, TCP, WS };
  Mode mode_{Mode::None};

  // crypto/session/identity
  ConnectionEngine engine_;

  // transports
  TcpTransport tcp_;
  std::unique_ptr<class WebSocketTransport> ws_; // defined in ws_transport.h

  // loop
  std::atomic<bool> running_{false};
  std::atomic<bool> isConnected_{false};
  std::thread rxThread_;
  std::mutex sendMtx_;
};
