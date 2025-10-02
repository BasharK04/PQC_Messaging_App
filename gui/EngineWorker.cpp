#include "EngineWorker.h"

#include <string>

#include <QUrl>
#include <QUrlQuery>

#include "ws_transport.h"

namespace {
QString shortenFingerprint(const std::string& fingerprint) {
  return QString::fromStdString(fingerprint).left(16) + "...";
}
}

EngineWorker::EngineWorker(QObject* parent) : QObject(parent) {}
EngineWorker::~EngineWorker() { disconnectFromPeer(); }

bool EngineWorker::parseEndpoint(const QString& endpoint, std::string& host, uint16_t& port) {
  const auto ep = endpoint.trimmed();
  const int idx = ep.lastIndexOf(':');
  if (idx <= 0) return false;
  host = ep.left(idx).toStdString();
  bool ok = false;
  int p = ep.mid(idx + 1).toInt(&ok);
  if (!ok || p <= 0 || p > 65535) return false;
  port = static_cast<uint16_t>(p);
  return true;
}

// ---------------- TCP (existing) ----------------

void EngineWorker::startConnect(const QString& endpoint, const QString& password) {
  if (isConnected_) { emit status("Already connected; disconnecting first."); disconnectFromPeer(); }

  std::string host; uint16_t port = 0;
  if (!parseEndpoint(endpoint, host, port)) { emit error("Invalid endpoint. Use host:port"); return; }

  bool created = false;
  std::string fingerprint;
  std::string err;
  if (!engine_.loadOrCreateIdentity("client.id", password.toStdString(), fingerprint, err, &created)) {
    emit error(QString("Identity error: ") + err.c_str());
    return;
  }
  emit status(created ? "Identity created." : "Identity loaded.");
  emit identityReady(shortenFingerprint(fingerprint));

  emit status(QString("Connecting to %1:%2 ...").arg(QString::fromStdString(host)).arg(port));
  if (!tcp_.connect(host, port)) { emit error("TCP connect failed."); return; }

  auto send_fn = [this](const std::vector<uint8_t>& frame) {
    std::lock_guard<std::mutex> lk(sendMtx_);
    return tcp_.send(frame);
  };
  auto recv_fn = [this](std::vector<uint8_t>& frame) { return tcp_.recv(frame); };

  std::string peerFingerprint;
  if (!engine_.runClientHandshake(send_fn, recv_fn, peerFingerprint, err)) {
    tcp_.close();
    emit error(QString("Handshake/connect error: ") + err.c_str());
    return;
  }

  mode_ = Mode::TCP;
  isConnected_ = true;
  running_ = true;
  emit status("Handshake complete. Session established (client/TCP).");
  if (!peerFingerprint.empty()) {
    emit status(QString("Peer fingerprint: ") + shortenFingerprint(peerFingerprint));
  }
  emit connected();
  rxThread_ = std::thread([this]{ this->recvLoop(); });
}

void EngineWorker::startHost(quint16 port, const QString& password) {
  if (isConnected_) { emit status("Already connected; disconnecting first."); disconnectFromPeer(); }

  bool created = false;
  std::string fingerprint;
  std::string err;
  if (!engine_.loadOrCreateIdentity("client.id", password.toStdString(), fingerprint, err, &created)) {
    emit error(QString("Identity error: ") + err.c_str());
    return;
  }
  emit status(created ? "Identity created." : "Identity loaded.");
  emit identityReady(shortenFingerprint(fingerprint));

  emit status(QString("Hosting on port %1 ...").arg(port));
  if (!tcp_.listen_and_accept(port)) { emit error("listen/accept failed."); return; }

  auto send_fn = [this](const std::vector<uint8_t>& frame) {
    std::lock_guard<std::mutex> lk(sendMtx_);
    return tcp_.send(frame);
  };
  auto recv_fn = [this](std::vector<uint8_t>& frame) { return tcp_.recv(frame); };

  std::string peerFingerprint;
  if (!engine_.runServerHandshake(send_fn, recv_fn, peerFingerprint, err)) {
    tcp_.close();
    emit error(QString("Handshake/host error: ") + err.c_str());
    return;
  }

  mode_ = Mode::TCP;
  isConnected_ = true;
  running_ = true;
  emit status("Handshake complete. Session established (host/TCP).");
  if (!peerFingerprint.empty()) {
    emit status(QString("Peer fingerprint: ") + shortenFingerprint(peerFingerprint));
  }
  emit connected();
  rxThread_ = std::thread([this]{ this->recvLoop(); });
}

// --------------- Relay (WebSocket) ---------------

static QString ws_join(const QString& base, const QString& room) {
  QUrl u(base);
  if (u.scheme() == "http") u.setScheme("ws");
  else if (u.scheme() == "https") u.setScheme("wss");
  if (u.path().isEmpty() || u.path() == "/") u.setPath("/ws");
  QUrlQuery q; q.addQueryItem("room", room); u.setQuery(q);
  return u.toString();
}

void EngineWorker::startRelayConnect(const QString& relayUrl, const QString& peerUsername, const QString& password) {
  if (isConnected_) { emit status("Already connected; disconnecting first."); disconnectFromPeer(); }

  bool created = false;
  std::string fingerprint;
  std::string err;
  if (!engine_.loadOrCreateIdentity("client.id", password.toStdString(), fingerprint, err, &created)) {
    emit error(QString("Identity error: ") + err.c_str());
    return;
  }
  emit status(created ? "Identity created." : "Identity loaded.");
  emit identityReady(shortenFingerprint(fingerprint));

  const QString url = ws_join(relayUrl, peerUsername);
  emit status("Relay connect to " + url + " ...");
  ws_ = std::make_unique<WebSocketTransport>();
  if (!ws_->connect_url(url.toStdString())) {
    ws_.reset();
    emit error("Relay WebSocket connect failed.");
    return;
  }

  auto send_fn = [this](const std::vector<uint8_t>& frame) {
    std::lock_guard<std::mutex> lk(sendMtx_);
    return ws_ && ws_->send(frame);
  };
  auto recv_fn = [this](std::vector<uint8_t>& frame) {
    return ws_ && ws_->recv(frame);
  };

  std::string peerFingerprint;
  if (!engine_.runClientHandshake(send_fn, recv_fn, peerFingerprint, err)) {
    if (ws_) ws_->close();
    ws_.reset();
    emit error(QString("Relay handshake error: ") + err.c_str());
    return;
  }

  mode_ = Mode::WS;
  isConnected_ = true;
  running_ = true;
  emit status("Handshake complete. Session established (relay/client).");
  if (!peerFingerprint.empty()) {
    emit status(QString("Peer fingerprint: ") + shortenFingerprint(peerFingerprint));
  }
  emit connected();
  rxThread_ = std::thread([this]{ this->recvLoop(); });
}

void EngineWorker::startRelayHost(const QString& relayUrl, const QString& myUsername, const QString& password) {
  if (isConnected_) { emit status("Already connected; disconnecting first."); disconnectFromPeer(); }

  bool created = false;
  std::string fingerprint;
  std::string err;
  if (!engine_.loadOrCreateIdentity("client.id", password.toStdString(), fingerprint, err, &created)) {
    emit error(QString("Identity error: ") + err.c_str());
    return;
  }
  emit status(created ? "Identity created." : "Identity loaded.");
  emit identityReady(shortenFingerprint(fingerprint));

  const QString url = ws_join(relayUrl, myUsername);
  emit status("Relay host (listen) at " + url + " ...");
  ws_ = std::make_unique<WebSocketTransport>();
  if (!ws_->connect_url(url.toStdString())) {
    ws_.reset();
    emit error("Relay WebSocket connect failed.");
    return;
  }

  auto send_fn = [this](const std::vector<uint8_t>& frame) {
    std::lock_guard<std::mutex> lk(sendMtx_);
    return ws_ && ws_->send(frame);
  };
  auto recv_fn = [this](std::vector<uint8_t>& frame) {
    return ws_ && ws_->recv(frame);
  };

  std::string peerFingerprint;
  if (!engine_.runServerHandshake(send_fn, recv_fn, peerFingerprint, err)) {
    if (ws_) ws_->close();
    ws_.reset();
    emit error(QString("Relay host handshake error: ") + err.c_str());
    return;
  }

  mode_ = Mode::WS;
  isConnected_ = true;
  running_ = true;
  emit status("Handshake complete. Session established (relay/host).");
  if (!peerFingerprint.empty()) {
    emit status(QString("Peer fingerprint: ") + shortenFingerprint(peerFingerprint));
  }
  emit connected();
  rxThread_ = std::thread([this]{ this->recvLoop(); });
}

// --------------- Common ---------------

void EngineWorker::disconnectFromPeer() {
  running_ = false;
  if (mode_ == Mode::TCP) tcp_.close();
  if (mode_ == Mode::WS && ws_) ws_->close();
  if (rxThread_.joinable()) rxThread_.join();
  if (isConnected_) { isConnected_ = false; emit disconnected(); }
  mode_ = Mode::None;
}

void EngineWorker::sendMessage(const QString& text) {
  if (!isConnected_) { emit error("Not connected."); return; }

  std::vector<uint8_t> frame;
  std::string err;
  if (!engine_.encryptAndSerializeMessage(text.toStdString(), "gui", "peer", frame, err)) {
    emit error(QString("Send error: ") + err.c_str());
    return;
  }

  std::lock_guard<std::mutex> lk(sendMtx_);
  bool ok = false;
  if (mode_ == Mode::TCP) ok = tcp_.send(frame);
  else if (mode_ == Mode::WS && ws_) ok = ws_->send(frame);
  if (!ok) {
    emit error("Send failed");
  }
}

void EngineWorker::recvLoop() {
  for (;;) {
    std::vector<uint8_t> frame;
    bool ok = false;
    if (mode_ == Mode::TCP) ok = tcp_.recv(frame);
    else if (mode_ == Mode::WS && ws_) ok = ws_->recv(frame);
    if (!ok) break;

    std::string plaintext;
    std::string err;
    if (!engine_.parseAndDecryptMessage(frame, plaintext, err)) {
      emit status(QString("Dropping message: ") + err.c_str());
      continue;
    }
    emit messageReceived(QString::fromStdString(plaintext));
  }
  isConnected_ = false;
  running_ = false;
  emit disconnected();
}
