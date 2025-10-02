#include "ws_transport.h"
#include <QEventLoop>
#include <QTimer>

WebSocketTransport::WebSocketTransport() {
  socket_.setParent(nullptr); // lives in current thread (EngineWorker's thread)
  QObject::connect(&socket_, &QWebSocket::connected, [this]{
    connected_ = true;
  });
  QObject::connect(&socket_, &QWebSocket::disconnected, [this]{
    closed_ = true;
    connected_ = false;
    cv_.notify_all();
  });
  QObject::connect(&socket_, &QWebSocket::binaryMessageReceived,
                   [this](const QByteArray& msg){
                     {
                       std::lock_guard<std::mutex> lk(mtx_);
                       inbox_.push(msg);
                     }
                     cv_.notify_one();
                   });
  // (optional) errors—wakeup waiters
  QObject::connect(&socket_, &QWebSocket::errorOccurred, [this](auto){
    closed_ = true;
    connected_ = false;
    cv_.notify_all();
  });
}

WebSocketTransport::~WebSocketTransport() {
  close();
}

bool WebSocketTransport::connect_url(const std::string& wsUrl, int timeout_ms) {
  QUrl url(QString::fromStdString(wsUrl));
  socket_.open(url);

  QEventLoop loop;
  QTimer timer;
  timer.setSingleShot(true);
  QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
  // quit on connected or error/close
  QObject::connect(&socket_, &QWebSocket::connected, &loop, &QEventLoop::quit);
  QObject::connect(&socket_, &QWebSocket::disconnected, &loop, &QEventLoop::quit);
  QObject::connect(&socket_, &QWebSocket::errorOccurred, &loop, &QEventLoop::quit);
  timer.start(timeout_ms);
  loop.exec();

  return connected_;
}

bool WebSocketTransport::send(const std::vector<uint8_t>& data) {
  if (!connected_) return false;
  qint64 n = socket_.sendBinaryMessage(QByteArray(reinterpret_cast<const char*>(data.data()),
                                                  static_cast<int>(data.size())));
  return n >= 0;
}

bool WebSocketTransport::recv(std::vector<uint8_t>& out) {
  std::unique_lock<std::mutex> lk(mtx_);
  cv_.wait(lk, [&]{ return !inbox_.empty() || closed_; });
  if (!inbox_.empty()) {
    QByteArray msg = std::move(inbox_.front());
    inbox_.pop();
    lk.unlock();
    out.assign(msg.begin(), msg.end());
    return true;
  }
  // closed and no message
  return false;
}

void WebSocketTransport::close() {
  if (connected_) {
    socket_.close();
  }
  closed_ = true;
  connected_ = false;
  cv_.notify_all();
}
