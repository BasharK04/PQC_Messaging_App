#pragma once
#include <vector>
#include <string>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>

#include <QWebSocket>
#include <QUrl>

// Blocking wrapper around QWebSocket for engine use.
// Send/recv are message-based (no extra length-prefixing).
class WebSocketTransport {
public:
  WebSocketTransport();
  ~WebSocketTransport();

  // wsUrl like: ws://host:8080/ws?room=alice  (wss:// supported if your server does TLS)
  bool connect_url(const std::string& wsUrl, int timeout_ms = 8000);
  bool send(const std::vector<uint8_t>& data);
  bool recv(std::vector<uint8_t>& out);  // blocks until a message arrives or connection closes
  void close();

  bool is_open() const { return connected_; }

private:
  QWebSocket socket_;
  std::atomic<bool> connected_{false};
  std::atomic<bool> closed_{false};

  std::mutex mtx_;
  std::condition_variable cv_;
  std::queue<QByteArray> inbox_;
};
