#pragma once
#include <string>
#include <vector>
#include <cstdint>

// Minimal blocking WebSocket client built on Boost.Beast for CLI usage.
class BeastWebSocketTransport {
public:
  BeastWebSocketTransport();
  ~BeastWebSocketTransport();

  // Accepts ws:// or wss:// URLs. Returns true on success.
  bool connect_url(const std::string& url);
  bool send(const std::vector<uint8_t>& data);
  bool recv(std::vector<uint8_t>& out);
  void close();

private:
  struct Impl;
  Impl* impl_ = nullptr;
};
