#pragma once
#include <string>
#include <vector>
#include <cstdint>

// Blocking WebSocket client built with Boost.Beast for the CLI.
class BeastWebSocketTransport {
public:
  BeastWebSocketTransport();
  ~BeastWebSocketTransport();

  // Accepts ws:// or wss:// URLs.
  bool connect_url(const std::string& url);
  bool send(const std::vector<uint8_t>& data);
  bool recv(std::vector<uint8_t>& out);
  void close();

private:
  struct Impl;
  Impl* impl_ = nullptr;
};
