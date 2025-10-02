#pragma once
#include <string>
#include <vector>
#include <cstdint>

struct ITransport {
  virtual ~ITransport() = default;

  // Client side: connect to host:port (e.g., "127.0.0.1", 5555)
  virtual bool connect(const std::string& host, uint16_t port) = 0;

  // Server side: listen on port and accept a single connection (blocking)
  virtual bool listen_and_accept(uint16_t port) = 0;

  // Send one framed message (length-prefixed)
  virtual bool send(const std::vector<uint8_t>& frame) = 0;

  // Receive one framed message (blocking)
  virtual bool recv(std::vector<uint8_t>& out_frame) = 0;

  // Close the underlying connection (optional)
  virtual void close() = 0;
};
