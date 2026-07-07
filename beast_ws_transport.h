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

  // DANGEROUS dev-only escape hatch. When set to true BEFORE connect_url(), a
  // wss:// connection skips certificate/hostname verification (verify_none) so
  // self-signed relays can be used during development. The default is secure
  // verification; only enable this for a trusted, local dev relay.
  void set_insecure_tls(bool allow);

private:
  struct Impl;
  Impl* impl_ = nullptr;
};
