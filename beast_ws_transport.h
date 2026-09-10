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

  // Tears down the underlying TCP connection WITHOUT writing a WebSocket
  // close frame. Beast's websocket::stream permits one concurrent read plus
  // one concurrent write, but close() performs a write -- calling it while
  // another thread is blocked in recv() races that write against the
  // in-flight read and trips Beast's internal assertion (UB in release
  // builds). shutdown() instead cancels and shuts down the lowest-layer
  // socket, which unblocks a thread parked in recv() promptly by failing its
  // read, without touching the websocket framing layer at all. Safe to call
  // from a different thread than the one blocked in recv(), and safe to call
  // more than once (idempotent). After shutdown(), send()/close() become
  // no-ops and recv() returns false promptly.
  void shutdown();

  // DANGEROUS dev-only escape hatch. When set to true BEFORE connect_url(), a
  // wss:// connection skips certificate/hostname verification (verify_none) so
  // self-signed relays can be used during development. The default is secure
  // verification; only enable this for a trusted, local dev relay.
  void set_insecure_tls(bool allow);

private:
  struct Impl;
  Impl* impl_ = nullptr;
};
