#include "beast_ws_transport.h"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <atomic>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <string>

#include <openssl/ssl.h>

namespace {
struct ParsedUrl {
  std::string scheme;    // ws or wss
  std::string host;
  std::string port;
  std::string target;    // path+query
};

static bool parse_ws_url(const std::string& url, ParsedUrl& out) {
  // scheme://host[:port]/path?query
  auto pos = url.find("://");
  if (pos == std::string::npos) return false;
  out.scheme = url.substr(0, pos);
  std::string rest = url.substr(pos + 3);
  auto slash = rest.find('/');
  std::string hostport = slash == std::string::npos ? rest : rest.substr(0, slash);
  out.target = slash == std::string::npos ? "/" : rest.substr(slash);
  auto colon = hostport.rfind(':');
  if (colon != std::string::npos) {
    out.host = hostport.substr(0, colon);
    out.port = hostport.substr(colon + 1);
  } else {
    out.host = hostport;
    out.port = (out.scheme == "wss" ? "443" : "80");
  }
  if (out.target.empty()) out.target = "/";
  return !out.host.empty();
}
}

struct BeastWebSocketTransport::Impl {
  boost::asio::io_context ioc;
  std::unique_ptr<boost::asio::ssl::context> ssl_ctx;
  std::unique_ptr<boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>>> wss;
  std::unique_ptr<boost::beast::websocket::stream<boost::beast::tcp_stream>> ws;
  ParsedUrl u;
  std::atomic<bool> open{false};
  bool allow_insecure_tls = false;

  // Guards send()/close() so two threads can never write to the stream at
  // the same time (Beast allows only one concurrent write). recv() is
  // deliberately NOT guarded by this mutex -- holding it across the blocking
  // read would deadlock any concurrent send(). Beast permits one concurrent
  // read alongside one concurrent write, so an unguarded read racing a
  // mutex-guarded write is safe.
  std::mutex write_mtx;

  // Set once the connection has been torn down via shutdown() or close().
  // Makes both of those idempotent and turns send()/close() into no-ops
  // afterward; recv() checks it up front so it never touches a torn-down
  // stream after the fact.
  std::atomic<bool> closed_{false};

  bool connect(const std::string& url) {
    if (!parse_ws_url(url, u)) return false;
    using tcp = boost::asio::ip::tcp;
    namespace ssl = boost::asio::ssl;
    tcp::resolver resolver(ioc);
    auto results = resolver.resolve(u.host, u.port);

    if (u.scheme == "wss") {
      ssl_ctx = std::make_unique<ssl::context>(ssl::context::tls_client);
      if (allow_insecure_tls) {
        // Dev-only: accept any certificate. Loud warning so it can never pass
        // silently in a real deployment.
        std::cerr << "[WARNING] --insecure: TLS certificate verification is "
                     "DISABLED for " << u.host << ". Do NOT use against a real relay.\n";
        ssl_ctx->set_verify_mode(ssl::verify_none);
      } else {
        // Secure default: verify the peer chain against the system trust store
        // and require the certificate to match the hostname.
        ssl_ctx->set_verify_mode(ssl::verify_peer);
        ssl_ctx->set_default_verify_paths();
      }
      wss = std::make_unique<boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>>>(ioc, *ssl_ctx);

      // SNI: many servers (and cert validation) require the hostname in the
      // ClientHello. Failure to set it is fatal.
      if (!SSL_set_tlsext_host_name(wss->next_layer().native_handle(), u.host.c_str())) {
        throw boost::system::system_error(
            static_cast<int>(::ERR_get_error()),
            boost::asio::error::get_ssl_category(),
            "SSL_set_tlsext_host_name (SNI) failed");
      }
      if (!allow_insecure_tls) {
        wss->next_layer().set_verify_callback(ssl::host_name_verification(u.host));
      }

      boost::beast::get_lowest_layer(*wss).connect(results);
      wss->next_layer().handshake(ssl::stream_base::client);
      wss->set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::client));
      wss->handshake(u.host, u.target);
      open = true;
      return true;
    } else {
      ws = std::make_unique<boost::beast::websocket::stream<boost::beast::tcp_stream>>(ioc);
      boost::beast::get_lowest_layer(*ws).connect(results);
      ws->set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::client));
      ws->handshake(u.host, u.target);
      open = true;
      return true;
    }
  }

  bool send(const std::vector<uint8_t>& data) {
    if (closed_ || !open) return false;
    std::lock_guard<std::mutex> lock(write_mtx);
    if (closed_ || !open) return false;  // re-check: may have raced shutdown()/close()
    boost::system::error_code ec;
    if (wss) {
      wss->binary(true);
      wss->write(boost::asio::buffer(data), ec);
    } else {
      ws->binary(true);
      ws->write(boost::asio::buffer(data), ec);
    }
    return !ec;
  }

  bool recv(std::vector<uint8_t>& out) {
    if (closed_ || !open) return false;
    boost::beast::flat_buffer buffer;
    boost::system::error_code ec;
    if (wss) {
      wss->read(buffer, ec);
    } else {
      ws->read(buffer, ec);
    }
    if (ec) return false;
    auto b = buffer.data();
    out.assign(static_cast<const uint8_t*>(b.data()), static_cast<const uint8_t*>(b.data()) + b.size());
    return true;
  }

  // Graceful WebSocket close: writes a close frame and waits for the peer's
  // reply per the Beast handshake. Only safe to call when no other thread is
  // concurrently blocked in recv() on this stream -- callers that have a
  // reader thread parked in recv() MUST call shutdown() and join that thread
  // first. A no-op once shutdown()/close() has already run.
  void close() {
    if (closed_.exchange(true)) return;  // idempotent
    if (!open) return;
    std::lock_guard<std::mutex> lock(write_mtx);
    boost::system::error_code ec;
    if (wss) {
      wss->close(boost::beast::websocket::close_code::normal, ec);
    } else if (ws) {
      ws->close(boost::beast::websocket::close_code::normal, ec);
    }
    open = false;
  }

  // See header comment on BeastWebSocketTransport::shutdown().
  void shutdown() {
    if (closed_.exchange(true)) return;  // idempotent
    using tcp = boost::asio::ip::tcp;
    boost::system::error_code ec;
    if (wss) {
      auto& sock = boost::beast::get_lowest_layer(*wss).socket();
      sock.cancel(ec);
      ec.clear();
      sock.shutdown(tcp::socket::shutdown_both, ec);
    } else if (ws) {
      auto& sock = boost::beast::get_lowest_layer(*ws).socket();
      sock.cancel(ec);
      ec.clear();
      sock.shutdown(tcp::socket::shutdown_both, ec);
    }
    open = false;
  }
};

BeastWebSocketTransport::BeastWebSocketTransport() : impl_(new Impl) {}
// close() is idempotent (guarded by Impl::closed_) whether or not shutdown()
// was already called, so this is safe in all cases: if the caller already
// called shutdown() (and joined any reader thread), close() here is a no-op;
// if not, it performs a normal single-threaded graceful close. Either way
// there is exactly one owner of impl_ (this object), so delete cannot
// double-free, and nothing re-enters the stream after this point.
BeastWebSocketTransport::~BeastWebSocketTransport() { close(); delete impl_; }

bool BeastWebSocketTransport::connect_url(const std::string& url) {
  try {
    return impl_->connect(url);
  } catch (const std::exception& ex) {
    // TLS certificate/hostname verification failures land here; surface as a
    // clean connect failure instead of an uncaught exception.
    std::cerr << "[transport] connect failed: " << ex.what() << "\n";
    return false;
  }
}
bool BeastWebSocketTransport::send(const std::vector<uint8_t>& data) { return impl_->send(data); }
bool BeastWebSocketTransport::recv(std::vector<uint8_t>& out) { return impl_->recv(out); }
void BeastWebSocketTransport::close() { impl_->close(); }
void BeastWebSocketTransport::shutdown() { impl_->shutdown(); }
void BeastWebSocketTransport::set_insecure_tls(bool allow) { impl_->allow_insecure_tls = allow; }
