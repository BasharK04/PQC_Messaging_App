#include "tcp_transport.h"

#include <vector>
#include <string>
#include <stdexcept>

#include <boost/asio.hpp>
#if defined(_WIN32)
  #include <winsock2.h>
#else
  #include <arpa/inet.h>
#endif

using boost::asio::ip::tcp;

TcpTransport::TcpTransport() : socket_(io_) {}
TcpTransport::~TcpTransport() { close(); }

bool TcpTransport::connect(const std::string& host, uint16_t port) {
  try {
    tcp::resolver resolver(io_);
    auto endpoints = resolver.resolve(host, std::to_string(port));
    boost::asio::connect(socket_, endpoints);
    return true;
  } catch (...) {
    return false;
  }
}

bool TcpTransport::listen_and_accept(uint16_t port) {
  try {
    tcp::acceptor acceptor(io_, tcp::endpoint(tcp::v4(), port));
    acceptor.accept(socket_);
    return true;
  } catch (...) {
    return false;
  }
}

bool TcpTransport::send(const std::vector<uint8_t>& frame) {
  try {
    uint32_t len = static_cast<uint32_t>(frame.size());
    uint32_t net_len = htonl(len);
    boost::asio::write(socket_, boost::asio::buffer(&net_len, sizeof(net_len)));
    if (len) {
      boost::asio::write(socket_, boost::asio::buffer(frame.data(), frame.size()));
    }
    return true;
  } catch (...) {
    return false;
  }
}

bool TcpTransport::recv(std::vector<uint8_t>& out_frame) {
  try {
    uint32_t net_len = 0;
    boost::asio::read(socket_, boost::asio::buffer(&net_len, sizeof(net_len)));
    uint32_t len = ntohl(net_len);
    out_frame.resize(len);
    if (len) {
      boost::asio::read(socket_, boost::asio::buffer(out_frame.data(), out_frame.size()));
    }
    return true;
  } catch (...) {
    return false;
  }
}

void TcpTransport::close() {
  boost::system::error_code ec;
  socket_.shutdown(tcp::socket::shutdown_both, ec);
  socket_.close(ec);
}
