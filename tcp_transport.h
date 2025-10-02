#pragma once
#include "transport.h"
#include <boost/asio.hpp>

class TcpTransport : public ITransport {
public:
  TcpTransport();
  ~TcpTransport() override;

  bool connect(const std::string& host, uint16_t port) override;
  bool listen_and_accept(uint16_t port) override;
  bool send(const std::vector<uint8_t>& frame) override;
  bool recv(std::vector<uint8_t>& out_frame) override;
  void close() override;

private:
  boost::asio::io_context io_;
  boost::asio::ip::tcp::socket socket_;
};
