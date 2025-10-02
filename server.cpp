#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include <google/protobuf/stubs/common.h>

#include "connection_engine.h"
#include "tcp_transport.h"

int main() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  const std::string id_path = "server.id";
  std::string password;
  std::cout << "[server] Password to create/unlock server identity: ";
  std::getline(std::cin, password);

  ConnectionEngine engine;
  bool created = false;
  std::string fingerprint;
  std::string err;
  if (!engine.loadOrCreateIdentity(id_path, password, fingerprint, err, &created)) {
    std::cerr << "[server] Identity error: " << err << "\n";
    return 1;
  }
  std::cout << "[server] Identity " << (created ? "created" : "loaded")
            << ". fp: " << fingerprint.substr(0, 16) << "...\n";

  TcpTransport tx;
  std::cout << "[server] Listening on 5555...\n";
  if (!tx.listen_and_accept(5555)) {
    std::cerr << "[server] accept failed\n";
    return 1;
  }
  std::cout << "[server] Client connected\n";

  auto send_fn = [&tx](const std::vector<uint8_t>& frame) { return tx.send(frame); };
  auto recv_fn = [&tx](std::vector<uint8_t>& frame) { return tx.recv(frame); };

  std::string peer_fp;
  if (!engine.runServerHandshake(send_fn, recv_fn, peer_fp, err)) {
    std::cerr << "[server] Handshake failed: " << err << "\n";
    return 1;
  }
  std::cout << "[server] Peer fp: " << peer_fp.substr(0, 16) << "...\n";

  std::vector<uint8_t> frame;
  if (!tx.recv(frame)) {
    std::cerr << "[server] recv Envelope failed\n";
    return 1;
  }

  std::string plaintext;
  if (!engine.parseAndDecryptMessage(frame, plaintext, err)) {
    std::cerr << "[server] decrypt failed: " << err << "\n";
    return 1;
  }
  std::cout << "[server] Decrypted: " << plaintext << "\n";

  tx.close();
  return 0;
}
