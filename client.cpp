#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include <google/protobuf/stubs/common.h>

#include "connection_engine.h"
#include "tcp_transport.h"

int main() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  const std::string id_path = "client.id";
  std::string password;
  std::cout << (std::filesystem::exists(id_path)
                  ? "[client] Unlock identity. Password: "
                  : "[client] No identity found. Create one now.\nPassword: ");
  std::getline(std::cin, password);

  ConnectionEngine engine;
  bool created = false;
  std::string fingerprint;
  std::string err;
  if (!engine.loadOrCreateIdentity(id_path, password, fingerprint, err, &created)) {
    std::cerr << "[client] Identity error: " << err << "\n";
    return 1;
  }
  std::cout << "[client] Identity " << (created ? "created" : "loaded")
            << ". Fingerprint: " << fingerprint.substr(0, 16) << "...\n";

  TcpTransport tx;
  if (!tx.connect("127.0.0.1", 5555)) {
    std::cerr << "[client] Connect failed\n";
    return 1;
  }

  auto send_fn = [&tx](const std::vector<uint8_t>& frame) { return tx.send(frame); };
  auto recv_fn = [&tx](std::vector<uint8_t>& frame) { return tx.recv(frame); };

  std::string peer_fp;
  if (!engine.runClientHandshake(send_fn, recv_fn, peer_fp, err)) {
    std::cerr << "[client] Handshake failed: " << err << "\n";
    return 1;
  }
  std::cout << "[client] Peer fp: " << peer_fp.substr(0, 16) << "...\n";

  std::cout << "[client] Enter message: ";
  std::string input;
  std::getline(std::cin, input);
  if (input.empty()) input = "Hello from client";

  std::vector<uint8_t> frame;
  if (!engine.encryptAndSerializeMessage(input, "alice", "bob", frame, err)) {
    std::cerr << "[client] Encrypt failed: " << err << "\n";
    return 1;
  }
  if (!tx.send(frame)) {
    std::cerr << "[client] Send failed\n";
    return 1;
  }

  std::cout << "[client] Sent " << frame.size() << " bytes.\n";
  tx.close();

  return 0;
}
