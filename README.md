E2EE Messaging

A one-on-one end-to-end encrypted chat with:
- A reusable core engine (handshake + message crypto)
- A WebSocket relay server
- A console client that handshakes E2E over the relay
- TCP console tools for local development

Build

Prereqs (macOS/Linux): CMake, a C++17 compiler, OpenSSL, Boost.System, Protobuf, liboqs.

Option A:
```
./scripts/build.sh   # uses GUI=OFF, TYPE=RelWithDebInfo, JOBS=8 by default
```

Option B:
```
make           # builds CLI + backend
make gui       # builds GUI too (if Qt links on your OS)
make test      # runs in-memory crypto test
```

Artifacts:
- build/relay_server — simple relay (room broadcast)
- build/relay_cli — E2EE chat over relay (WebSocket)
- build/pqc_client, build/pqc_server — TCP dev tools
- build/engine_loopback_test — in-memory handshake + message roundtrip

CLI Usage

You can use positional args or flags:

- Positional: `relay_cli <host|connect> <relay_url> <room> <password>`
- Flags: `relay_cli (--host|--connect) --relay <url> --room <name> [--password <pw>]`

Examples:
- `./build/relay_cli --host --relay http://127.0.0.1:8080 --room alice --password pass123`
- `./build/relay_cli --connect --relay http://127.0.0.1:8080 --room alice --password pass123`

Pins are stored per `<relay-host[:port]>#<room>` in `pins.txt`.

Quickstart (Local)

- Terminal A: ./build/relay_server 8080
- Terminal B: ./build/relay_cli host http://127.0.0.1:8080 alice pass123
- Terminal C: ./build/relay_cli connect http://127.0.0.1:8080 alice pass123

Type messages in either client.

Deploy the Relay (Hosted on DigitalOcean)

On droplet:
```
sudo apt-get update
sudo apt-get install -y build-essential cmake libboost-system-dev libssl-dev protobuf-compiler libprotobuf-dev
# clone this repo, then
cmake -S . -B build -DBUILD_GUI=OFF
cmake --build build -j
sudo ufw allow 8080/tcp
./build/relay_server 8080
```
Use a terminal multiplexer (tmux) or create a systemd unit to keep it running.

On your machine:
```
./build/relay_cli host    http://<droplet_ip>:8080 alice pass123
./build/relay_cli connect http://<droplet_ip>:8080 alice pass123
```

Architecture

- Core: connection_engine.{h,cpp}
  - Identity (Ed25519 keystore), Kyber KEM handshake, HKDF(SHA-256) to AES-256-GCM session key, serialize/deserialize protobuf Envelope/ChatMessage.
- Transports:
  - TCP: tcp_transport.* (dev tools)
  - WebSocket (CLI): beast_ws_transport.* (Boost.Beast)
  - WebSocket (GUI): ws_transport.* (Qt, optional GUI currently disabled)
- Relay: relay_server.cpp (rooms, broadcasts binary frames)
- Protocol constants: protocol.h

Security Notes

- Identity is stored encrypted with PBKDF2(AES-GCM). Protect your password.
- TOFU pinning in relay_cli: on first successful handshake per room, the peer fingerprint is saved to pins.txt. If it changes later, the client aborts. Delete the line to re-pin.
- This is a learning project: no reconnection/backoff, minimal error handling, no message ordering or replay protection.

What to Improve (Future Work)
- GUI linking on macOS (Qt/OpenGL) and UI polish.
- Reconnection and backoff.
- Replay protection and message authentication metadata.
- Stronger identity management (per-relay scoping, import/export).


Production Notes

- Systemd unit: see `deploy/relay_server.service`. Copy to `/etc/systemd/system/relay_server@youruser.service`, set the `WorkingDirectory` and `ExecStart` paths for your environment, then:
  - `sudo systemctl daemon-reload`
  - `sudo systemctl enable --now relay_server@youruser`

- TLS via Caddy: see `deploy/Caddyfile`. Install Caddy, replace `chat.example.com`, and run Caddy as a service. Clients can then use `https://chat.example.com` and the CLI will switch to `wss://` automatically.

GUI Status

- The Qt GUI target is currently disabled by default on macOS due to an OpenGL/AGL link issue. The backend and CLI are complete and recommended for demos.
- To attempt building the GUI: install Qt6 and run `cmake -S . -B build -DBUILD_GUI=ON`. On Linux this usually links fine; on macOS you may need to adjust your Qt/OpenGL setup.

Build

```
cmake -S . -B build -DBUILD_GUI=OFF
cmake --build build -j
```

Run loopback test to check crypto:

```
./build/engine_loopback_test
```
