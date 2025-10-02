
# E2EE Messaging

End-to-end encrypted 1:1 chat built in C++17 as a learning project. It runs locally or against a small relay server (tested on a $6/mo DigitalOcean droplet).

## Features
- Kyber-512 + Ed25519 handshake that authenticates peers and derives an AES-256-GCM session key via HKDF-SHA256.
- Password-protected identity file (`client.id`) using PBKDF2-HMAC-SHA256 + AES-GCM.
- WebSocket relay (`relay_server`) that simply forwards frames by room; it never sees plaintext.
- CLI chat client (`relay_cli`) with TOFU fingerprint pinning per `<relay-host>#<room>`.
- Optional Qt GUI (Linux-friendly; macOS needs a newer Qt build).

## Build
Prerequisites: CMake, a C++17 compiler, Boost.System, OpenSSL, Protobuf, liboqs.

```
./scripts/build.sh          # default build
make                        # same as above
make gui                    # build GUI too (if Qt available)
make test                   # run in-memory loopback test
```

## Quick Local Test
1. `./build/relay_server 8080`
2. `./build/relay_cli --host --relay http://127.0.0.1:8080 --room demo --password pass123`
3. `./build/relay_cli --connect --relay http://127.0.0.1:8080 --room demo --password pass123`

Messages typed in one terminal show up in the other. The first handshake pins peer fingerprints in `pins.txt`.

## Deploying the Relay (DigitalOcean)
```
ssh root@<droplet_ip>
sudo apt-get update
sudo apt-get install -y build-essential cmake libboost-system-dev libssl-dev protobuf-compiler libprotobuf-dev
# build liboqs from source (see scripts/install_deps_ubuntu.sh)
cmake -S . -B build -DBUILD_GUI=OFF
cmake --build build -j1       # use -j1 on small RAM droplets
sudo ufw allow 8080/tcp
sudo systemctl enable --now relay_server   # uses deploy/relay_server.service
```
Clients connect with the same relay URL + room, for example:
```
./build/relay_cli --host    --relay http://<droplet_ip>:8080 --room demo --password pass123
./build/relay_cli --connect --relay http://<droplet_ip>:8080 --room demo --password pass123
```

## Architecture & Crypto
- **Identity**: `client.id` stores a 32-byte Ed25519 keypair encrypted with AES-GCM. The key is derived from the user password via PBKDF2-HMAC-SHA256 (200k iterations, random salt).
- **Handshake**: Each connection creates a Kyber ephemeral keypair, signs it with Ed25519, exchanges ciphertext, and derives the shared secret. HKDF (salt=`"E2EE-v1"`, info=`"AES-256-GCM"`) stretches it to 32 bytes for AES-256-GCM.
- **Messaging**: ChatMessage (protobuf) carries nonce + ciphertext + timestamp. Envelope wraps it for the relay; the relay never decrypts content.
- **Transports**: `tcp_transport.*` (dev TCP testing), `beast_ws_transport.*` (Boost.Beast WebSocket for CLI), `ws_transport.*` (Qt WebSocket for GUI).
- **Relay**: `relay_server.cpp` groups WebSocket connections by `room` query string and forwards binary frames to other participants in that room.

## TODO / Next Steps
- Add TLS termination (e.g., Caddy in front of the relay) so clients use `https://`/`wss://` URLs.
- Build a small directory service (register/login, username search, public-key lookup, presence) to avoid manual room coordination.
- Package a release target that bundles binaries + quickstart docs.

## License
See `LICENSE`.
