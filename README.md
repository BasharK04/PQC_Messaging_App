E2EE Messaging

A one-on-one end-to-end encrypted chat with:
- A reusable core engine (handshake + message crypto)
- A WebSocket relay server
- A console client that handshakes E2E over the relay
- TCP console tools for local development

Build

Prereqs (macOS/Linux): CMake, a C++17 compiler, OpenSSL, Boost.System, Protobuf, liboqs.

Option A:
=======
# E2EE Messaging – notes for future me (and interviewers)

This is the playground where I’m learning C++17, Qt, and end‑to‑end encryption. It currently does 1:1 chat with Kyber + Ed25519, a tiny relay, and a CLI client. Not production grade, but enough to fire up two terminals (or machines) and see encrypted messages bouncing around.

## What’s in the repo
- `connection_engine.*` – loads/creates an identity file (`client.id`), runs the Kyber handshake, derives the AES‑GCM key, encrypts/decrypts protobuf messages.
- `relay_server.cpp` – WebSocket fan‑out by room (boost::beast, no storage, no auth).
- `relay_cli` – console chat over the relay, TOFU pinning stored in `pins.txt`.
- `pqc_client/pqc_server` – TCP console toys I used before switching to the relay.
- `gui/` – Qt GUI; works great on Linux, macOS still needs that OpenGL/AGL fix.

## Building it (pick one)
>>>>>>> 0d8e359 (Remove generated build directory)
```
./scripts/build.sh          # default: GUI off, RelWithDebInfo
make                        # same as above
make gui                    # if Qt links on your box
make run-relay-fast PORT=8080   # just run the relay, no rebuild
```
You’ll need a C++17 compiler, CMake, Boost, OpenSSL, Protobuf, liboqs. On macOS: Homebrew can install all of them. On Ubuntu: see `scripts/install_deps_ubuntu.sh` (liboqs still comes from source).

<<<<<<< HEAD
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
=======
## Quick local test
1. Terminal A: `./build/relay_server 8080`
2. Terminal B: `./build/relay_cli --host --relay http://127.0.0.1:8080 --room test --password pass123`
3. Terminal C: same command but `--connect`
You’ll see the peer fingerprint once, then any text you type shows up on the other side.

## Running it on my droplet (QuantRelay)
>>>>>>> 0d8e359 (Remove generated build directory)
```
ssh root@174.138.91.64
sudo apt-get update
sudo apt-get install -y build-essential cmake libboost-system-dev libssl-dev protobuf-compiler libprotobuf-dev
# build liboqs from source (see scripts/install_deps_ubuntu.sh)
cmake -S . -B build -DBUILD_GUI=OFF
cmake --build build -j1            # small droplet, easy on RAM
sudo systemctl enable --now relay_server   # using deploy/relay_server.service
```
From my laptop I just run:
```
./build/relay_cli --host    --relay http://174.138.91.64:8080 --room corina --password pass123
./build/relay_cli --connect --relay http://174.138.91.64:8080 --room corina --password pass123
```

## Security-ish notes
- Identity file (`client.id`) is AES-GCM encrypted, key derived with PBKDF2-HMAC-SHA256 (200k iterations, random salt).
- First handshake per `<relay-host>#<room>` pins the peer fingerprint in `pins.txt`. If the peer key changes, the client bails and tells you to delete the line if you really want to trust the new key.
- Relay only forwards bytes; all message contents stay E2E encrypted.

## Stuff I still want to add
- [ ] TLS + Caddy in front of the relay so clients can use `https://mydomain` instead of `http://ip:port`.
- [ ] Directory service: register/login, username search, store public keys, share “presence” (relay/room). Basically remove the “agree out of band” step.
- [ ] (Optional) GUI polish on macOS once I swap out the Qt build that drags in AGL.
- [ ] Maybe a “make release” that tars up `relay_server`, `relay_cli`, and the docs.

<<<<<<< HEAD
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
=======
## If you’re skimming for an interview
- Shows Kyber + Ed25519 handshake, HKDF to AES-GCM, protobuf transport.
- Boost::beast WebSocket relay, CLI client, optional Qt GUI.
- Deployable on a $6/mo DO droplet (systemd unit + ufw rules).
- Clear next steps (directory service, TLS proxy) to cross the finish line.
>>>>>>> 0d8e359 (Remove generated build directory)
