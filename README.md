# E2EE Messaging

End-to-end encrypted 1:1 chat in C++17, built as a learning project around a
post-quantum key exchange. Peers authenticate each other with Ed25519, agree on
keys with ML-KEM-768, and talk through a relay that never sees plaintext — and
never sees who is talking to whom either.

Please see before using:
[Security properties and limitations](#security-properties-and-limitations).

## Features

- **Post-quantum key exchange** — ML-KEM-768 / FIPS 203 (via liboqs), with an
  Ed25519-authenticated, transcript-bound 3-message handshake and mutual
  HMAC-SHA256 key confirmation.
- **Identity concealment** — the handshake opens with an anonymous ML-KEM
  exchange; both parties' public keys and signatures are encrypted under a key
  derived from it before they ever reach the wire.
- **Sealed-sender messaging** — sender, recipient, timestamps, sequence numbers
  and content type all live inside the AEAD ciphertext. The relay sees only a
  version tag, a nonce and an opaque blob.
- **Length hiding** — plaintext is padded to fixed-size buckets, so ciphertext
  length reveals only a bucket. A 64-byte and a 200-byte message both emit
  identical 291-byte frames.
- **Directional keys** — separate AES-256-GCM keys per direction, so a reflected
  frame cannot decrypt.
- **Replay and reorder rejection** — strictly monotonic sequence numbers checked
  *after* AEAD authentication, plus a ±300 s timestamp window.
- **TOFU peer pinning** — a shared fingerprint store used by both the CLI and the
  GUI; a mismatch aborts the connection.
- **TLS verification on by default** for `wss://` (peer verify, SNI, hostname
  check), with an explicit `--insecure` opt-out for self-signed dev relays.
- **Opaque relay rooms** — clients join under a derived token, not a readable name.
- **Encrypted chunked file transfer** at the engine level: 256 KiB streaming
  chunks, constant-time whole-file HMAC-SHA256, path-traversal-safe filenames.
  Engine API only — deliberately not exposed in the CLI or GUI.
- **Password-encrypted identity keystore** — Ed25519 key under PBKDF2-HMAC-SHA256
  at 600,000 iterations, file header bound as AEAD associated data, keys zeroized.

## Build

Prerequisites: CMake, a C++17 compiler, Boost.System, OpenSSL 3, Protobuf,
Abseil, liboqs. Qt 6 is needed **only** for the GUI. Dependency helpers live in
`scripts/install_deps_macos.sh` and `scripts/install_deps_ubuntu.sh`.

```bash
# headless (relay + CLI) — no Qt required
cmake -S . -B build -DBUILD_GUI=OFF -DCMAKE_PREFIX_PATH="$(brew --prefix openssl@3)"
cmake --build build -j4

# with the Qt GUI
cmake -S . -B build -DBUILD_GUI=ON \
  -DCMAKE_PREFIX_PATH="$(brew --prefix qt);$(brew --prefix openssl@3)"
cmake --build build -j4
```

Use `-j1` on small-RAM droplets. Optional sanitizers: `-DENABLE_SANITIZERS=ON`.

## Quick Local Test

Give each peer its **own working directory and identity file** — peers sharing a
directory also share `pins.txt` and will abort on a spurious TOFU mismatch.

```bash
# terminal 1
./build/relay_server 8080

# terminal 2
mkdir -p /tmp/peerA && cd /tmp/peerA
relay_cli --host --relay http://127.0.0.1:8080 \
          --room demo --room-secret ourshared --password pw --id-file host.id

# terminal 3
mkdir -p /tmp/peerB && cd /tmp/peerB
relay_cli --connect --relay http://127.0.0.1:8080 \
          --room demo --room-secret ourshared --password pw --id-file peer.id
```

Both sides print the derived room token (they must match) and the peer
fingerprint. **Verify those fingerprints out of band** — that comparison is the
actual security boundary. Type to chat; Ctrl-D quits.

## CLI reference

| Flag | Meaning |
| --- | --- |
| `--host` / `--connect` | Which side of the handshake to run. |
| `--relay <url>`, `-r` | Relay base URL (`http://`, `https://`, `ws://`, `wss://`). |
| `--room <name>`, `-m` | Room name. Hashed into a token before it is sent. |
| `--room-secret <s>` | Shared out-of-band secret mixed into the room token. |
| `--password <pw>`, `-p` | Identity keystore password. Prompted if omitted. |
| `--id-file <path>`, `-i` | Identity keystore path (default `client.id`). |
| `--insecure` | **Dev only.** Disables TLS certificate verification for `wss://`. |
| `--help`, `-h` | Usage. |

## Security properties and limitations

**What a relay or passive observer can still see:** connection timing, message
timing and cadence, which size *bucket* each frame fell into, source IP
addresses, and that ML-KEM-768 is in use (inferable from key lengths).

**Known limitations**

- **No cover traffic.** Metadata is greatly reduced, but traffic analysis by
  timing and volume remains possible. This is metadata *reduction*, not anonymity.
- **Room tokens without `--room-secret` are obfuscation, not secrecy.** A hash of
  a guessable name can be dictionary-attacked.
- **No forward secrecy for identity concealment.** The identity seal derives from
  the same KEM secret as the session, so compromise of that secret would
  retroactively unseal captured handshake identities.
- **TOFU is trust-on-first-use.** Pins are scoped per relay-host#room (CLI) or per
  username (GUI), not a verified global identity directory.
- **Not a PQC+classical hybrid.** ML-KEM-768 targets NIST security category 3, but
  this is a KEM+AEAD construction — there is no X25519/ECDH combined alongside
  ML-KEM, so a future weakness in ML-KEM has no classical fallback.
- **No relay admission control.** Anyone holding the token can join a room, and
  participant counts are not capped.
- **One integration test binary, no CI.**
- **Not audited.** No independent review or formal verification. A learning
  project, not production software.

## Deploying the Relay

The relay is headless and does **not** require Qt.

```bash
sudo apt-get install -y build-essential cmake libboost-system-dev libssl-dev \
     protobuf-compiler libprotobuf-dev pkg-config
# build liboqs from source (see scripts/install_deps_ubuntu.sh)
cmake -S . -B build -DBUILD_GUI=OFF
cmake --build build -j1
sudo ufw allow 8080/tcp
sudo systemctl enable --now relay_server   # uses deploy/relay_server.service
```

For TLS, front the relay with Caddy (`deploy/Caddyfile`) and connect over
`wss://` so certificate verification applies.

## Project layout

```
connection_engine.*   handshake, sealed-sender message layer, file transfer
session.h             directional keys, sequence counters
crypto.h              AES-256-GCM helper
hkdf.*, kem_kyber.*   HKDF-SHA256, ML-KEM-768 (FIPS 203) via liboqs
identity.*            Ed25519 keystore (PBKDF2 + AES-GCM)
pin_store.*           shared TOFU fingerprint store
room_token.h          opaque relay room token derivation
file_transfer.h       chunk size, streaming HMAC, filename sanitizer
*.proto               wire formats (envelope, messages, handshake)
relay_server.cpp      room-keyed frame forwarder
relay_cli.cpp         CLI chat client
gui/                  Qt GUI
tools/                integration test
```

## Testing

```bash
cmake --build build -j4 && ./build/engine_loopback_test
```

The in-memory integration test drives a full handshake over channel callbacks and
asserts, among other things:

- text round-trip in both directions
- replay/reorder rejection
- sealed sender — that sender and recipient identifiers are **absent from the raw
  frame bytes**
- identity concealment — that neither party's public key appears in the handshake
- length padding — that differently sized messages land in the same bucket
- ciphertext, version and sealed-identity tampering are rejected
- a validly-sealed response signed by the *wrong* identity is rejected at
  signature verification
- room-token determinism, distinctness and format

## License

See `LICENSE`.
