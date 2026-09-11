# E2EE Messaging

End-to-end encrypted 1:1 chat in C++17, built as a learning project around a
post-quantum key exchange. Peers authenticate each other with Ed25519, agree on
keys with CRYSTALS-Kyber-512, and talk through a small relay that never sees
plaintext — and, as of the metadata work described below, never sees who is
talking to whom either.

This is not audited software. See
[Security properties and limitations](#security-properties-and-limitations) for
an honest account of what it does and does not protect against.

## Features

- **Post-quantum key exchange** — CRYSTALS-Kyber-512 (via liboqs) with an
  Ed25519-authenticated, transcript-bound handshake and mutual HMAC key
  confirmation.
- **Identity concealment** — the handshake opens with an anonymous Kyber
  exchange; both parties' public keys and signatures are encrypted before they
  ever reach the wire.
- **Sealed-sender messaging** — sender, recipient, timestamps, sequence numbers
  and content type all live inside the ciphertext. The relay sees only a version
  tag, a nonce and an opaque blob.
- **Length hiding** — plaintext is padded to fixed size buckets, so ciphertext
  length reveals only a bucket, not the true message size.
- **Replay and reorder rejection** — strictly monotonic sequence numbers checked
  after AEAD authentication, plus a ±300 s timestamp window.
- **TOFU peer pinning** — shared fingerprint store used by both the CLI and the
  GUI; a mismatch aborts the connection.
- **TLS verification on by default** for `wss://` relays, with an explicit
  opt-out for self-signed development relays.
- **Opaque relay rooms** — clients join under a derived token rather than a
  human-readable room name.
- **Qt GUI** with a live "Key Exchange" panel that visualizes the real handshake
  as it happens.
- **Encrypted chunked file transfer** at the engine level (see the note in
  [File transfer](#file-transfer) — it is not currently exposed in either UI).

## Build

Prerequisites: CMake, a C++17 compiler, Boost.System, OpenSSL 3, Protobuf,
Abseil, liboqs. Qt 6 is required **only** for the GUI.

Helper scripts install dependencies: `scripts/install_deps_macos.sh`,
`scripts/install_deps_ubuntu.sh`.

### Headless (relay + CLI, no Qt needed)

```bash
cmake -S . -B build -DBUILD_GUI=OFF -DCMAKE_PREFIX_PATH="$(brew --prefix openssl@3)"
cmake --build build -j4
```

On a small droplet, use `-j1` to avoid running out of RAM.

### With the Qt GUI

```bash
cmake -S . -B build -DBUILD_GUI=ON \
  -DCMAKE_PREFIX_PATH="$(brew --prefix qt);$(brew --prefix openssl@3)"
cmake --build build -j4
```

Convenience targets also exist: `make`, `make gui`, `make test`,
`./scripts/build.sh`.

Optional sanitizers: configure with `-DENABLE_SANITIZERS=ON`.

## Quick Local Test

Run the relay, then two clients. **Give each peer its own working directory and
its own identity file** — peers sharing a directory also share `pins.txt`, and
each will see the other's fingerprint under the same pin label and abort with a
TOFU mismatch.

```bash
# terminal 1 — the relay
./build/relay_server 8080

# terminal 2 — the host
mkdir -p /tmp/peerA && cd /tmp/peerA
relay_cli --host --relay http://127.0.0.1:8080 \
          --room demo --room-secret ourshared --password pw --id-file host.id

# terminal 3 — the peer
mkdir -p /tmp/peerB && cd /tmp/peerB
relay_cli --connect --relay http://127.0.0.1:8080 \
          --room demo --room-secret ourshared --password pw --id-file peer.id
```

Both sides print the derived room token (they must match), the peer fingerprint,
and a TOFU status line. Type to chat; Ctrl-D quits.

On first connection each side pins the other's fingerprint. **Verify those
fingerprints out of band** — that comparison is the actual security boundary.

## CLI reference

| Flag | Meaning |
| --- | --- |
| `--host` / `--connect` | Which side of the handshake to run. |
| `--relay <url>`, `-r` | Relay base URL (`http://`, `https://`, `ws://`, `wss://`). |
| `--room <name>`, `-m` | Room name. Hashed into a token before it is sent. |
| `--room-secret <s>` | Shared out-of-band secret mixed into the room token. |
| `--password <pw>`, `-p` | Password for the identity keystore. Prompted if omitted. |
| `--id-file <path>`, `-i` | Identity keystore path (default `client.id`). |
| `--insecure` | **Dev only.** Disables TLS certificate verification for `wss://`. |
| `--help`, `-h` | Usage. |

## Architecture & Crypto

### Identity

An Ed25519 keypair in a password-encrypted keystore (default `client.id`). The
encryption key comes from PBKDF2-HMAC-SHA256 at 600,000 iterations over a random
salt, and a minimum-iteration floor is enforced on load so a tampered file cannot
weaken the KDF. The file header (magic, version, iteration count, salt, nonce,
public key) is bound as AES-GCM associated data, so header tampering is detected
rather than silently accepted. Key material is wiped with `OPENSSL_cleanse`.

### Handshake

Three messages. The client's first message carries no identity at all, and each
side's identity is encrypted under a key derived from the Kyber exchange before
it is transmitted.

```
client                                                          server
  |                                                                |
  |  1. HandshakeHello { version, kem_public_key }                 |
  |     (anonymous — no identity on the wire)                      |
  | -------------------------------------------------------------> |
  |                                     encapsulate -> ss, kem_ct  |
  |                                     k_outer = HKDF(ss,"outer") |
  |                                                                |
  |  2. HandshakeResponse { version, kem_ciphertext,               |
  |       sealed_nonce, sealed_identity }                          |
  |     sealed_identity = AES-256-GCM(k_outer,                     |
  |         { identity_pub, identity_sig over H_s, confirm_s })    |
  | <------------------------------------------------------------- |
  |  decapsulate -> ss; derive k_outer; open seal;                 |
  |  verify server signature over H_s; verify confirm_s            |
  |                                                                |
  |  3. HandshakeConfirm { sealed_nonce, sealed_identity }          |
  |     sealed_identity = AES-256-GCM(k_outer,                     |
  |         { identity_pub, identity_sig over H_c, confirm_c })    |
  | -------------------------------------------------------------> |
  |                       open seal; verify client signature over  |
  |                       H_c; verify confirm_c; session ready     |
```

Two transcript hashes are used, because the server does not learn the client's
identity until the final message:

```
H_s = SHA256("E2EE-HS-v2|s" || version || lp(kem_pk) || lp(kem_ct) || lp(server_id_pub))
H_c = SHA256("E2EE-HS-v2|c" || version || lp(kem_pk) || lp(kem_ct) || lp(server_id_pub) || lp(client_id_pub))
```

`lp(x)` is a 4-byte big-endian length prefix followed by the bytes, so no field
can be shifted across a boundary without changing the hash. The server signs
`H_s`; the client signs `H_c`, which binds both identities together — a relay
cannot splice a client's final message onto a handshake carrying a different
server identity. Key confirmation MACs are compared in constant time, and the
protocol version is both checked explicitly and bound into the transcript.

### Session keys

HKDF-SHA256 expands the single Kyber shared secret into:

- `k_c2s` and `k_s2c` — **directional** AES-256-GCM keys. Each side encrypts
  with its send key and decrypts with its receive key, which is what makes
  reflected ciphertext fail to decrypt.
- `k_confirm` — handshake key-confirmation MAC key.
- `k_file` — whole-file HMAC key for transfers.
- `k_outer` — identity-seal key used during the handshake.

### Message layer (sealed sender)

The wire envelope carries only what decryption requires:

```
Envelope { version, nonce, ciphertext }
```

Everything else rides inside the AEAD plaintext:

```
[4-byte BE length][InnerMessage protobuf][random padding]

InnerMessage { sender_id, recipient_id, timestamp_unix, seq,
               kind, transfer_id, chunk_index, body }
```

The framed plaintext is padded to the next bucket — 256 B, 512 B, 1 KiB, 2 KiB,
4 KiB, 8 KiB, 16 KiB, 32 KiB, 64 KiB, 128 KiB, 256 KiB, then multiples of
256 KiB — so a 5-byte and a 200-byte message produce identically sized frames.
AAD is a direction tag plus the version and nothing else, since all per-message
metadata is now inside the ciphertext where it is both confidential and
authenticated. On receive: decrypt, unframe, check the timestamp window, then
enforce the monotonic sequence number — the counter is only advanced after the
AEAD tag verifies, so an unauthenticated frame cannot poison replay state.

### Relay rooms

Clients never send the room name. They send

```
token = hex(SHA256("E2EE-room-v1" || lp(room) || lp(secret)))
```

as the `room` query parameter. The relay treats it as an opaque key and needed no
changes. Fingerprint pins are still stored locally under the real room name, so
`pins.txt` stays readable.

### File transfer

`ConnectionEngine::sendFile` and `parseAndDecryptEvent` implement chunked
encrypted transfer: 256 KiB chunks streamed from and to disk so a large file is
never held in memory, a whole-file HMAC-SHA256 under `k_file` verified in
constant time before the file is finalized, filenames reduced to a sanitized
basename to prevent path traversal, and partial files deleted on any failure.
Chunk index and transfer id are authenticated inside the ciphertext, so a relay
cannot reorder chunks or splice them across transfers.

**This is currently an engine API only** — it is deliberately not wired into the
CLI or the GUI.

### Transports

- `beast_ws_transport.*` — Boost.Beast WebSocket, used by the CLI. For `wss://`
  it sets `verify_peer`, loads the system trust store, enables SNI and performs
  hostname verification. `--insecure` disables this for self-signed dev relays
  and prints a warning.
- `ws_transport.*` — Qt WebSocket, used by the GUI.
- `tcp_transport.*` — plain TCP, used by the `pqc_client` / `pqc_server` dev
  demos.

A 16 MiB frame cap applies, and the relay bounds inbound message size.

### GUI

Qt Widgets chat client with a "Key Exchange" dock panel that renders the
handshake as ordered steps — identity unlocked, Kyber keypair generated,
anonymous hello, encapsulation/decapsulation, identity unsealed, signature
verified, HKDF derivation, key confirmation, peer pinned — each driven by a real
engine observer callback rather than a simulated timeline. The panel reports only
public values (algorithm names, byte counts, fingerprints); key material is never
exposed to it. Peer fingerprints are shown prominently, with distinct first-use
and mismatch states.

## Security properties and limitations

**What a relay or passive observer can still see**

- Connection timing, message timing and cadence, and the number of frames.
- Which size *bucket* each frame fell into (not the true plaintext length).
- Source IP addresses.
- That Kyber-512 is in use, inferable from key and ciphertext lengths.

**Known limitations**

- **No cover traffic.** Metadata is greatly reduced, but traffic analysis by
  timing and volume remains possible. This is metadata *reduction*, not
  anonymity.
- **Room tokens without `--room-secret` are obfuscation, not secrecy.** A hash of
  a guessable room name can be dictionary-attacked; it stops casual log reading
  and enumeration, nothing stronger.
- **No forward secrecy for identity concealment.** The identity seal derives from
  the same KEM shared secret as the session, so compromise of that secret would
  retroactively unseal captured handshake identities.
- **TOFU is trust-on-first-use.** Pins are scoped per relay-host#room (CLI) or per
  username (GUI), not by a verified global identity directory. First-use
  fingerprints must be compared out of band.
- **Kyber-512 is NIST security level 1.** This is a KEM+AEAD hybrid (asymmetric
  KEM plus symmetric AEAD) — it is *not* a PQC+classical hybrid combiner; there
  is no X25519/ECDH alongside Kyber.
- **The relay performs no admission control.** Anyone holding the token can join
  a room, and participant counts are not capped.
- **Testing is one integration binary, and there is no CI.**
- **Not audited.** No independent review or formal verification. Treat it as a
  learning project, not production-grade software.

## Deploying the Relay (DigitalOcean)

The relay is headless and does **not** require Qt.

```bash
ssh root@<droplet_ip>
sudo apt-get update
sudo apt-get install -y build-essential cmake libboost-system-dev libssl-dev \
     protobuf-compiler libprotobuf-dev pkg-config
# build liboqs from source (see scripts/install_deps_ubuntu.sh)
cmake -S . -B build -DBUILD_GUI=OFF
cmake --build build -j1          # -j1 on small-RAM droplets
sudo ufw allow 8080/tcp
sudo systemctl enable --now relay_server   # uses deploy/relay_server.service
```

For TLS, put Caddy in front of the relay (`deploy/Caddyfile`) and connect with a
`wss://` URL so certificate verification applies.

## Project layout

```
connection_engine.*   handshake, sealed-sender message layer, file transfer
session.h             directional keys, sequence counters
crypto.h              AES-256-GCM helper
hkdf.*, kem_kyber.*   HKDF-SHA256, Kyber-512 via liboqs
identity.*            Ed25519 keystore (PBKDF2 + AES-GCM)
pin_store.*           shared TOFU fingerprint store
room_token.h          opaque relay room token derivation
file_transfer.h       chunk size, streaming HMAC, filename sanitizer
*.proto               wire formats (envelope, messages, handshake)
relay_server.cpp      room-keyed frame forwarder
relay_cli.cpp         CLI chat client
gui/                  Qt GUI, incl. HandshakePanel visualization
tools/                integration test
scripts/, deploy/     build helpers and deployment files
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
- length padding — that differently sized messages land in the same bucket
- ciphertext and version tampering are rejected
- sealed-identity tampering is rejected
- a validly-sealed response signed by the *wrong* identity is rejected at
  signature verification
- room-token determinism, distinctness and format

## License

See `LICENSE`.
