#pragma once
#include <string>

// Trust-On-First-Use (TOFU) peer-fingerprint pin store shared by every
// frontend (CLI and GUI). Maps a caller-supplied peer label (e.g. a username or
// "host#room") to the peer's identity fingerprint (hex). Persisted to a simple
// "label fingerprint\n" text file with atomic writes and de-duplication.
//
// Both frontends MUST route their post-handshake peer check through this class
// so pinning behavior (and the MITM protection it provides) is identical.
enum class PinResult {
  Pinned,    // first use: the label was previously unknown and is now trusted
  Matched,   // the presented fingerprint matches the stored pin
  Mismatch   // the presented fingerprint DIFFERS from the stored pin (MITM!)
};

class PinStore {
public:
  // Looks up the pin for `peerLabel` in `pinsPath`.
  //  - not present  -> writes it, returns Pinned
  //  - present, ==  -> returns Matched
  //  - present, !=  -> returns Mismatch (the file is NOT modified)
  // The file is rewritten atomically (temp file + rename) and de-duplicated
  // whenever a new pin is added or existing duplicate lines are detected.
  static PinResult checkAndPin(const std::string& pinsPath,
                               const std::string& peerLabel,
                               const std::string& peerFingerprintHex);

  // Read-only lookup. Returns the stored fingerprint hex for `peerLabel`, or an
  // empty string if none is pinned.
  static std::string lookup(const std::string& pinsPath,
                            const std::string& peerLabel);
};
