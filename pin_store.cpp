#include "pin_store.h"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {

// Parse the pins file into an ordered list of (label, fingerprint) pairs,
// de-duplicated by label keeping the FIRST occurrence. `hadDuplicates` is set
// true if the raw file contained duplicate or malformed lines so the caller can
// decide to rewrite a clean version. Missing file is treated as empty.
std::vector<std::pair<std::string, std::string>> readPins(const std::string& path,
                                                          bool& hadDuplicates) {
  hadDuplicates = false;
  std::vector<std::pair<std::string, std::string>> pins;
  std::unordered_set<std::string> seen;

  std::ifstream f(path);
  if (!f) return pins;

  std::string line;
  size_t rawLines = 0;
  while (std::getline(f, line)) {
    std::istringstream iss(line);
    std::string label, fp;
    if (!(iss >> label >> fp)) {
      // blank or malformed line -> mark dirty so we rewrite a clean file
      if (!line.empty()) hadDuplicates = true;
      continue;
    }
    ++rawLines;
    if (seen.count(label)) {
      hadDuplicates = true;  // duplicate label
      continue;
    }
    seen.insert(label);
    pins.emplace_back(std::move(label), std::move(fp));
  }
  if (rawLines != pins.size()) hadDuplicates = true;
  return pins;
}

// Atomically write the pins to `path`: write to a temp file, fsync-free rename.
bool writePinsAtomic(const std::string& path,
                     const std::vector<std::pair<std::string, std::string>>& pins) {
  const std::string tmp = path + ".tmp";
  {
    std::ofstream out(tmp, std::ios::trunc);
    if (!out) return false;
    for (const auto& kv : pins) {
      out << kv.first << " " << kv.second << "\n";
    }
    out.flush();
    if (!out.good()) return false;
  }
  // std::rename is atomic on POSIX when src and dst are on the same filesystem.
  if (std::rename(tmp.c_str(), path.c_str()) != 0) {
    std::remove(tmp.c_str());
    return false;
  }
  return true;
}

}  // namespace

std::string PinStore::lookup(const std::string& pinsPath,
                             const std::string& peerLabel) {
  bool dirty = false;
  auto pins = readPins(pinsPath, dirty);
  for (const auto& kv : pins) {
    if (kv.first == peerLabel) return kv.second;
  }
  return {};
}

PinResult PinStore::checkAndPin(const std::string& pinsPath,
                                const std::string& peerLabel,
                                const std::string& peerFingerprintHex) {
  bool dirty = false;
  auto pins = readPins(pinsPath, dirty);

  for (const auto& kv : pins) {
    if (kv.first == peerLabel) {
      if (kv.second == peerFingerprintHex) {
        // Matched. Opportunistically clean up any duplicate/malformed lines so
        // the file self-heals (the legacy file appended duplicates).
        if (dirty) writePinsAtomic(pinsPath, pins);
        return PinResult::Matched;
      }
      // A pin exists and differs: do NOT modify the file, signal MITM.
      return PinResult::Mismatch;
    }
  }

  // First use: trust and persist.
  pins.emplace_back(peerLabel, peerFingerprintHex);
  writePinsAtomic(pinsPath, pins);
  return PinResult::Pinned;
}
