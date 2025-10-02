#!/usr/bin/env bash
set -euo pipefail

brew update
brew install cmake boost openssl@3 abseil protobuf pkg-config liboqs qt
echo "If CMake can't find Qt, configure with: -DCMAKE_PREFIX_PATH=\"$(brew --prefix qt)\""

