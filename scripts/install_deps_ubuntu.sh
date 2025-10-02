#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config \
  libboost-system-dev libssl-dev protobuf-compiler libprotobuf-dev \
  qt6-base-dev qt6-websockets-dev

# liboqs: use distro if available, otherwise build from source
if ! pkg-config --exists liboqs; then
  echo "liboqs not found via pkg-config. See https://github.com/open-quantum-safe/liboqs for build instructions."
fi

