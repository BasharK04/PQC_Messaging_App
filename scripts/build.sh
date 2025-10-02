#!/usr/bin/env bash
set -euo pipefail

GUI=${GUI:-OFF}
TYPE=${TYPE:-RelWithDebInfo}
JOBS=${JOBS:-8}
BUILD_DIR=${BUILD_DIR:-build}

usage() {
  echo "Usage: GUI=ON|OFF TYPE=Debug|Release|RelWithDebInfo JOBS=N BUILD_DIR=dir $0" >&2
}

cmake -S . -B "$BUILD_DIR" -DBUILD_GUI="$GUI" -DCMAKE_BUILD_TYPE="$TYPE"
cmake --build "$BUILD_DIR" -j "$JOBS"
echo "Done. Binaries in $BUILD_DIR/"

