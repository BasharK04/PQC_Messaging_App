# Simple wrapper Makefile for easier builds and runs

BUILD_DIR ?= build
JOBS ?= 8
GUI ?= OFF
TYPE ?= RelWithDebInfo
PORT ?= 8080

.PHONY: all build gui clean relay cli test run-relay

all: build

build:
	cmake -S . -B $(BUILD_DIR) -DBUILD_GUI=$(GUI) -DCMAKE_BUILD_TYPE=$(TYPE)
	cmake --build $(BUILD_DIR) -j $(JOBS)

gui:
	$(MAKE) build GUI=ON

clean:
	rm -rf $(BUILD_DIR)

relay: build
	@echo Built relay_server at $(BUILD_DIR)/relay_server

cli: build
	@echo Built relay_cli at $(BUILD_DIR)/relay_cli

test: build
	$(BUILD_DIR)/engine_loopback_test

run-relay: relay
	$(BUILD_DIR)/relay_server $(PORT)

.PHONY: run-relay-fast
# Run relay without rebuilding; fails if binary missing
run-relay-fast:
	@if [ ! -x "$(BUILD_DIR)/relay_server" ]; then \
		echo "relay_server not found in $(BUILD_DIR). Run 'make' first." >&2; \
		exit 1; \
	fi
	$(BUILD_DIR)/relay_server $(PORT)
