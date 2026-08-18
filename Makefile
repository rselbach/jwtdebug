.PHONY: all build clean format-check install lint test

BINARY_NAME := jwtdebug
BUILD_DIR := build

# GoReleaser sets GORELEASER_CURRENT_TAG when it builds a release.
VERSION := $(shell \
	if [ -n "$(GORELEASER_CURRENT_TAG)" ]; then \
	  echo "$(GORELEASER_CURRENT_TAG)"; \
	else \
	  git describe --tags --exact-match 2>/dev/null \
	    || git rev-parse --short HEAD; \
	fi)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
# Use the commit timestamp by default so repeated builds of the same revision
# carry identical metadata. Callers can override BUILD_DATE when needed.
BUILD_DATE ?= $(shell git show -s --format=%cI HEAD 2>/dev/null || echo "unknown")

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p "$(BUILD_DIR)"
	@JWTDEBUG_VERSION="$(VERSION)" \
	  JWTDEBUG_COMMIT="$(COMMIT)" \
	  JWTDEBUG_BUILD_DATE="$(BUILD_DATE)" \
	  cargo build --locked --release
	@cp "target/release/$(BINARY_NAME)" "$(BUILD_DIR)/$(BINARY_NAME)"
	@echo "Build successful: $(BUILD_DIR)/$(BINARY_NAME)"

clean:
	@echo "Cleaning..."
	@rm -rf "$(BUILD_DIR)" "target"
	@echo "Done!"

format-check:
	@cargo fmt -- --check

test: format-check
	@echo "Running Rust checks..."
	@cargo clippy --locked --all-targets -- -D warnings
	@cargo test --locked --all-targets

lint: format-check
	@cargo clippy --locked --all-targets -- -D warnings

install:
	@echo "Installing $(BINARY_NAME) version $(VERSION)..."
	@JWTDEBUG_VERSION="$(VERSION)" \
	  JWTDEBUG_COMMIT="$(COMMIT)" \
	  JWTDEBUG_BUILD_DATE="$(BUILD_DATE)" \
	  cargo install --locked --path .
	@echo "Installation successful!"
