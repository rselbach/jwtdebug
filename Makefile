.PHONY: all build clean test install

# Binary name
BINARY_NAME=jwtdebug

BUILD_DIR=build

# Version from git: if a tag exists, use the tag, otherwise use the commit hash
# GoReleaser sets GORELEASER_CURRENT_TAG if building through GoReleaser
VERSION=$(shell if [ -n "$(GORELEASER_CURRENT_TAG)" ]; then echo $(GORELEASER_CURRENT_TAG); else git describe --tags --exact-match 2>/dev/null || git rev-parse --short HEAD; fi)
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@JWTDEBUG_VERSION=$(VERSION) \
		JWTDEBUG_COMMIT=$(COMMIT) \
		JWTDEBUG_BUILD_DATE=$(BUILD_DATE) \
		cargo build --release
	@cp target/release/$(BINARY_NAME) $(BUILD_DIR)/$(BINARY_NAME)
	@echo "Build successful! The binary '$(BUILD_DIR)/$(BINARY_NAME)' is now available."

clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@cargo clean
	@echo "Done!"

test:
	@echo "Running Rust tests..."
	@cargo fmt --check
	@cargo clippy -- -D warnings
	@cargo test

install:
	@echo "Installing $(BINARY_NAME) version $(VERSION)..."
	@JWTDEBUG_VERSION=$(VERSION) \
		JWTDEBUG_COMMIT=$(COMMIT) \
		JWTDEBUG_BUILD_DATE=$(BUILD_DATE) \
		cargo install --path .
	@echo "Installation successful!"
