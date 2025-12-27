.PHONY: all build clean test

# Binary name
BINARY_NAME=jwtdebug

# Go related variables
GOBASE=$(shell pwd)
GOBIN=$(GOBASE)/bin
GOFILES=$(wildcard ./cmd/jwtdebug/*.go) $(wildcard ./internal/*/*.go)
BUILD_DIR=build

# Version from git: if a tag exists, use the tag, otherwise use the commit hash
# GoReleaser sets GORELEASER_CURRENT_TAG if building through GoReleaser
VERSION=$(shell if [ -n "$(GORELEASER_CURRENT_TAG)" ]; then echo $(GORELEASER_CURRENT_TAG); else git describe --tags --exact-match 2>/dev/null || git rev-parse --short HEAD; fi)

# Use linker flags to provide version/build info
LDFLAGS=-ldflags "-s -w -X github.com/rselbach/jwtdebug/internal/cli.Version=$(VERSION)"

all: build

build: 
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) $(LDFLAGS) ./cmd/jwtdebug
	@echo "Build successful! The binary '$(BUILD_DIR)/$(BINARY_NAME)' is now available."

clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@echo "Done!"

test:
	@echo "Running tests..."
	@go test -v ./...

install:
	@echo "Installing $(BINARY_NAME) version $(VERSION)..."
	@go install $(LDFLAGS) ./cmd/jwtdebug
	@echo "Installation successful!"
