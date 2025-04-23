.PHONY: all build clean test

# Binary name
BINARY_NAME=jwtdebug

# Go related variables
GOBASE=$(shell pwd)
GOBIN=$(GOBASE)/bin
GOFILES=$(wildcard ./cmd/jwtdebug/*.go) $(wildcard ./internal/*/*.go)

# Use linker flags to provide version/build info
LDFLAGS=-ldflags "-s -w"

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	@go build -o $(BINARY_NAME) $(LDFLAGS) ./cmd/jwtdebug
	@echo "Build successful! The binary '$(BINARY_NAME)' is now available."

clean:
	@echo "Cleaning..."
	@rm -f $(BINARY_NAME)
	@echo "Done!"

test:
	@echo "Running tests..."
	@go test -v ./...

install:
	@echo "Installing $(BINARY_NAME)..."
	@go install $(LDFLAGS) ./cmd/jwtdebug
	@echo "Installation successful!"
