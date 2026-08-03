.PHONY: all build clean format-check install lint test

BINARY_NAME := jwtdebug
BUILD_DIR := build
COMMAND := ./cmd/jwtdebug
GO := go
VERSION_PACKAGE := github.com/rselbach/jwtdebug/internal/jwtdebug

# GoReleaser sets GORELEASER_CURRENT_TAG when it builds a release.
VERSION := $(shell \
	if [ -n "$(GORELEASER_CURRENT_TAG)" ]; then \
	  echo "$(GORELEASER_CURRENT_TAG)"; \
	else \
	  git describe --tags --exact-match 2>/dev/null \
	    || git rev-parse --short HEAD; \
	fi)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X $(VERSION_PACKAGE).version=$(VERSION) \
	-X $(VERSION_PACKAGE).commit=$(COMMIT) \
	-X $(VERSION_PACKAGE).buildDate=$(BUILD_DATE)

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p "$(BUILD_DIR)"
	@$(GO) build -trimpath -ldflags "$(LDFLAGS)" \
	  -o "$(BUILD_DIR)/$(BINARY_NAME)" "$(COMMAND)"
	@echo "Build successful: $(BUILD_DIR)/$(BINARY_NAME)"

clean:
	@echo "Cleaning..."
	@rm -rf "$(BUILD_DIR)"
	@echo "Done!"

format-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$${unformatted}" ]; then \
	  echo "The following Go files need formatting:" >&2; \
	  echo "$${unformatted}" >&2; \
	  exit 1; \
	fi

test: format-check
	@echo "Running Go checks..."
	@$(GO) vet ./...
	@$(GO) test -race ./...

lint: format-check
	@golangci-lint run ./...

install:
	@echo "Installing $(BINARY_NAME) version $(VERSION)..."
	@$(GO) install -trimpath -ldflags "$(LDFLAGS)" "$(COMMAND)"
	@echo "Installation successful!"
