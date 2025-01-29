# Binary name and path
BINARY_NAME=jwtdebug
BUILD_DIR=build

# Main build target
all: $(BUILD_DIR)/$(BINARY_NAME)

# Create build directory if it doesn't exist and build the binary
$(BUILD_DIR)/$(BINARY_NAME): go.* *.go | $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Clean target to remove build artifacts
clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
