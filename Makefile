.PHONY: all clean run

# Variables
BINARY_NAME=truffle
GO=go
GOFLAGS=-v
LDFLAGS=-ldflags "-s -w"
BIN_DIR=bin

all: $(BIN_DIR)
	@echo "Building $(BINARY_NAME)..."
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME) .

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BIN_DIR)

run: all
	@echo "Running $(BINARY_NAME)..."
	./$(BIN_DIR)/$(BINARY_NAME) -i en13 -k sk-svcacct-2NGdxpnJRKBSc3T6_oktsePfV0B0CmJVwXbsnX3G9NiRPVvld4YPQegREMsT3BlbkFJvnvox7XL7rS7ilPoG30cUFLavyWVXgWvWSL9MU2GqKInNA6F5xeaDya-DggA --debug-ai
