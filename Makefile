.PHONY: all build clean run linux-amd64

# Variables
BINARY_NAME=truffle
GO=go
GOFLAGS=-v
LDFLAGS=-ldflags "-s -w"

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_NAME) truffle.go

linux-amd64:
	@echo "Building $(BINARY_NAME) for Linux amd64..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_NAME)-linux-amd64 truffle.go

clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-linux-amd64
	rm -f go.sum
	rm -f go.mod

run:
	@echo "Running $(BINARY_NAME)..."
	./$(BINARY_NAME) -i en13 -k sk-svcacct-2NGdxpnJRKBSc3T6_oktsePfV0B0CmJVwXbsnX3G9NiRPVvld4YPQegREMsT3BlbkFJvnvox7XL7rS7ilPoG30cUFLavyWVXgWvWSL9MU2GqKInNA6F5xeaDya-DggA --debug-ai

# Initialize Go module
init:
	@echo "Initializing Go module..."
	$(GO) mod init truffle
	$(GO) mod tidy 