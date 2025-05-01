# Truffle

Truffle is a sophisticated network traffic analysis tool that combines packet capture capabilities with AI-powered analysis. It monitors network traffic in real-time, identifies patterns, and provides intelligent insights about network behavior and potential anomalies.

## Features

- Real-time network packet capture and analysis
- TLS/SNI detection and tracking
- DNS request monitoring
- AI-powered traffic analysis and anomaly detection
- Configurable filtering system
- Rate-limited API usage
- Detailed connection tracking
- Debug mode for detailed output

## Prerequisites

- Go 1.16 or later
- libpcap development libraries
- OpenAI API key

## Installation

1. Clone the repository:
```bash
git clone https://github.com/doxx/truffle.git
cd truffle
```

2. Install dependencies:
```bash
go mod download
```

3. Build the project:
```bash
make build
```

## Usage

Run Truffle with the following command:

```bash
./bin/truffle -i <interface> -k <openai-api-key> [-debug]
```

### Command Line Arguments

- `-i`: Network interface to capture on (required)
- `-k`: OpenAI API key (required)
- `-debug`: Enable debug output (optional)

## Development

The project consists of several key components:

- `truffle.go`: Main application logic and packet capture
- `ai_analyzer.go`: AI-powered analysis and OpenAI integration
- `filter.go`: Filtering system implementation
- `types.go`: Common type definitions

### Building

```bash
make build
```

### Testing

```bash
make test
```

## License

To be determined.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
