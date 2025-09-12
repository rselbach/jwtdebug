# JWT Debug Tool

A modern command-line utility for debugging and analyzing JSON Web Tokens (JWTs).

## Features

- Decode and display JWT token components (header, claims, signature)
- Prettified claim display with human-readable formatting
- Special handling for standard JWT claims with human-friendly labels
- Verify token signatures with various algorithms (HMAC, RSA/PSS, ECDSA, EdDSA)
- Check expiration status and validity periods
- Colorized output for better readability
- Output formats: pretty, JSON, raw
- Decode base64url-encoded signatures to hex
- Multiple input methods (command-line arguments, piped input)
- Persistent configuration via config files
- Comprehensive test suite

## Project Structure

The codebase follows a modular structure for better organization:

```
jwtdebug/
├── cmd/
│   └── jwtdebug/      # Entry point and main application
├── internal/
│   ├── cli/           # Command-line interface and flags
│   ├── config/        # Config load/apply/save
│   ├── parser/        # JWT token parsing + normalization
│   ├── printer/       # Output formatting + expiration checks
│   └── verification/  # Signature verification
```

## Installation

### Using Homebrew

The recommended way to install jwtdebug is through Homebrew:

```bash
# Install from our tap
brew tap rselbach/tap
brew install jwtdebug
```

This will download and install the latest version of jwtdebug automatically.

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/jwtdebug.git
cd jwtdebug

# Build the binary (outputs to build/jwtdebug)
make build

# Run tests
make test

# (Optional) install to repo-local bin/ (respects GOBIN)
make install

# Run without building
go run ./cmd/jwtdebug -h
```

### Upgrading

To upgrade to the latest version when installed via Homebrew:

```bash
brew update
brew upgrade jwtdebug
```

## Usage

```bash
# Basic usage - decode a token
jwtdebug eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.signature

# Pipe a token from another command
echo "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature" | jwtdebug

# Show all token information including expiration status
jwtdebug -all eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature

# Verify a token signature using a key file
jwtdebug -verify -key public.pem eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature
```

## Options

```
-all            Show all token parts and information
-claims         Show token claims/payload (default: true)
-color          Colorize output (default: true)
-config         Path to config file
-decode-sig     Decode signature from base64
-expiry         Check token expiration status
-format         Output format: pretty, json, or raw (default: pretty)
-header         Show token header
-ignore-exp     Ignore token expiration when verifying
-key string     Key file for signature verification
-save-config    Save current settings to config file
-sig            Show token signature
-verify         Verify token signature (requires -key)
-version        Show version information
```

Notes:
- Claims are parsed without verification unless `-verify -key` is supplied. A one‑line notice is printed to stderr so JSON/stdout consumers aren’t broken.

For detailed information about configuration options, see [CONFIG.md](docs/CONFIG.md).

## Examples

### Decoding a token

```bash
jwtdebug eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.signature
```

Output:
```
CLAIMS:
  Subject: 1234567890

  Custom Claims:
  admin: true
  name: John Doe
```

### Checking expiration and showing all parts

```bash
jwtdebug -all eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNzE2MjM5MDIyfQ.signature
```

Output:
```
HEADER:
{
  "alg": "HS256",
  "typ": "JWT"
}

CLAIMS:
  Subject: 1234567890
  Expiration: 1716239022 2024-05-21T03:23:42Z

SIGNATURE:
Raw: signature

EXPIRATION:
✓ Token expires at 2024-05-21T03:23:42Z (2345678 seconds from now)
```

## Development

### Building from source
```bash
# Build the binary
make build
```

### Adding new features
The modular structure makes it easy to extend functionality:
- Add new output formats in the `printer` package
- Support for new token algorithms in the `verification` package
- Additional CLI options in the `cli` package

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
