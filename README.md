# jwtdebug

A fast, modern command-line utility for decoding and debugging JSON Web Tokens (JWTs).

## Why jwtdebug?

- **Fast**: Native Go binary, no runtime dependencies
- **Secure**: Tokens never leave your machine (unlike jwt.io)
- **Smart**: Extracts JWTs from cookies, headers, JSON — just paste whatever you copied
- **Scriptable**: JSON output, exit codes, and raw claims for piping to `jq`
- **Familiar CLI**: Follows conventions from tools like `kubectl`, `jq`, and `curl`

## Quick Start

```bash
# Install via Homebrew
brew install rselbach/tap/jwtdebug

# Try it now with this sample token:
jwtdebug eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

# Decode a token
jwtdebug eyJhbGciOiJIUzI1NiIs...

# Decode from clipboard (macOS)
pbpaste | jwtdebug

# Show everything
jwtdebug -a eyJhbGciOiJIUzI1NiIs...

# Verify signature
jwtdebug -V -k public.pem eyJhbGciOiJIUzI1NiIs...

# Pipe claims to jq
jwtdebug --raw-claims token | jq '.sub'
```

## Features

- 🔍 **Decode** JWT header, claims, and signature
- ✅ **Verify** signatures (HMAC, RSA, RSA-PSS, ECDSA, EdDSA)
- ⏰ **Check** expiration status with human-readable output
- 🎨 **Colorized** output (disable with `--no-color`)
- 📤 **Multiple formats**: pretty (default), JSON, raw
- 📥 **Flexible input**: argument, pipe, clipboard, or stdin
- ⚙️ **Configurable**: save preferences to `~/.jwtdebug.json`
- 🐚 **Shell completions**: bash, zsh, fish

## Installation

### Homebrew (recommended)

```bash
brew tap rselbach/tap
brew install jwtdebug
```

### From Source

```bash
git clone https://github.com/rselbach/jwtdebug.git
cd jwtdebug
make build
./build/jwtdebug --help
```

## Usage

```
jwtdebug [options] <token>
jwtdebug [options] -           # read from stdin explicitly
command | jwtdebug [options]   # read from pipe
```

### Display Options

| Flag | Short | Description |
|------|-------|-------------|
| `--all` | `-a` | Show all token parts and info |
| `--header` | `-H` | Show token header |
| `--claims` | `-c` | Show token claims (default: true) |
| `--signature` | `-s` | Show token signature |
| `--expiration` | `-e` | Check token expiration status |
| `--decode-signature` | | Decode signature from base64 to hex |
| `--raw-claims` | | Output only raw claims JSON (for piping) |

### Verification Options

| Flag | Short | Description |
|------|-------|-------------|
| `--verify` | `-V` | Verify token signature |
| `--key-file` | `-k` | Key file for signature verification |
| `--ignore-expiration` | | Ignore token expiration when verifying |

### Output Options

| Flag | Short | Description |
|------|-------|-------------|
| `--output` | `-o` | Output format: `pretty`, `json`, or `raw` |
| `--color` | | Colorize output (default: true) |
| `--no-color` | | Disable colored output |

### Input Options

| Flag | Description |
|------|-------------|
| `--strict` | Disable smart extraction (expect exact JWT input) |

By default, jwtdebug uses **smart extraction** to find JWTs in any input:
- `Bearer eyJ...` — Authorization headers
- `cookie_name=eyJ...` — Cookie values
- `Set-Cookie: token=eyJ...; HttpOnly` — Set-Cookie headers
- `{"access_token":"eyJ..."}` — JSON responses

Use `--strict` if you need exact input matching.

### Other Options

| Flag | Short | Description |
|------|-------|-------------|
| `--help` | `-h` | Show help message |
| `--version` | | Show version information |
| `--quiet` | `-q` | Suppress informational notices |
| `--verbose` | `-v` | Enable verbose output |
| `--completion` | | Generate shell completion (bash, zsh, fish) |
| `--config` | | Path to config file |
| `--save-config` | | Save current settings to config file |

## Examples

### Basic Decoding

```bash
$ jwtdebug eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ

CLAIMS:
  Standard Claims:
    Subject: 1234567890

  Custom Claims:
    admin: true
    name:  John Doe
```

### Show Everything

```bash
$ jwtdebug -a token

HEADER:
{
  "alg": "HS256",
  "typ": "JWT"
}

CLAIMS:
  Standard Claims:
    Subject:    1234567890
    Expiration: 1716239022 (2024-05-21T03:23:42Z)

SIGNATURE:
Raw: TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ

EXPIRATION:
✓ Token expires at 2024-05-21T03:23:42Z (in 30 days)
```

### Verify Signature

```bash
$ jwtdebug -V -k public.pem token
CLAIMS:
  ...

VERIFICATION:
✓ Signature verified successfully
```

**Key formats by algorithm:**
- **HMAC** (HS256/384/512): Raw secret bytes in a file (e.g., `echo -n "your-secret" > secret.key`)
- **RSA** (RS256/384/512, PS256/384/512): PEM-encoded public key
- **ECDSA** (ES256/384/512): PEM-encoded EC public key
- **EdDSA**: PEM-encoded Ed25519 public key

### Pipe to jq

```bash
$ jwtdebug --raw-claims token | jq '.sub'
"1234567890"
```

### Read from Pipe

```bash
# From clipboard (macOS)
pbpaste | jwtdebug

# From a file
cat token.txt | jwtdebug

# From another command
curl -s https://api.example.com/token | jwtdebug
```

## Shell Completions

Generate and install shell completions:

```bash
# Bash
jwtdebug --completion bash > /usr/local/etc/bash_completion.d/jwtdebug

# Zsh
jwtdebug --completion zsh > "${fpath[1]}/_jwtdebug"

# Fish
jwtdebug --completion fish > ~/.config/fish/completions/jwtdebug.fish
```

## Configuration

Save your preferred settings:

```bash
# Save current options as defaults
jwtdebug -o json --no-color --save-config

# Use a specific config file
jwtdebug --config ~/.config/jwtdebug/work.json token
```

See [CONFIG.md](docs/CONFIG.md) for details.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid token format |
| 3 | Signature verification failed |
| 4 | Configuration error |

## Comparison with Alternatives

| Feature | jwtdebug | jwt.io | jwt-cli |
|---------|----------|--------|---------|
| Offline/secure | ✅ | ❌ | ✅ |
| Signature verification | ✅ | ✅ | ✅ |
| Shell completions | ✅ | N/A | ❌ |
| Config file | ✅ | N/A | ❌ |
| Pipe-friendly | ✅ | ❌ | ✅ |
| Homebrew install | ✅ | N/A | ✅ |

## Project Structure

```
jwtdebug/
├── cmd/jwtdebug/      # Entry point
├── internal/
│   ├── cli/           # Command-line flags
│   ├── completions/   # Shell completions
│   ├── config/        # Configuration handling
│   ├── parser/        # JWT parsing
│   ├── printer/       # Output formatting
│   └── verification/  # Signature verification
└── docs/              # Documentation
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see [LICENSE](LICENSE) for details.
