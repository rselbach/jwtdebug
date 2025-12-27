# Changelog

All notable changes to jwtdebug will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Smart token extraction** (enabled by default):
  - Automatically extracts JWTs from cookies, headers, JSON, and more
  - Just paste `_session_cookie=eyJ...` or `Authorization: Bearer eyJ...` — it just works
  - Use `--strict` to disable and require exact JWT input
- **CLI improvements for familiarity**:
  - Long and short flag forms (e.g., `--signature`/`-s`, `--all`/`-a`, `--key-file`/`-k`)
  - `--output`/`-o` flag (replaces `--format` for consistency with kubectl, docker, jq)
  - `--no-color` flag as alternative to `--color=false`
  - `--verbose`/`-v` flag for debugging
  - `--raw-claims` flag for piping claims to jq or other tools
  - Explicit `-h`/`--help` flags
  - `--completion` flag for generating shell completions (bash, zsh, fish)
- **Better error messages**: Token snippets included in error output
- **Stdin improvements**:
  - Support for `-` as explicit stdin marker
  - Helpful hint when no token is provided
  - Message when reading from stdin interactively
- **Version output**: Now includes commit hash and build date with `--verbose`
- **Exit codes**: Documented and consistent exit codes (0=success, 1=error, 2=invalid token, 3=verification failed, 4=config error)
- **Shell completions**: Generate completions with `jwtdebug --completion bash|zsh|fish`

### Changed

- Renamed flags for consistency with common CLI tools:
  - `-sig` → `--signature`/`-s`
  - `-expiry` → `--expiration`/`-e`
  - `-decode-sig` → `--decode-signature`
  - `-key` → `--key-file`/`-k`
  - `-format` → `--output`/`-o`
  - `-ignore-exp` → `--ignore-expiration`
- Old flag names still work for backward compatibility but are hidden from help

### Fixed

- Exit code now properly reflects verification failures

## [0.1.0] - Initial Release

### Added

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
