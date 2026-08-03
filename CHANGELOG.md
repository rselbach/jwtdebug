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
  - `--verbose`/`-v` flag for debugging
  - `--raw-claims` flag for piping claims to jq or other tools
  - Explicit `-h`/`--help` flags
- **Better error messages**: Token snippets included in error output
- **Stdin improvements**:
  - Support for `-` as explicit stdin marker
  - Helpful hint when no token is provided
  - Message when reading from stdin interactively
- **Version output**: Now includes commit hash and build date with `--verbose`
- **Exit codes**: Documented and consistent exit codes (0=success, 1=error, 2=invalid token, 3=verification failed)
- Verification errors name a trailing newline in an HMAC key file, a common
  result of writing the secret with `echo` rather than `echo -n`

### Changed

- Rewrote the codebase in idiomatic Go using only the standard library while
  preserving the CLI, verification algorithms, output, and exit-code contract
- Replaced the Cargo, Rust, and Zig build pipeline with native Go builds across
  Linux, macOS, and Windows
- Removed the nonfunctional AppImage release hook and its unverified rolling
  tool download; supported Linux archives and packages are unchanged
- Migrated the deprecated GoReleaser Homebrew formula configuration to a cask
- Pinned release and CI actions plus the Rust, Zig, cargo-zigbuild, and
  GoReleaser tool versions for reproducible workflows
- Replaced the P-521 release candidate with stable `p521` 0.14 and declared
  Rust 1.88 as the minimum supported compiler required by the locked dependency
  graph
- CI now tests Linux, macOS, and Windows from one matrix and checks the declared
  Rust 1.88 minimum; the redundant build-only job was removed
- Help output is generated from the Clap argument definitions, eliminating the
  duplicate hand-maintained option list
- Verification key files and algorithm-specific key parsers are prepared once
  per invocation and reused for every input token
- Integration tests are split into focused CLI and verification targets with
  shared fixtures in one support module
- **BREAKING**: expiration report timestamps are always rendered in UTC for
  deterministic output across machines
- **BREAKING**: signature verification now requires `--algorithm`, so the
  expected algorithm comes from the user rather than the untrusted token header
- **BREAKING**: `--help` writes to stdout instead of stderr, so it can be piped
  to a pager or `grep`
- **BREAKING**: every input token is processed even when an earlier one fails,
  for both command-line arguments and piped stdin. The exit code reports the
  first failure rather than stopping at it
- A short HMAC key warns instead of failing verification, so tokens signed with
  common sample secrets (jwt.io's default is 19 bytes) can be inspected. The
  warning is not silenced by `--quiet`
- Key file failures report a single "failed to open key file" message instead of
  splitting into separate stat and read wording

- Renamed flags for consistency with common CLI tools:
  - `-sig` → `--signature`/`-s`
  - `-expiry` → `--expiration`/`-e`
  - `-key` → `--key-file`/`-k`
  - `-ignore-exp` → `--ignore-expiration`
- Old flag names still work for backward compatibility but are hidden from help

### Fixed

- Smart extraction now recognizes `=` as a JWT boundary, so the documented
  cookie and `Set-Cookie` inputs are actually decoded
- `--ignore-expiration` skips only `exp`; future or malformed `nbf` claims are
  still rejected during signature verification
- Integer and fractional `exp` values now expire consistently at subsecond
  boundaries
- Non-regular key paths such as FIFOs are rejected before opening, avoiding a
  blocking read when no writer is attached
- Closed output pipes now terminate cleanly instead of panicking
- Exit code now properly reflects verification failures
- A future `iat` is reported as time remaining instead of a negative age
- Rejected HMAC and RSA signatures report "signature is invalid" rather than
  jsonwebtoken's internal enum name, matching what the ES512 path already said
- DER-encoded SubjectPublicKeyInfo keys are rejected as HMAC secrets, closing a
  gap in the algorithm-confusion guard that only checked for PEM
- Fractional NumericDate strings such as `"exp": "1700000000.5"` are accepted,
  matching the existing handling of fractional numbers

## [0.1.0] - Initial Release

### Added

- Decode and display JWT token components (header, claims, signature)
- Prettified claim display with human-readable formatting
- Special handling for standard JWT claims with human-friendly labels
- Verify token signatures with various algorithms (HMAC, RSA/PSS, ECDSA, EdDSA)
- Check expiration status and validity periods
- Multiple input methods (command-line arguments, piped input)
- Comprehensive test suite
