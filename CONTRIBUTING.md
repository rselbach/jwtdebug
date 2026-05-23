# Contributing to jwtdebug

Thanks for your interest in contributing!

## Development Setup

```bash
# Clone the repo
git clone https://github.com/rselbach/jwtdebug.git
cd jwtdebug

# Build
make build

# Run tests
make test

# Install locally
make install
```

Requires a stable Rust toolchain.

## Code Style

- Run `cargo fmt` before committing
- Keep `cargo clippy -- -D warnings` clean
- Add focused unit or CLI integration tests for behavior changes
- Keep it simple — avoid over-engineering

## Pull Requests

1. Fork the repo and create your branch from `main`
2. Add tests for new functionality
3. Ensure `make test` passes
4. Update documentation if needed
5. Keep commits focused and atomic

## Reporting Issues

When reporting bugs, please include:
- jwtdebug version (`jwtdebug --version`)
- OS and architecture
- Steps to reproduce
- Expected vs actual behavior

For security issues, please email directly instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
