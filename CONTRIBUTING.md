# Contributing to ftr

Thank you for your interest in contributing to ftr! This document provides guidelines for contributing to the project.

## How to Contribute

1. **Fork the repository** and create your branch from `main`.
2. **Add tests** for any new functionality.
3. **Ensure all tests pass** by running `cargo test`.
4. **Run clippy** to catch common mistakes: `cargo clippy -- -D warnings`
5. **Format your code** with `cargo fmt`.
6. **Update documentation** as needed.
7. **Submit a pull request** with a clear description of your changes.

## Development Setup

```bash
# Clone your fork
git clone git@github.com:YOUR_USERNAME/tracer.git
cd tracer

# Build the project
cargo build

# Run tests
cargo test

# Run with sudo (required for ICMP)
sudo cargo run -- google.com
```

## Code Style

- Follow Rust naming conventions
- Use meaningful variable names
- Add comments for complex logic
- Keep functions focused and small

## Reporting Issues

When reporting issues, please include:
- Your operating system
- Rust version (`rustc --version`)
- Steps to reproduce the issue
- Expected vs actual behavior

## Feature Requests

Feature requests are welcome! Please open an issue to discuss your idea before implementing major changes.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.