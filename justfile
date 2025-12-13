# Default recipe - runs all checks and tests
default: build build-examples

# Run all lint checks
lint: check fmt clippy

# Run all tests
test: unit-test doc-test integration-test

# Check if the code compiles with all features
check:
    cargo check --all-features

# Check code formatting
fmt:
    cargo fmt --all -- --check

# Run clippy lints
clippy:
    cargo clippy --all-features -- -D warnings

# Run clippy with auto-fixes
clippy-fix:
    cargo clippy --all-features --fix

# Test the library with default features
unit-test:
    cargo test --lib
    cargo test --lib --features async

# Test the documentation examples
doc-test:
    cargo test --doc

# Build example plugins
build-examples:
    cargo build --package rscni-debug
    cargo build --package async-rscni-debug

# Run plugin integration tests
integration-test:
    cargo test --test plugin_integration_test

# Build all packages
build:
    cargo build --all

# Build with release profile
build-release:
    cargo build --all --release

# Clean build artifacts
clean:
    cargo clean

# Generate documentation
doc:
    cargo doc --all-features

# Show help
help:
    @just --list
