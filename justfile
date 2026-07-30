# Default recipe - builds every crate, examples included
default: build

# No `check` here: clippy type-checks everything cargo check does, so running both
# compiles the workspace twice for one set of diagnostics.

# Run all lint checks
lint: fmt clippy

# Run all tests
test: unit-test doc-test integration-test

# Check if the code compiles with all features
check:
    cargo check --workspace --all-features

# Check code formatting
fmt:
    cargo fmt --all -- --check

# Run clippy lints
clippy:
    cargo clippy --workspace --all-features --all-targets -- -D warnings

# Once with default features, once with everything, so the feature-gated code is covered
# both ways. `--workspace` rather than a list of `--package` flags, so a new crate is
# picked up without editing this.

# Test every crate's library
unit-test:
    cargo test --workspace --lib
    cargo test --workspace --lib --all-features

# Test the documentation examples
doc-test:
    cargo test --workspace --doc --all-features

# Run cross-crate integration tests
integration-test:
    cargo test --package integration-tests

# One invocation, not one per package: separate invocations resolve rscni-plugin under
# different feature sets and rebuild it each time.

# Build example plugins
build-examples:
    cargo build --package rscni-debug --package async-rscni-debug

# Build all packages
build:
    cargo build --workspace

# Build with release profile
build-release:
    cargo build --workspace --release

# Clean build artifacts
clean:
    cargo clean

# Generate documentation
doc:
    cargo doc --workspace --all-features

# All three in one invocation, not one each: cargo then verifies each packaged crate
# against the others it just built. Packaging rscni-plugin alone fails until rscni-types
# is actually on crates.io.

# Verify the publishable crates package cleanly
package:
    cargo package -p rscni-types -p rscni-plugin -p rscni --allow-dirty

# The manual kind cluster walkthrough for the example plugins. Kept out of this file
# because it needs docker and kind and never runs in CI, unlike everything above.
mod examples 'rscni/examples'

# Show help
help:
    @just --list --list-submodules
