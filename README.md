# RsCNI

A Rust library for building [CNI (Container Network Interface)](https://www.cni.dev/) plugins with trait-based architecture.

[![crates.io](https://img.shields.io/crates/v/rscni.svg)](https://crates.io/crates/rscni)
[![docs.rs](https://docs.rs/rscni/badge.svg)](https://docs.rs/rscni)
![CI](https://github.com/terassyi/rscni/workflows/CI/badge.svg)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

RsCNI provides a type-safe API for implementing CNI plugins in Rust, following the [CNI specification v1.1.0](https://github.com/containernetworking/cni/blob/spec-v1.1.0/SPEC.md).

> **Breaking Changes in v0.1.0**
>
> The API has been completely redesigned from v0.0.4 with a new trait-based architecture.

## Features

- **Idiomatic Rust**: Trait-based design with type safety and zero-cost abstractions
- **Async Support**: Optional async/await support for high-performance plugins
- **CNI Spec Compliant**: Supports CNI specification v0.3.1, v0.4.0, v1.0.0, and v1.1.0
- **Well-tested**: Comprehensive unit tests and integration tests

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rscni = "0.1"
```

For async support, you need to enable the `async` feature and add `async-trait` and an async runtime (such as `tokio`):

```toml
[dependencies]
rscni = { version = "0.1", features = ["async"] }
async-trait = "0.1"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

### Basic Plugin (Sync)

Implement the `Cni` trait to create your CNI plugin:

```rust
use rscni::cni::{Cni, Plugin};
use rscni::{Args, CNIResult, Error};

struct MyCniPlugin;

impl Cni for MyCniPlugin {
    fn add(&self, args: Args) -> Result<CNIResult, Error> {
        // Implement network setup logic
        Ok(CNIResult::default())
    }

    fn del(&self, args: Args) -> Result<CNIResult, Error> {
        // Implement network teardown logic
        Ok(CNIResult::default())
    }

    fn check(&self, args: Args) -> Result<CNIResult, Error> {
        // Implement network validation logic
        Ok(CNIResult::default())
    }
}

fn main() {
    let my_cni = MyCniPlugin;
    let plugin = Plugin::default().msg("My CNI Plugin v0.1.0");

    plugin.run(&my_cni).expect("Failed to execute CNI command");
}
```

### Async Plugin

Enable the `async` feature and implement the async `Cni` trait:

```rust
use async_trait::async_trait;
use rscni::async_cni::{Cni, Plugin};
use rscni::{Args, CNIResult, Error};

struct MyAsyncCniPlugin;

#[async_trait]
impl Cni for MyAsyncCniPlugin {
    async fn add(&self, args: Args) -> Result<CNIResult, Error> {
        // Async network setup
        Ok(CNIResult::default())
    }

    async fn del(&self, args: Args) -> Result<CNIResult, Error> {
        // Async network teardown
        Ok(CNIResult::default())
    }

    async fn check(&self, args: Args) -> Result<CNIResult, Error> {
        // Async network validation
        Ok(CNIResult::default())
    }
}

#[tokio::main]
async fn main() {
    let my_cni = MyAsyncCniPlugin;
    let plugin = Plugin::default().msg("My Async CNI Plugin v0.1.0");

    plugin.run(&my_cni).await.expect("Failed to execute CNI command");
}
```

## Examples

Complete working examples are available in the [`examples/`](./examples) directory:

- [**rscni-debug**](./examples/rscni-debug/src/main.rs) - Synchronous CNI plugin for debugging
- [**async-rscni-debug**](./examples/async-rscni-debug/src/main.rs) - Asynchronous CNI plugin for debugging

Run examples:

```bash
# Build the debug plugin
cargo build --package rscni-debug

# Test with CNI environment
CNI_COMMAND=VERSION ./target/debug/rscni-debug
```

## CNI Data Types

RsCNI provides strongly-typed structures for CNI configurations:

- `Args` - CNI command arguments (container ID, netns, ifname, etc.)
- `NetConf` - Network configuration from stdin
- `CNIResult` - Plugin execution result with IPs, routes, DNS
- `PluginInfo` - Plugin version information

See the [API documentation](https://docs.rs/rscni) for complete type definitions.

## Testing

RsCNI includes comprehensive test coverage:

```bash
# Run unit tests only
cargo test --lib

# Run with async feature
cargo test --features async

# Run integration tests
cargo test --test plugin_integration_test
```

## License

RsCNI is licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) for the full license text.
