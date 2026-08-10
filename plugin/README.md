# rscni-plugin

A Rust library for building [CNI (Container Network Interface)](https://www.cni.dev/) plugins with trait-based architecture.

[![crates.io](https://img.shields.io/crates/v/rscni-plugin.svg)](https://crates.io/crates/rscni-plugin)
[![docs.rs](https://docs.rs/rscni-plugin/badge.svg)](https://docs.rs/rscni-plugin)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/terassyi/rscni/blob/main/LICENSE)

`rscni-plugin` provides a type-safe API for implementing CNI plugins in Rust, following the [CNI specification v1.1.0](https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md).

This is the *plugin* side of CNI: the process a container runtime invokes. To invoke plugins instead, see `rscni-runtime` (planned).

> [!IMPORTANT]
> **Renamed from `rscni`.** If you depend on `rscni` 0.2.x, change the dependency to `rscni-plugin = "0.3"` and replace `rscni::` with `rscni_plugin::`; the module layout is unchanged. `rscni` 0.3.0 is a deprecated shim that re-exports this crate to ease the move.

## Features

- **Idiomatic Rust**: Trait-based design with type safety and zero-cost abstractions
- **Async Support**: Optional async/await support for high-performance plugins
- **CNI Spec Compliant**: Supports CNI specification v0.3.0, v0.3.1, v0.4.0, v1.0.0 and v1.1.0
- **Well-tested**: Comprehensive unit tests and integration tests

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rscni-plugin = "0.3"
```

For async support, you need to enable the `async` feature and add `async-trait` and an async runtime (such as `tokio`):

```toml
[dependencies]
rscni-plugin = { version = "0.3", features = ["async"] }
async-trait = "0.1"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

### Basic Plugin (Sync)

Implement the `Cni` trait to create your CNI plugin:

```rust
use rscni_plugin::cni::{Cni, Plugin};
use rscni_plugin::error::Error;
use rscni_plugin::types::{Args, CNIResult};

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

    fn status(&self, args: Args) -> Result<(), Error> {
        // Implement status check
        Ok(())
    }

    fn gc(&self, args: Args) -> Result<(), Error> {
        // Implement gc logic
        Ok(())
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
use rscni_plugin::async_cni::{Cni, Plugin};
use rscni_plugin::error::Error;
use rscni_plugin::types::{Args, CNIResult};

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

    async fn status(&self, args: Args) -> Result<(), Error> {
        // Implement status check
        Ok(())
    }

    async fn gc(&self, args: Args) -> Result<(), Error> {
        // Implement gc logic
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let my_cni = MyAsyncCniPlugin;
    let plugin = Plugin::default().msg("My Async CNI Plugin v0.1.0");

    plugin.run(&my_cni).await.expect("Failed to execute CNI command");
}
```

## CNI Data Types

- `types::Args` - CNI command arguments (container ID, netns, ifname, etc.)
- `types::NetConf` - Network configuration from stdin
- `types::CNIResult` - Plugin execution result with IPs, routes, DNS
- `version::PluginInfo` - Plugin version information

Everything except `Args` and `ArgsBuilder` is re-exported from [`rscni-types`](https://crates.io/crates/rscni-types), so `rscni_plugin::types::NetConf` and `rscni_types::types::NetConf` are the same type. `Args` is specific to being invoked as a plugin, which is why it lives here.

See the [API documentation](https://docs.rs/rscni-plugin) for complete type definitions.

## Examples

Complete working examples live in [`examples/`](https://github.com/terassyi/rscni/tree/main/examples):

- [**rscni-debug**](https://github.com/terassyi/rscni/blob/main/examples/rscni_debug.rs) - Synchronous CNI plugin for debugging
- [**async-rscni-debug**](https://github.com/terassyi/rscni/blob/main/examples/async_rscni_debug.rs) - Asynchronous CNI plugin for debugging

## License

Apache-2.0. See [LICENSE](https://github.com/terassyi/rscni/blob/main/LICENSE).
