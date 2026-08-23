//! Shared [CNI specification](https://www.cni.dev/) types for Rust.
//!
//! This crate holds the data structures and error type defined by the
//! [CNI specification v1.1.0](https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md),
//! and nothing else. It contains no code that invokes a plugin, and none that is
//! invoked as one.
//!
//! Both sides build on it:
//!
//! - [`rscni-plugin`](https://docs.rs/rscni-plugin) — for writing a CNI plugin, the
//!   process a container runtime invokes.
//! - `rscni-runtime` (planned) — for invoking CNI plugins, the
//!   Rust counterpart to Go's `libcni`.
//!
//! Because they share these types, a plugin and a runtime written with them agree on
//! the wire format, and neither has to read the specification again.
//!
//! Depend on this crate directly only when you need the types without either side's
//! machinery, for example to parse a `.conflist` file.
//!
//! # Contents
//!
//! - [`types`] — network configuration, results, and the `CNI_*` environment variable
//!   names
//! - [`legacy`] — the result layout of specification versions 0.3.0 through 0.4.0
//! - [`error`] — [`Error`](error::Error), covering the specification's error codes and
//!   plugin-defined ones
//! - [`version`] — [`PluginInfo`](version::PluginInfo) and version negotiation
//!
//! # Supported specification versions
//!
//! v0.3.0, v0.3.1, v0.4.0, v1.0.0 and v1.1.0.

/// Re-exported: [`types`] uses its types in public signatures, so a plugin can name
/// them without depending on `ipnet` itself.
pub use ipnet;

pub mod error;
pub mod legacy;
pub mod types;
pub mod version;
