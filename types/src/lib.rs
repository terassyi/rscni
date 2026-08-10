//! Shared [CNI specification](https://www.cni.dev/) types for Rust.
//!
//! This crate holds the data structures and error type defined by the
//! [CNI specification v1.1.0](https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md),
//! and nothing else. It knows how to represent a CNI conversation but never
//! takes part in one.
//!
//! Both sides of that conversation build on it:
//!
//! - [`rscni-plugin`](https://docs.rs/rscni-plugin) — for writing a CNI plugin, the
//!   process a container runtime invokes.
//! - `rscni-runtime` (planned) — for invoking CNI plugins, the
//!   Rust counterpart to Go's `libcni`.
//!
//! Sharing the types means a plugin and a runtime written with these crates agree on
//! the wire format by construction, and neither has to re-derive the specification.
//!
//! You normally depend on this crate directly only when you need the types without
//! either side's machinery — for example to parse a `.conflist` file.
//!
//! # Contents
//!
//! - [`types`] — network configuration, results, and the `CNI_*` environment variable
//!   names
//! - [`legacy`] — the result layout of specification versions 0.3.0 through 0.4.0
//! - [`error`] — [`Error`](error::Error), covering the specification's error codes
//! - [`version`] — [`PluginInfo`](version::PluginInfo) and version negotiation
//!
//! # Supported specification versions
//!
//! v0.3.0, v0.3.1, v0.4.0, v1.0.0 and v1.1.0.

pub mod error;
pub mod legacy;
pub mod types;
pub mod version;
