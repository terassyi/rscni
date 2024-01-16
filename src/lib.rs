//! RsCNI is a CNI plugin library for Rust.
//! RsCNI has a similar APIs to [containernetworking/cni/pkg/skel](https://pkg.go.dev/github.com/containernetworking/cni/pkg/skel).
//! The entrypoint is `Plugin`.
//! It accepts callback functions defined as `CmdFn` to represent CNI Add, Del and Check commands.
//!
//! Please see [rscni-debug](github.com/terassyi/rscni/blob/main/examples/README.md) for the example implementation.
//! To use async version of rscni, please use it with `feature=async` flag.
//! The usage of async version, see [async-rscni-debug](github.com/terassyi/rscni/blob/main/examples/async-rscni-debug/main.rs).
//!
//! # Quick start
//!
//! ```rust,no_run,ignore
//! fn main() {
//!     let version_info = PluginInfo::default();
//!     let mut dispatcher = Plugin::new(add, del, check, version_info, ABOUT_MSG);
//!
//!     dispatcher.run().expect("Failed to complete the CNI call");
//! }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#[cfg(any(feature = "async", doc))]
pub mod async_skel;
pub mod error;
#[cfg(feature = "std")]
pub mod skel;
pub mod types;
mod util;
pub mod version;
