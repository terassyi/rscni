//! `RsCNI` is a CNI plugin library for Rust.
//! `RsCNI` helps you to implement CNI plugins easily by abstracting common operations.
//! `RsCNI` offers trait based design for both sync and async CNI plugins.
//!
//! The entry point is the `Plugin` struct in the `cni` or `async_cni` module.
//! Your CNI plugin struct should implement the `Cni` trait defined in the respective module.
//!
//! Please see [rscni-debug](github.com/terassyi/rscni/blob/main/examples/README.md) for the example implementation.
//! To use async version of rscni, please use it with `feature=async` flag.
//! The usage of async version, see [async-rscni-debug](github.com/terassyi/rscni/blob/main/examples/async-rscni-debug/main.rs).
//!
//! # Quick start
//!
//! ```rust,no_run
//! # use rscni::{
//! #     cni::{Cni, Plugin},
//! #     error::Error,
//! #     types::{Args, CNIResult},
//! # };
//! #
//! # struct MyPlugin;
//! #
//! # impl Cni for MyPlugin {
//! #     fn add(&self, args: Args) -> Result<CNIResult, Error> {
//! #         // Implement network setup logic
//! #         Ok(CNIResult::default())
//! #     }
//! #
//! #     fn del(&self, args: Args) -> Result<CNIResult, Error> {
//! #         // Implement network teardown logic
//! #         Ok(CNIResult::default())
//! #     }
//! #
//! #     fn check(&self, args: Args) -> Result<CNIResult, Error> {
//! #         // Implement network check logic
//! #         Ok(CNIResult::default())
//! #     }
//! # }
//! #
//! let my_plugin = MyPlugin;
//! let plugin = Plugin::default();
//! plugin.run(&my_plugin).expect("Failed to run CNI plugin");
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#[cfg(any(feature = "async", doc))]
pub mod async_cni;
#[cfg(feature = "std")]
pub mod cni;
pub mod error;
pub mod types;
mod util;
pub(crate) mod version;
