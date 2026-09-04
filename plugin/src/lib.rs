//! A library for writing CNI plugins in Rust.
//!
//! This crate is the *plugin* side of CNI: the process a container runtime invokes.
//! For the calling side, see `rscni-runtime` (planned).
//!
//! Write a type that implements the `Cni` trait, then pass it to `Plugin::run`.
//! `Plugin::run` reads the `CNI_*` environment variables and stdin, calls the method for
//! the requested operation, and writes the result. Both `Cni` and `Plugin` are in the
//! [`cni`] module. The [`async_cni`] module has async versions of both, behind the
//! `async` feature.
//!
//! The specification types both sides exchange live in
//! [`rscni-types`](https://docs.rs/rscni-types) and are re-exported here, so
//! `rscni_plugin::types::NetConf` and `rscni_types::types::NetConf` are the same type.
//!
//! Complete examples:
//! [rscni-debug](https://github.com/terassyi/rscni/blob/main/examples/rscni_debug.rs) and
//! [async-rscni-debug](https://github.com/terassyi/rscni/blob/main/examples/async_rscni_debug.rs).
//!
//! # Quick start
//!
//! ```rust,no_run
//! # use rscni_plugin::{
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
//! #     fn del(&self, args: Args) -> Result<(), Error> {
//! #         // Implement network teardown logic
//! #         Ok(())
//! #     }
//! #
//! #     fn check(&self, args: Args) -> Result<(), Error> {
//! #         // Implement network check logic
//! #         Ok(())
//! #     }
//! #
//! #     fn status(&self, _args: Args) -> Result<(), Error> {
//! #         // Implement plugin readiness check
//! #         Ok(())
//! #     }
//! #
//! #     fn gc(&self, _args: Args) -> Result<(), Error> {
//! #         // Implement garbage collection logic
//! #         Ok(())
//! #     }
//! # }
//! #
//! let my_plugin = MyPlugin;
//! let plugin = Plugin::default();
//! plugin.run(&my_plugin).expect("Failed to run CNI plugin");
//! ```

/// The error type returned by every CNI operation.
///
/// Re-exported from [`rscni_types::error`].
pub mod error {
    #[doc(inline)]
    pub use rscni_types::error::*;
}

/// CNI specification types, plus the plugin-side invocation input.
///
/// The specification types are re-exported from [`rscni_types::types`];
/// [`Args`](crate::types::Args) is defined by this crate.
pub mod types {
    #[doc(inline)]
    pub use rscni_types::types::*;

    pub use crate::args::Args;
}

/// Plugin version reporting and negotiation.
///
/// Re-exported from [`rscni_types::version`].
pub mod version {
    #[doc(inline)]
    pub use rscni_types::version::*;
}

#[cfg(any(feature = "async", doc))]
pub mod async_cni;
#[cfg(feature = "std")]
pub mod cni;

mod args;
mod util;

/// Test helpers for building [`Args`](crate::types::Args) without the `CNI_*` environment.
///
/// Behind the `test-util` feature; for the test code of crates that implement
/// [`Cni`](crate::cni::Cni).
#[cfg(feature = "test-util")]
pub mod test_util;
