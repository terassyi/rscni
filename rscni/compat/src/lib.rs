//! **Deprecated. This crate has been renamed to [`rscni-plugin`](https://docs.rs/rscni-plugin).**
//!
//! `rscni` 0.3.0 exists only to ease that rename. It re-exports `rscni-plugin` under the
//! module paths 0.2.x used, so existing code keeps compiling, and it will not be updated
//! again.
//!
//! # Migrating
//!
//! ```toml
//! # before
//! rscni = "0.2"
//! # after
//! rscni-plugin = "0.3"
//! ```
//!
//! Then replace `rscni::` with `rscni_plugin::` — the module layout is unchanged, so
//! `rscni::cni::Plugin` becomes `rscni_plugin::cni::Plugin` and so on.
//!
//! # Why the rename
//!
//! The repository now publishes both sides of the CNI conversation, and `rscni` did not
//! say which side it was:
//!
//! - [`rscni-plugin`](https://docs.rs/rscni-plugin) — write a CNI plugin (this crate's
//!   contents)
//! - `rscni-runtime` (planned) — invoke CNI plugins
//! - [`rscni-types`](https://docs.rs/rscni-types) — the specification types both share
//!
//! # On the deprecation warnings
//!
//! Only [`cni::Plugin`] and `async_cni::Plugin` carry `#[deprecated]`, and they are
//! type aliases rather than re-exports because of a rustc limitation: `#[deprecated]` is
//! inert on a `pub use`, on the module a path travels through, and on the crate root, so
//! a shim built purely out of re-exports cannot warn at all. A deprecated *type alias*
//! does warn.
//!
//! `Plugin` is the one type every plugin has to name — you cannot run one without
//! constructing it — so aliasing it is enough for the warning to reach everybody. The
//! `Cni` trait would be the other candidate, but trait aliases are unstable and turning
//! it into anything other than a re-export would break the `impl Cni for …` blocks this
//! crate exists to keep compiling.

pub use rscni_plugin::{error, types, version};

#[cfg(feature = "std")]
pub mod cni {
    pub use rscni_plugin::cni::*;

    /// Entry point for CNI plugins.
    ///
    /// Shadows the glob re-export above so that naming it warns.
    #[deprecated(
        since = "0.3.0",
        note = "`rscni` has been renamed to `rscni-plugin`: use `rscni_plugin::cni::Plugin`"
    )]
    pub type Plugin = rscni_plugin::cni::Plugin;
}

// Gated on the feature alone, not `any(feature = "async", doc)`. There is no source here
// to document unconditionally — the glob target `rscni_plugin::async_cni` only exists
// when `rscni-plugin/async` is on, so adding a `doc` arm makes `cargo doc` fail to
// resolve the import. docs.rs sees this module via `all-features` instead.
#[cfg(feature = "async")]
pub mod async_cni {
    pub use rscni_plugin::async_cni::*;

    /// Entry point for async CNI plugins.
    ///
    /// Shadows the glob re-export above so that naming it warns.
    #[deprecated(
        since = "0.3.0",
        note = "`rscni` has been renamed to `rscni-plugin`: use `rscni_plugin::async_cni::Plugin`"
    )]
    pub type Plugin = rscni_plugin::async_cni::Plugin;
}
