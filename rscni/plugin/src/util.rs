//! Plugin-side plumbing: env/IO abstractions (the test seam for the mock env and mock
//! stdio in the `cni`/`async_cni` tests) and output formatting.
//!
//! Everything here is `pub` *in a private module*, which is not reachable from outside
//! the crate (`use rscni_plugin::util::…` is E0603). The plain `pub` is load-bearing
//! for `Env`/`Io`: they appear as bounds on the externally nameable `ArgsBuilder`, and
//! rustc's `private_bounds` lint requires a bound to be formally at least as visible as
//! the item it constrains. Narrowing them to `pub(crate)` turns that warning on, and
//! `-D warnings` turns it into a CI failure.

use std::{io, str::FromStr};

use rscni_types::{error::Error, version::PluginInfo};

/// Renders the JSON a plugin writes in response to `CNI_COMMAND=VERSION`.
///
/// Lives here rather than on [`PluginInfo`] because it is plugin-side output
/// formatting: a runtime deserializes this JSON, it never produces it, so the shared
/// types crate has no business promising the exact string.
pub fn version_json(info: &PluginInfo) -> Result<String, Error> {
    serde_json::to_string(info).map_err(|e| Error::FailedToDecode(e.to_string()))
}

/// Renders the human-readable text a plugin prints when `CNI_COMMAND` is unset.
///
/// Plugin-side formatting, kept out of `rscni-types` for the same reason as
/// [`version_json`].
pub fn about_text(info: &PluginInfo, msg: Option<String>) -> String {
    let versions = info.supported_versions().join(", ");
    msg.map_or_else(
        || format!("CNI protocol versions supported: {versions}"),
        |msg| format!("{msg}\nCNI protocol versions supported: {versions}"),
    )
}

pub trait Env {
    /// Reads an environment variable.
    ///
    /// Returns `Ok(None)` when the variable is unset **or set to the empty string** —
    /// the specification's reference implementation treats the two identically, and
    /// which variables may be absent depends on the operation, so presence is the
    /// caller's decision, not this trait's. `Err` is reserved for values that exist
    /// but cannot be used (non-unicode, parse failure).
    fn get<T>(name: &str) -> Result<Option<T>, Error>
    where
        T: FromStr,
        T::Err: std::error::Error + 'static;
}

pub struct OsEnv;

impl Env for OsEnv {
    fn get<T>(name: &str) -> Result<Option<T>, Error>
    where
        T: FromStr,
        T::Err: std::error::Error + 'static,
    {
        match std::env::var(name) {
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(e) => Err(Error::InvalidEnvValue(e.to_string())),
            Ok(v) if v.is_empty() => Ok(None),
            Ok(v) => v
                .parse()
                .map(Some)
                .map_err(|e: T::Err| Error::InvalidEnvValue(e.to_string())),
        }
    }
}

pub trait Io {
    fn io_in() -> impl io::Read;
    fn io_out() -> impl io::Write;
    #[allow(dead_code)]
    fn io_err() -> impl io::Write;
}

pub struct StdIo;

impl Io for StdIo {
    fn io_in() -> impl io::Read {
        io::stdin()
    }

    fn io_out() -> impl io::Write {
        io::stdout()
    }

    fn io_err() -> impl io::Write {
        io::stderr()
    }
}
