//! Plugin-side plumbing: env/IO abstractions (the test seam for the mock env and mock
//! stdio in the `cni`/`async_cni` tests) and the ADD result's JSON rendering.

use std::{io, str::FromStr};

use rscni_types::{
    error::Error,
    legacy,
    types::{CNIResult, CNIResultWithVersion},
    version::SpecVersion,
};

/// Renders the JSON a plugin writes for a successful ADD: the result in the layout
/// the negotiated version requires, declared under that version.
///
/// A free function for want of a receiver: it belongs to neither the version nor the
/// result, and the layout choice is deliberately the plugin's. `version` must be
/// [`is_supported`](SpecVersion::is_supported), which dispatch checks before it lets
/// the ADD callback run.
///
/// # Errors
///
/// Returns [`Error::FailedToDecode`] if the result cannot be serialized.
pub fn result_json(version: SpecVersion, result: CNIResult) -> Result<String, Error> {
    if version.is_legacy() {
        serde_json::to_string(&legacy::CNIResult::new(version, result))
    } else {
        serde_json::to_string(&CNIResultWithVersion::new(version, result))
    }
    .map_err(|e| Error::FailedToDecode(e.to_string()))
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
