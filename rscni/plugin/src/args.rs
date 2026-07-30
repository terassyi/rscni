//! Plugin invocation input.
//!
//! [`Args`] is what a plugin receives on each call: every field except `config`
//! comes from an environment variable, and `config` is the
//! [`NetConf`] JSON read from stdin. [`ArgsBuilder`] assembles it by reading
//! each source in turn.
//!
//! These types live here rather than in `rscni-types` because they are specific
//! to being invoked as a plugin. A CNI runtime writes these parameters out
//! instead of reading them, so it has no use for them.

use std::{env, io::Read, path::PathBuf, str::FromStr};

use rscni_types::{
    error::Error,
    types::{
        CNI_ARGS, CNI_COMMAND, CNI_CONTAINERID, CNI_IFNAME, CNI_NETNS, CNI_PATH, Cmd, NetConf,
    },
};

use crate::util::{Env, Io};

/// Reads the `CNI_COMMAND` environment variable.
///
/// `Ok(None)` means the variable is set but empty — the plugin prints its about text in
/// that case, so emptiness is not an error here even though [`Cmd`]'s `FromStr` rejects
/// it. A missing variable is still an error, exactly as it always was.
///
/// This is a free function rather than an inherent method on [`Cmd`] because `Cmd`
/// lives in `rscni-types`, which knows nothing about [`Env`].
// `pub(crate)` is what this is: `args` is a private module and nothing re-exports this,
// unlike `Args`/`ArgsBuilder`. clippy's `redundant_pub_crate` would rather see `pub`
// because the two reach equally far today, but `pub` would silently widen the crate's
// API the day `mod args` becomes public, so the narrower marker is kept deliberately.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn cmd_from_env<E: Env>() -> Result<Option<Cmd>, Error> {
    let raw = E::get::<String>(CNI_COMMAND)?;
    if raw.is_empty() {
        return Ok(None);
    }
    Cmd::from_str(&raw).map(Some)
}

/// Args is input data for the CNI call.
///
/// All fields except for `config` are given as environment values.
/// `config` field is given as a JSON format data([`NetConf`]) from stdin.
/// Depending on the type of command, some fields are omitted.
/// Please see <https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#parameters> and <https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#cni-operations>.
#[derive(Debug, Default, Clone)]
pub struct Args {
    /// Container ID. A unique plaintext identifier for a container, allocated by the runtime.
    /// Must not be empty.
    /// Must start with an alphanumeric character, optionally followed by any combination of one or more alphanumeric characters, underscore (), dot (.) or hyphen (-).
    container_id: Option<String>,
    /// A reference to the container's "isolation domain".
    /// If using network namespaces, then a path to the network namespace (e.g. /run/netns/nsname).
    netns: Option<PathBuf>,
    /// Name of the interface to create inside the container; if the plugin is unable to use this interface name it must return an error.
    ifname: Option<String>,
    /// Extra arguments passed in by the user at invocation time. Alphanumeric key-value pairs separated by semicolons.
    #[allow(clippy::struct_field_names)]
    args: Option<String>,
    /// List of paths to search for CNI plugin executables. Paths are separated by an OS-specific list separator; for example ':' on Linux and ';' on Windows.
    path: Vec<PathBuf>,
    /// Please see [`NetConf`].
    config: Option<NetConf>,
}

impl Args {
    /// Returns the container ID if present.
    #[must_use]
    pub fn container_id(&self) -> Option<&str> {
        self.container_id.as_deref()
    }

    /// Returns the network namespace path if present.
    #[must_use]
    pub const fn netns(&self) -> Option<&PathBuf> {
        self.netns.as_ref()
    }

    /// Returns the interface name if present.
    #[must_use]
    pub fn ifname(&self) -> Option<&str> {
        self.ifname.as_deref()
    }

    /// Returns the extra arguments if present.
    #[must_use]
    pub fn args(&self) -> Option<&str> {
        self.args.as_deref()
    }

    /// Returns the list of CNI plugin paths.
    #[must_use]
    pub fn path(&self) -> &[PathBuf] {
        &self.path
    }

    /// Returns the network configuration if present.
    #[must_use]
    pub const fn config(&self) -> Option<&NetConf> {
        self.config.as_ref()
    }
}

/// Builder for constructing `Args` instances.
#[derive(Debug)]
pub struct ArgsBuilder<E: Env, I: Io> {
    container_id: Option<String>,
    netns: Option<PathBuf>,
    ifname: Option<String>,
    #[allow(clippy::struct_field_names)]
    args: Option<String>,
    path: Vec<PathBuf>,
    config: Option<NetConf>,
    _phantom_e: std::marker::PhantomData<E>,
    _phantom_i: std::marker::PhantomData<I>,
}

impl<E: Env, I: Io> ArgsBuilder<E, I> {
    /// Creates a new `ArgsBuilder`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            container_id: None,
            netns: None,
            ifname: None,
            args: None,
            path: Vec::new(),
            config: None,
            _phantom_e: std::marker::PhantomData,
            _phantom_i: std::marker::PhantomData,
        }
    }

    /// Reads container ID from the `CNI_CONTAINERID` environment variable.
    ///
    /// # Errors
    ///
    /// Returns an error if the environment variable is set but cannot be read properly.
    pub fn container_id(mut self) -> Result<Self, Error> {
        self.container_id = Some(E::get::<String>(CNI_CONTAINERID)?);
        Ok(self)
    }

    /// Reads network namespace from the `CNI_NETNS` environment variable.
    ///
    /// # Errors
    ///
    /// Returns an error if the environment variable is set but cannot be read properly.
    pub fn netns(mut self) -> Result<Self, Error> {
        // `PathBuf: FromStr` is infallible, so no decode failure to handle here.
        self.netns = Some(PathBuf::from(E::get::<String>(CNI_NETNS)?));
        Ok(self)
    }

    /// Reads interface name from the `CNI_IFNAME` environment variable.
    ///
    /// # Errors
    ///
    /// Returns an error if the environment variable is set but cannot be read properly.
    pub fn ifname(mut self) -> Result<Self, Error> {
        self.ifname = Some(E::get::<String>(CNI_IFNAME)?);
        Ok(self)
    }

    /// Reads extra arguments from the `CNI_ARGS` environment variable.
    ///
    /// # Errors
    ///
    /// Returns an error if the environment variable is set but cannot be read properly.
    pub fn args(mut self) -> Result<Self, Error> {
        let val = E::get::<String>(CNI_ARGS)?;
        self.args = if val.is_empty() { None } else { Some(val) };
        Ok(self)
    }

    /// Reads CNI plugin paths from the `CNI_PATH` environment variable.
    ///
    /// # Errors
    ///
    /// Returns an error if the environment variable is set but cannot be read properly.
    pub fn path(mut self) -> Result<Self, Error> {
        // The separator is OS-specific (':' on Unix, ';' on Windows), which is exactly
        // what `env::split_paths` implements; on Unix it matches a plain ':' split
        // byte for byte, empty segments included.
        self.path = env::split_paths(&E::get::<String>(CNI_PATH)?).collect();
        Ok(self)
    }

    /// Reads network configuration from stdin.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Failed to read from stdin
    /// - Failed to parse JSON configuration
    pub fn config(mut self) -> Result<Self, Error> {
        let mut buf = String::new();
        I::io_in()
            .read_to_string(&mut buf)
            .map_err(|e| Error::IOFailure(e.to_string()))?;

        self.config =
            serde_json::from_str(&buf).map_err(|e| Error::FailedToDecode(e.to_string()))?;
        Ok(self)
    }

    /// Validates required fields based on the CNI command.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing for the given command:
    /// - `ADD`/`DEL`/`CHECK` commands require `container_id` and `ifname`
    /// - `GC` command requires `path` (`CNI_PATH`)
    pub(crate) fn validate(self, cmd: Cmd) -> Result<Self, Error> {
        match cmd {
            Cmd::Add | Cmd::Del | Cmd::Check => {
                // These commands require container_id and ifname
                if self.container_id.is_none() {
                    return Err(Error::InvalidEnvValue(
                        "CNI_CONTAINERID is required for ADD/DEL/CHECK commands".to_string(),
                    ));
                }
                if self.ifname.is_none() {
                    return Err(Error::InvalidEnvValue(
                        "CNI_IFNAME is required for ADD/DEL/CHECK commands".to_string(),
                    ));
                }
            }
            // GC command requires CNI_PATH
            Cmd::Gc if self.path.is_empty() => {
                return Err(Error::InvalidEnvValue(
                    "CNI_PATH is required for GC command".to_string(),
                ));
            }
            // STATUS and VERSION don't require container-specific parameters. The
            // wildcard also covers any operation a future CNI specification adds
            // (`Cmd` is `#[non_exhaustive]`): a command this crate does not know cannot
            // have extra requirements enforced here.
            _ => {}
        }
        Ok(self)
    }

    /// Builds the `Args` instance.
    ///
    /// # Errors
    ///
    /// This function currently always returns `Ok`, but returns `Result` for API consistency.
    pub fn build(self) -> Result<Args, Error> {
        Ok(Args {
            container_id: self.container_id,
            netns: self.netns,
            ifname: self.ifname,
            args: self.args,
            path: self.path,
            config: self.config,
        })
    }
}

impl<E: Env, I: Io> Default for ArgsBuilder<E, I> {
    fn default() -> Self {
        Self::new()
    }
}
