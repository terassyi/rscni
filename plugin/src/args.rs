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

use std::{env, io::Read, path::PathBuf};

use rscni_types::{
    error::Error,
    types::{
        CNI_ARGS, CNI_CONTAINERID, CNI_IFNAME, CNI_NETNS, CNI_PATH, Cmd, ContainerId,
        InterfaceName, NetConf,
    },
};

use crate::util::{Env, Io};

/// Args is input data for the CNI call.
///
/// All fields except for `config` are given as environment values.
/// `config` field is given as a JSON format data([`NetConf`]) from stdin.
/// Depending on the type of command, some fields are omitted.
/// Please see <https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#parameters> and <https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#cni-operations>.
#[derive(Debug, Default, Clone)]
pub struct Args {
    /// Container ID. A unique plaintext identifier for a container, allocated by the runtime.
    container_id: Option<ContainerId>,
    /// A reference to the container's "isolation domain".
    /// If using network namespaces, then a path to the network namespace (e.g. /run/netns/nsname).
    netns: Option<PathBuf>,
    /// Name of the interface to create inside the container; if the plugin is unable to use this interface name it must return an error.
    ifname: Option<InterfaceName>,
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
    pub const fn container_id(&self) -> Option<&ContainerId> {
        self.container_id.as_ref()
    }

    /// Returns the network namespace path if present.
    #[must_use]
    pub const fn netns(&self) -> Option<&PathBuf> {
        self.netns.as_ref()
    }

    /// Returns the interface name if present.
    #[must_use]
    pub const fn ifname(&self) -> Option<&InterfaceName> {
        self.ifname.as_ref()
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

/// Every dispatchable operation requires the network configuration on stdin, so
/// dispatch converts `Args` into the [`NetConf`] it must contain, failing with
/// [`Error::InvalidNetworkConfig`] (error code 7) when it is absent, or carries no
/// usable network name.
///
/// The absence must be a hard error rather than a skipped check: a stdin of literal
/// JSON `null` deserializes into *no configuration* without a decode error, and
/// treating that as "nothing to validate" would bypass version negotiation entirely
/// and hand the [`Cni`](crate::cni::Cni) implementation an `Args` the specification
/// says cannot exist.
impl<'a> TryFrom<&'a Args> for &'a NetConf {
    type Error = Error;

    fn try_from(args: &'a Args) -> Result<Self, Self::Error> {
        let conf = args.config().ok_or_else(|| {
            Error::InvalidNetworkConfig("network configuration is required on stdin".to_string())
        })?;
        conf.validate_name()?;
        Ok(conf)
    }
}

/// Builder for constructing `Args` instances.
#[derive(Debug)]
pub struct ArgsBuilder<E: Env, I: Io> {
    container_id: Option<ContainerId>,
    netns: Option<PathBuf>,
    ifname: Option<InterfaceName>,
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
    /// An unset or empty variable leaves the field `None`; whether that is acceptable
    /// depends on the command and is decided by [`Self::validate`].
    ///
    /// # Errors
    ///
    /// Returns an error if the environment variable cannot be read, or holds a value
    /// [`ContainerId`] rejects.
    // Converted here rather than by `E::get::<ContainerId>`: that renders the failure
    // through `Error`'s `Display`, which is the wire msg, losing the details.
    pub fn container_id(mut self) -> Result<Self, Error> {
        self.container_id = E::get::<String>(CNI_CONTAINERID)?
            .map(ContainerId::try_from)
            .transpose()?;
        Ok(self)
    }

    /// Reads network namespace from the `CNI_NETNS` environment variable.
    ///
    /// # Errors
    ///
    /// Returns an error if the environment variable is set but cannot be read properly.
    pub fn netns(mut self) -> Result<Self, Error> {
        // `PathBuf: FromStr` is infallible, so no decode failure to handle here.
        self.netns = E::get::<String>(CNI_NETNS)?.map(PathBuf::from);
        Ok(self)
    }

    /// Reads interface name from the `CNI_IFNAME` environment variable.
    ///
    /// # Errors
    ///
    /// Returns an error if the environment variable cannot be read, or holds a value
    /// [`InterfaceName`] rejects.
    pub fn ifname(mut self) -> Result<Self, Error> {
        self.ifname = E::get::<String>(CNI_IFNAME)?
            .map(InterfaceName::try_from)
            .transpose()?;
        Ok(self)
    }

    /// Reads extra arguments from the `CNI_ARGS` environment variable.
    ///
    /// # Errors
    ///
    /// Returns an error if the environment variable is set but cannot be read properly.
    pub fn args(mut self) -> Result<Self, Error> {
        self.args = E::get::<String>(CNI_ARGS)?;
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
        self.path = E::get::<String>(CNI_PATH)?
            .map(|v| env::split_paths(&v).collect())
            .unwrap_or_default();
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

    /// Validates the environment-sourced fields based on the CNI command, following
    /// the spec's required/optional environment parameter matrix:
    ///
    /// | command | required |
    /// |---|---|
    /// | ADD, CHECK | `CNI_CONTAINERID`, `CNI_NETNS`, `CNI_IFNAME` |
    /// | DEL | `CNI_CONTAINERID`, `CNI_IFNAME` — `CNI_NETNS` is optional, because the
    ///   spec requires DEL to complete even after the namespace is gone |
    /// | GC | `CNI_PATH` |
    /// | STATUS, VERSION | nothing |
    ///
    /// `CNI_ARGS` is optional everywhere, and `CNI_PATH` everywhere but GC — the
    /// reference implementation requires it more widely, but the spec's tables win.
    ///
    /// # Errors
    ///
    /// Returns an error naming every variable the command requires and lacks.
    pub(crate) fn validate(self, cmd: Cmd) -> Result<Self, Error> {
        let mut missing = Vec::new();
        match cmd {
            Cmd::Add | Cmd::Check | Cmd::Del => {
                if self.container_id.is_none() {
                    missing.push(CNI_CONTAINERID);
                }
                if self.netns.is_none() && !matches!(cmd, Cmd::Del) {
                    missing.push(CNI_NETNS);
                }
                if self.ifname.is_none() {
                    missing.push(CNI_IFNAME);
                }
            }
            // GC command requires CNI_PATH
            Cmd::Gc if self.path.is_empty() => missing.push(CNI_PATH),
            // STATUS and VERSION require no container-specific parameters.
            _ => {}
        }
        if missing.is_empty() {
            Ok(self)
        } else {
            Err(Error::missing_env(&missing))
        }
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
