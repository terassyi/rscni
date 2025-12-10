//! Asynchronous CNI plugin interface.
//!
//! Enable the `async` feature to use this module:
//!
//! ```toml
//! [dependencies]
//! rscni = { version = "0.1.0-dev", features = ["async"] }
//! ```

use std::io::Write;

#[cfg(feature = "async")]
use async_trait::async_trait;

use crate::{
    error::Error,
    types::{Args, CNIResult, Cmd},
    util::{Env, Io, OsEnv, StdIo},
    version::PluginInfo,
};

/// The core trait for implementing an async CNI plugin.
///
/// Implement this trait to define the behavior of your CNI plugin for the
/// ADD, DEL, and CHECK operations as specified by the CNI specification.
///
/// # CNI Operations
///
/// - **ADD**: Called when a container is created. Set up the network interface.
/// - **DEL**: Called when a container is deleted. Clean up the network interface.
/// - **CHECK**: Called to verify that the network configuration is as expected.
///
/// # Example
///
/// ```rust,ignore
/// use async_trait::async_trait;
/// use rscni::{async_cni::Cni, error::Error, types::{Args, CNIResult}};
///
/// struct MyPlugin;
///
/// #[async_trait]
/// impl Cni for MyPlugin {
///     async fn add(&self, args: Args) -> Result<CNIResult, Error> {
///         // Network setup logic
///         Ok(CNIResult::default())
///     }
///
///     async fn del(&self, args: Args) -> Result<CNIResult, Error> {
///         // Network cleanup logic
///         Ok(CNIResult::default())
///     }
///
///     async fn check(&self, args: Args) -> Result<CNIResult, Error> {
///         // Network verification logic
///         Ok(CNIResult::default())
///     }
/// }
/// ```
#[cfg_attr(feature = "async", async_trait)]
pub trait Cni {
    /// Executes the ADD command for the CNI plugin.
    /// https://github.com/containernetworking/cni/blob/v1.1.0/SPEC.md#add-add-container-to-network-or-apply-modifications
    ///
    /// This method is called when a container is created and needs network connectivity.
    /// It should set up the network interface, assign IP addresses, configure routes, etc.
    ///
    /// # Arguments
    ///
    /// * `args` - Contains all CNI parameters including container ID, network namespace,
    ///   interface name, and network configuration from stdin.
    ///
    /// # Returns
    ///
    /// Returns a [`CNIResult`](../types/struct.CNIResult.html) containing the network configuration
    /// that was created (interfaces, IPs, routes, DNS).
    ///
    /// # Errors
    ///
    /// Returns an error if the ADD operation fails.
    async fn add(&self, args: Args) -> Result<CNIResult, Error>;

    /// Executes the DEL command for the CNI plugin.
    /// https://github.com/containernetworking/cni/blob/v1.1.0/SPEC.md#del-remove-container-from-network-or-un-apply-modifications
    ///
    /// This method is called when a container is being deleted and should clean up
    /// all network resources that were created during the ADD operation.
    ///
    /// # Arguments
    ///
    /// * `args` - Contains all CNI parameters needed to identify and clean up the network.
    ///
    /// # Returns
    ///
    /// Returns an empty [`CNIResult`](../types/struct.CNIResult.html) on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the DEL operation fails.
    async fn del(&self, args: Args) -> Result<CNIResult, Error>;

    /// Executes the CHECK command for the CNI plugin.
    /// https://github.com/containernetworking/cni/blob/v1.1.0/SPEC.md#check-check-containers-networking-is-as-expected
    ///
    /// This method verifies that the network configuration is still correct and matches
    /// what was configured during ADD.
    ///
    /// # Arguments
    ///
    /// * `args` - Contains all CNI parameters and the previous result to check against.
    ///
    /// # Returns
    ///
    /// Returns an empty [`CNIResult`](../types/struct.CNIResult.html) on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the CHECK operation fails.
    async fn check(&self, args: Args) -> Result<CNIResult, Error>;
}

/// Entry point for async CNI plugins.
#[derive(Debug, Default)]
pub struct Plugin {
    info: PluginInfo,
    msg: Option<String>,
}

impl Plugin {
    /// Creates a new `Plugin` with custom CNI version support.
    ///
    /// # Arguments
    ///
    /// * `ver` - The primary CNI version (e.g., "1.1.0")
    /// * `versions` - List of supported CNI versions
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rscni::async_cni::Plugin;
    ///
    /// let plugin = Plugin::new(
    ///     "1.1.0",
    ///     vec!["1.0.0".to_string(), "1.1.0".to_string()]
    /// );
    /// ```
    #[must_use]
    pub fn new(ver: &str, versions: Vec<String>) -> Self {
        Self {
            info: PluginInfo::new(ver, versions),
            msg: None,
        }
    }

    /// Sets a message to display with version information.
    ///
    /// # Arguments
    ///
    /// * `msg` - Plugin description or version string
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rscni::async_cni::Plugin;
    ///
    /// let plugin = Plugin::default()
    ///     .msg("AsyncPlugin v1.0.0 - Async I/O support");
    /// ```
    #[must_use]
    pub fn msg(mut self, msg: &str) -> Self {
        self.msg = Some(msg.to_string());
        self
    }

    /// Runs the CNI plugin asynchronously.
    ///
    /// This method processes the CNI command asynchronously and calls the
    /// appropriate method on your `Cni` implementation.
    ///
    /// # Arguments
    ///
    /// * `cni` - A reference to your async `Cni` trait implementation
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - CNI environment variables are missing or invalid
    /// - Network configuration is invalid
    /// - CNI version is incompatible
    /// - Your `Cni` implementation returns an error
    /// - I/O errors occur
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use async_trait::async_trait;
    /// use rscni::{async_cni::{Cni, Plugin}, error::Error, types::{Args, CNIResult}};
    ///
    /// struct MyPlugin;
    ///
    /// #[async_trait]
    /// impl Cni for MyPlugin {
    ///     async fn add(&self, args: Args) -> Result<CNIResult, Error> {
    ///         Ok(CNIResult::default())
    ///     }
    ///     async fn del(&self, args: Args) -> Result<CNIResult, Error> {
    ///         Ok(CNIResult::default())
    ///     }
    ///     async fn check(&self, args: Args) -> Result<CNIResult, Error> {
    ///         Ok(CNIResult::default())
    ///     }
    /// }
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let plugin = Plugin::default();
    ///     let my_plugin = MyPlugin;
    ///
    ///     if let Err(e) = plugin.run(&my_plugin).await {
    ///         eprintln!("Plugin failed: {}", e);
    ///         std::process::exit(1);
    ///     }
    /// }
    /// ```
    pub async fn run<T: Cni>(&self, cni: &T) -> Result<(), Error> {
        let res = self.inner_run::<T, OsEnv, StdIo>(cni).await?;

        StdIo::io_out()
            .write_all(res.as_bytes())
            .map_err(|e| Error::IOFailure(e.to_string()))
    }

    async fn inner_run<C: Cni, E: Env, I: Io>(&self, cni: &C) -> Result<String, Error> {
        let cmd = Cmd::get_from_env::<E>()?;

        match cmd {
            Cmd::Add => {
                let args = Args::build::<E, I>()?;
                let res = cni.add(args).await?;
                serde_json::to_string(&res).map_err(|e| Error::FailedToDecode(e.to_string()))
            }
            Cmd::Del => {
                let args = Args::build::<E, I>()?;
                let res = cni.del(args).await?;
                serde_json::to_string(&res).map_err(|e| Error::FailedToDecode(e.to_string()))
            }
            Cmd::Check => {
                let args = Args::build::<E, I>()?;
                let res = cni.check(args).await?;
                serde_json::to_string(&res).map_err(|e| Error::FailedToDecode(e.to_string()))
            }
            Cmd::Version => self.info.version(),
            Cmd::UnSet => Ok(self.info.about(self.msg.clone())),
        }
    }
}
