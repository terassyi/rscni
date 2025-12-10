use std::io::Write;

use crate::{
    error::Error,
    types::{Args, CNIResult, Cmd},
    util::{Env, Io, OsEnv, StdIo},
    version::PluginInfo,
};

/// The core trait for implementing a CNI plugin.
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
/// ```rust
/// use rscni::{cni::Cni, error::Error, types::{Args, CNIResult}};
///
/// struct MyPlugin;
///
/// impl Cni for MyPlugin {
///     fn add(&self, args: Args) -> Result<CNIResult, Error> {
///         // Network setup logic
///         Ok(CNIResult::default())
///     }
///
///     fn del(&self, args: Args) -> Result<CNIResult, Error> {
///         // Network cleanup logic
///         Ok(CNIResult::default())
///     }
///
///     fn check(&self, args: Args) -> Result<CNIResult, Error> {
///         // Network verification logic
///         Ok(CNIResult::default())
///     }
/// }
/// ```
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
    fn add(&self, args: Args) -> Result<CNIResult, Error>;

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
    fn del(&self, args: Args) -> Result<CNIResult, Error>;

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
    fn check(&self, args: Args) -> Result<CNIResult, Error>;
}

/// The main entry point for a CNI plugin.
///
/// `Plugin` handles all the CNI protocol details including:
/// - Reading CNI environment variables
/// - Parsing network configuration from stdin
/// - Version negotiation
/// - Routing commands (ADD/DEL/CHECK/VERSION) to the appropriate handler
/// - Writing results to stdout
///
/// # Example
///
/// ```rust,no_run
/// use rscni::{cni::{Cni, Plugin}, error::Error, types::{Args, CNIResult}};
///
/// struct MyPlugin;
/// impl Cni for MyPlugin {
///     fn add(&self, args: Args) -> Result<CNIResult, Error> { Ok(CNIResult::default()) }
///     fn del(&self, args: Args) -> Result<CNIResult, Error> { Ok(CNIResult::default()) }
///     fn check(&self, args: Args) -> Result<CNIResult, Error> { Ok(CNIResult::default()) }
/// }
///
/// fn main() {
///     let plugin = Plugin::default().msg("MyPlugin v1.0.0");
///     let my_plugin = MyPlugin;
///     plugin.run(&my_plugin).expect("Failed to run plugin");
/// }
/// ```
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
    /// * `ver` - The primary CNI version this plugin uses (e.g., "1.1.0")
    /// * `versions` - List of all CNI versions this plugin supports
    ///
    /// # Example
    ///
    /// ```rust
    /// use rscni::cni::Plugin;
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

    /// Sets an optional message to display with version information.
    ///
    /// This message is shown when the plugin is called with the VERSION command.
    ///
    /// # Arguments
    ///
    /// * `msg` - A description or version string for your plugin
    ///
    /// # Example
    ///
    /// ```rust
    /// use rscni::cni::Plugin;
    ///
    /// let plugin = Plugin::default()
    ///     .msg("MyPlugin v1.0.0 - CNI plugin");
    /// ```
    #[must_use]
    pub fn msg(mut self, msg: &str) -> Self {
        self.msg = Some(msg.to_string());
        self
    }

    /// Runs the CNI plugin by processing the CNI command and executing the appropriate operation.
    ///
    /// This method:
    /// 1. Reads the CNI_COMMAND environment variable
    /// 2. Routes to ADD/DEL/CHECK/VERSION based on the command
    /// 3. Calls the appropriate method on your `Cni` implementation
    /// 4. Writes the result to stdout in JSON format
    ///
    /// # Arguments
    ///
    /// * `cni` - A reference to your `Cni` trait implementation
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or an error if any step fails.
    ///
    /// # Errors
    ///
    /// This method can return errors for various reasons:
    /// - Missing or invalid CNI environment variables
    /// - Invalid network configuration on stdin
    /// - CNI version mismatch
    /// - Errors from your `Cni` implementation
    /// - I/O errors writing to stdout
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use rscni::{cni::{Cni, Plugin}, error::Error, types::{Args, CNIResult}};
    ///
    /// struct MyPlugin;
    /// impl Cni for MyPlugin {
    ///     fn add(&self, args: Args) -> Result<CNIResult, Error> { Ok(CNIResult::default()) }
    ///     fn del(&self, args: Args) -> Result<CNIResult, Error> { Ok(CNIResult::default()) }
    ///     fn check(&self, args: Args) -> Result<CNIResult, Error> { Ok(CNIResult::default()) }
    /// }
    ///
    /// fn main() {
    ///     let plugin = Plugin::default();
    ///     let my_plugin = MyPlugin;
    ///
    ///     if let Err(e) = plugin.run(&my_plugin) {
    ///         eprintln!("CNI plugin failed: {}", e);
    ///         std::process::exit(1);
    ///     }
    /// }
    /// ```
    pub fn run<T: Cni>(&self, cni: &T) -> Result<(), Error> {
        let res = self.inner_run::<T, OsEnv, StdIo>(cni)?;

        StdIo::io_out()
            .write_all(res.as_bytes())
            .map_err(|e| Error::IOFailure(e.to_string()))
    }

    fn inner_run<C: Cni, E: Env, I: Io>(&self, cni: &C) -> Result<String, Error> {
        let cmd = Cmd::get_from_env::<E>()?;

        match cmd {
            Cmd::Add => {
                let args = Args::build::<E, I>()?;
                if let Some(conf) = &args.config {
                    self.info.validate(&conf.cni_version)?;
                }
                let res = cni.add(args)?;
                serde_json::to_string(&res).map_err(|e| Error::FailedToDecode(e.to_string()))
            }
            Cmd::Del => {
                let args = Args::build::<E, I>()?;
                if let Some(conf) = &args.config {
                    self.info.validate(&conf.cni_version)?;
                }
                let res = cni.del(args)?;
                serde_json::to_string(&res).map_err(|e| Error::FailedToDecode(e.to_string()))
            }
            Cmd::Check => {
                let args = Args::build::<E, I>()?;
                if let Some(conf) = &args.config {
                    self.info.validate(&conf.cni_version)?;
                }
                let res = cni.check(args)?;
                serde_json::to_string(&res).map_err(|e| Error::FailedToDecode(e.to_string()))
            }
            Cmd::Version => self.info.version(),
            Cmd::UnSet => Ok(self.info.about(self.msg.clone())),
        }
    }
}
