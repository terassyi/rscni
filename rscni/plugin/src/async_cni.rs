//! Asynchronous CNI plugin interface.
//!
//! Enable the `async` feature to use this module:
//!
//! ```toml
//! [dependencies]
//! rscni-plugin = { version = "0.3", features = ["async"] }
//! ```

use std::io::Write;

#[cfg(feature = "async")]
use async_trait::async_trait;

use rscni_types::{
    error::Error,
    types::{CNIResult, CNIResultWithCNIVersion, Cmd},
    version::PluginInfo,
};

use crate::{
    args::{Args, ArgsBuilder, cmd_from_env, required_config},
    util::{Env, Io, OsEnv, StdIo, about_text, version_json},
};

/// The core trait for implementing an async CNI plugin.
///
/// Implement this trait to define the behavior of your CNI plugin for the
/// ADD, DEL, CHECK, and STATUS operations as specified by the CNI specification.
///
/// # CNI Operations
///
/// - **ADD**: Called when a container is created. Set up the network interface.
/// - **DEL**: Called when a container is deleted. Clean up the network interface.
/// - **CHECK**: Called to verify that the network configuration is as expected.
/// - **STATUS**: Called to check if the plugin is ready to service ADD requests.
/// - **GC**: Called to clean up stale resources not in the valid attachments list.
///
/// # Example
///
/// ```rust,ignore
/// use async_trait::async_trait;
/// use rscni_plugin::{async_cni::Cni, error::Error, types::{Args, CNIResult}};
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
///
///     async fn status(&self, _args: Args) -> Result<(), Error> {
///         // Plugin readiness check
///         Ok(())
///     }
///
///     async fn gc(&self, _args: Args) -> Result<(), Error> {
///         // Garbage collection logic
///         Ok(())
///     }
/// }
/// ```
#[cfg_attr(feature = "async", async_trait)]
pub trait Cni {
    /// Executes the ADD command for the CNI plugin.
    /// <https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#add-add-container-to-network-or-apply-modifications>
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
    /// <https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#del-remove-container-from-network-or-un-apply-modifications>
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
    /// <https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#check-check-containers-networking-is-as-expected>
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

    /// Executes the STATUS command for the CNI plugin.
    /// <https://www.cni.dev/docs/spec/#status-check-plugin-status>
    ///
    /// This method checks if the plugin is ready to service ADD requests.
    /// A plugin must return success (exit with zero) if it is ready.
    /// If the plugin knows that it cannot service ADD requests, it must return an error.
    ///
    /// # Arguments
    ///
    /// * `args` - Contains CNI parameters. For STATUS, only `path` and `config` are typically used.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the plugin is ready to service ADD requests.
    ///
    /// # Errors
    ///
    /// Returns an error if the plugin is not available:
    /// - [`Error::PluginNotAvailable`](../error/enum.Error.html#variant.PluginNotAvailable) (code 50):
    ///   The plugin cannot service ADD requests.
    /// - [`Error::PluginNotAvailableLimitedConnectivity`](../error/enum.Error.html#variant.PluginNotAvailableLimitedConnectivity) (code 51):
    ///   The plugin cannot service ADD requests, and existing containers may have limited connectivity.
    async fn status(&self, args: Args) -> Result<(), Error>;

    /// Executes the GC (Garbage Collection) command for the CNI plugin.
    /// <https://www.cni.dev/docs/spec/#gc-clean-up-any-stale-resources>
    ///
    /// The GC command provides a way for runtimes to specify the expected set of
    /// attachments to a network. The plugin should remove any resources related to
    /// attachments that do not exist in the provided set.
    ///
    /// Resources that may be cleaned up include:
    /// - IPAM reservations
    /// - Firewall rules
    ///
    /// # Arguments
    ///
    /// * `args` - Contains CNI parameters. For GC, only `path` and `config` are required.
    ///   The `config.valid_attachments` field contains the list of still-valid attachments.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the GC operation fails. Plugins should generally complete
    /// a GC action without error. If an error is encountered, the plugin should continue
    /// removing as many resources as possible and report errors back to the runtime.
    async fn gc(&self, args: Args) -> Result<(), Error>;
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
    /// use rscni_plugin::async_cni::Plugin;
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
    /// use rscni_plugin::async_cni::Plugin;
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
    /// use rscni_plugin::{async_cni::{Cni, Plugin}, error::Error, types::{Args, CNIResult}};
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
    #[allow(clippy::future_not_send)]
    pub async fn run<T: Cni>(&self, cni: &T) -> Result<(), Error> {
        let res = self.inner_run::<T, OsEnv, StdIo>(cni).await?;

        StdIo::io_out()
            .write_all(res.as_bytes())
            .map_err(|e| Error::IOFailure(e.to_string()))
    }

    #[allow(clippy::future_not_send)]
    async fn inner_run<C: Cni, E: Env, I: Io>(&self, cni: &C) -> Result<String, Error> {
        // CNI_COMMAND is required for every operation, so unset (or empty, which the
        // spec's reference implementation treats identically) is error code 4 on the
        // wire. The about text still goes to stderr: a human poking at the binary gets
        // help, and stderr is the diagnostics channel, so runtimes are unaffected.
        let Some(cmd) = cmd_from_env::<E>()? else {
            let _ = I::io_err().write_all(about_text(&self.info, self.msg.clone()).as_bytes());
            return Err(Error::InvalidEnvValue("CNI_COMMAND is not set".to_string()));
        };

        match cmd {
            Cmd::Add => {
                let args = ArgsBuilder::<E, I>::new()
                    .container_id()?
                    .netns()?
                    .ifname()?
                    .args()?
                    .path()?
                    .config()?
                    .validate(cmd)?
                    .build()?;
                let conf = required_config(&args)?;
                self.info.validate(&conf.cni_version)?;
                // The spec requires the ADD result to carry a `cniVersion` key echoing
                // the version supplied on input.
                let cni_version = conf.cni_version.clone();
                let res = cni.add(args).await?;
                let res = CNIResultWithCNIVersion::new(cni_version, res);
                serde_json::to_string(&res).map_err(|e| Error::FailedToDecode(e.to_string()))
            }
            Cmd::Del => {
                let args = ArgsBuilder::<E, I>::new()
                    .container_id()?
                    .netns()?
                    .ifname()?
                    .args()?
                    .path()?
                    .config()?
                    .validate(cmd)?
                    .build()?;
                self.info.validate(&required_config(&args)?.cni_version)?;
                let res = cni.del(args).await?;
                serde_json::to_string(&res).map_err(|e| Error::FailedToDecode(e.to_string()))
            }
            Cmd::Check => {
                let args = ArgsBuilder::<E, I>::new()
                    .container_id()?
                    .netns()?
                    .ifname()?
                    .args()?
                    .path()?
                    .config()?
                    .validate(cmd)?
                    .build()?;
                self.info.validate(&required_config(&args)?.cni_version)?;
                let res = cni.check(args).await?;
                serde_json::to_string(&res).map_err(|e| Error::FailedToDecode(e.to_string()))
            }
            Cmd::Status => {
                // STATUS command only requires CNI_PATH (optional) and config from stdin
                let args = ArgsBuilder::<E, I>::new()
                    .path()?
                    .config()?
                    .validate(cmd)?
                    .build()?;
                self.info.validate(&required_config(&args)?.cni_version)?;
                cni.status(args).await?;
                // STATUS returns no output on success
                Ok(String::new())
            }
            Cmd::Gc => {
                // GC command requires CNI_COMMAND and CNI_PATH, plus config from stdin
                let args = ArgsBuilder::<E, I>::new()
                    .path()?
                    .config()?
                    .validate(cmd)?
                    .build()?;
                self.info.validate(&required_config(&args)?.cni_version)?;
                cni.gc(args).await?;
                // GC returns no output on success
                Ok(String::new())
            }
            Cmd::Version => version_json(&self.info),
            // `Cmd` is `#[non_exhaustive]`: an operation added by a future CNI
            // specification is not one this version of the library can dispatch.
            cmd => Err(Error::InvalidEnvValue(format!(
                "unsupported CNI_COMMAND: {}",
                <&str>::from(cmd)
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Dns, Interface, IpConfig, NetConf, Route};
    use rstest::rstest;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::io::{Cursor, Read, Write};
    use std::str::FromStr;

    // Thread-local storage for mock environment variables
    thread_local! {
        static MOCK_ENV: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
    }

    // Mock Env implementation
    struct MockEnv;

    impl Env for MockEnv {
        fn get<T>(name: &str) -> Result<Option<T>, Error>
        where
            T: FromStr,
            T::Err: std::error::Error + 'static,
        {
            MOCK_ENV.with(|env| match env.borrow().get(name) {
                None => Ok(None),
                Some(v) if v.is_empty() => Ok(None),
                Some(v) => v
                    .parse::<T>()
                    .map(Some)
                    .map_err(|e| Error::InvalidEnvValue(e.to_string())),
            })
        }
    }

    // Thread-local storage for mock I/O
    thread_local! {
        static MOCK_INPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    }

    struct MockIo;

    impl Io for MockIo {
        fn io_in() -> impl Read {
            MOCK_INPUT.with(|input| {
                let data = input.borrow().clone();
                Cursor::new(data)
            })
        }

        fn io_out() -> impl Write {
            Vec::new()
        }

        fn io_err() -> impl Write {
            Vec::new()
        }
    }

    // Helper function to set mock environment variable
    fn set_mock_env(key: &str, value: &str) {
        MOCK_ENV.with(|env| {
            env.borrow_mut().insert(key.to_string(), value.to_string());
        });
    }

    // Helper function to set mock input
    fn set_mock_input(data: &str) {
        MOCK_INPUT.with(|input| {
            *input.borrow_mut() = data.as_bytes().to_vec();
        });
    }

    // Helper function to clear mock environment
    fn clear_mock_env() {
        MOCK_ENV.with(|env| {
            env.borrow_mut().clear();
        });
    }

    // Helper function to clear mock input
    fn clear_mock_input() {
        MOCK_INPUT.with(|input| {
            input.borrow_mut().clear();
        });
    }

    // Mock Cni implementation
    struct MockCni;

    #[cfg_attr(feature = "async", async_trait)]
    impl Cni for MockCni {
        async fn add(&self, _args: Args) -> Result<CNIResult, Error> {
            Ok(CNIResult {
                interfaces: vec![Interface {
                    name: "eth0".to_string(),
                    mac: "00:11:22:33:44:55".to_string(),
                    sandbox: Some("/var/run/netns/test".to_string()),
                    mtu: None,
                    socket_path: None,
                    pci_id: None,
                }],
                ips: vec![IpConfig {
                    interface: Some(0),
                    address: "10.1.0.5/16".to_string(),
                    gateway: Some("10.1.0.1".to_string()),
                }],
                routes: vec![Route {
                    dst: "0.0.0.0/0".to_string(),
                    gw: Some("10.1.0.1".to_string()),
                    mtu: None,
                    advmss: None,
                    priority: None,
                    table: None,
                    scope: None,
                }],
                dns: Some(Dns {
                    nameservers: vec!["10.1.0.1".to_string()],
                    domain: None,
                    search: None,
                    options: None,
                }),
            })
        }

        async fn del(&self, _args: Args) -> Result<CNIResult, Error> {
            Ok(CNIResult::default())
        }

        async fn check(&self, _args: Args) -> Result<CNIResult, Error> {
            Ok(CNIResult::default())
        }

        async fn status(&self, _args: Args) -> Result<(), Error> {
            Ok(())
        }

        async fn gc(&self, _args: Args) -> Result<(), Error> {
            Ok(())
        }
    }

    #[cfg(feature = "async")]
    #[rstest]
    #[case("ADD")]
    #[case("DEL")]
    #[case("CHECK")]
    #[tokio::test]
    async fn test_plugin_inner_run_commands(
        #[case] command: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        clear_mock_env();
        clear_mock_input();

        set_mock_env("CNI_COMMAND", command);
        set_mock_env("CNI_CONTAINERID", "test-container");
        set_mock_env("CNI_NETNS", "/var/run/netns/test");
        set_mock_env("CNI_IFNAME", "eth0");
        set_mock_env("CNI_PATH", "/opt/cni/bin");
        set_mock_env("CNI_ARGS", "");

        let config = NetConf {
            cni_version: "1.0.0".to_string(),
            name: "test-network".to_string(),
            r#type: "test".to_string(),
            ..Default::default()
        };
        set_mock_input(&serde_json::to_string(&config)?);

        let plugin = Plugin::default();
        let mock_cni = MockCni;

        let json_output = plugin
            .inner_run::<MockCni, MockEnv, MockIo>(&mock_cni)
            .await
            .map_err(|e| format!("Command {command} should succeed: {e}"))?;
        assert!(!json_output.is_empty());
        Ok(())
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_plugin_inner_run_add_echoes_cni_version() -> Result<(), Box<dyn std::error::Error>>
    {
        clear_mock_env();
        clear_mock_input();
        set_mock_env("CNI_COMMAND", "ADD");
        set_mock_env("CNI_CONTAINERID", "test-container");
        set_mock_env("CNI_NETNS", "/var/run/netns/test");
        set_mock_env("CNI_IFNAME", "eth0");
        let config = NetConf {
            cni_version: "1.0.0".to_string(),
            name: "test-network".to_string(),
            r#type: "test".to_string(),
            ..Default::default()
        };
        set_mock_input(&serde_json::to_string(&config)?);

        let plugin = Plugin::default();
        let output = plugin
            .inner_run::<MockCni, MockEnv, MockIo>(&MockCni)
            .await?;

        // The spec: the ADD result must carry the cniVersion supplied on input.
        let parsed: serde_json::Value = serde_json::from_str(&output)?;
        assert_eq!(parsed["cniVersion"], "1.0.0");
        Ok(())
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_plugin_inner_run_version() -> Result<(), Box<dyn std::error::Error>> {
        clear_mock_env();
        set_mock_env("CNI_COMMAND", "VERSION");

        let plugin = Plugin::default();
        let mock_cni = MockCni;

        let json_output = plugin
            .inner_run::<MockCni, MockEnv, MockIo>(&mock_cni)
            .await?;
        assert!(json_output.contains("cniVersion"));
        assert!(json_output.contains("supportedVersions"));
        Ok(())
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_plugin_inner_run_unset() {
        // Unset and empty are the same thing per the spec's reference implementation,
        // and CNI_COMMAND is required for every operation: both are error code 4.
        for empty in [false, true] {
            clear_mock_env();
            if empty {
                set_mock_env("CNI_COMMAND", "");
            }
            let plugin = Plugin::default().msg("Test Plugin v1.0.0");
            let result = plugin.inner_run::<MockCni, MockEnv, MockIo>(&MockCni).await;
            assert!(matches!(result, Err(Error::InvalidEnvValue(_))));
        }
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_plugin_inner_run_del_without_netns() -> Result<(), Box<dyn std::error::Error>> {
        // The spec makes CNI_NETNS optional for DEL: teardown must complete even after
        // the namespace is gone.
        clear_mock_env();
        clear_mock_input();
        set_mock_env("CNI_COMMAND", "DEL");
        set_mock_env("CNI_CONTAINERID", "test-container");
        set_mock_env("CNI_IFNAME", "eth0");
        let config = NetConf {
            cni_version: "1.0.0".to_string(),
            name: "test-network".to_string(),
            r#type: "test".to_string(),
            ..Default::default()
        };
        set_mock_input(&serde_json::to_string(&config)?);

        let plugin = Plugin::default();
        plugin
            .inner_run::<MockCni, MockEnv, MockIo>(&MockCni)
            .await?;
        Ok(())
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_plugin_inner_run_add_without_optional_env()
    -> Result<(), Box<dyn std::error::Error>> {
        // CNI_ARGS and CNI_PATH are optional for ADD; CNI_NETNS is not.
        clear_mock_env();
        clear_mock_input();
        set_mock_env("CNI_COMMAND", "ADD");
        set_mock_env("CNI_CONTAINERID", "test-container");
        set_mock_env("CNI_NETNS", "/var/run/netns/test");
        set_mock_env("CNI_IFNAME", "eth0");
        let config = NetConf {
            cni_version: "1.0.0".to_string(),
            name: "test-network".to_string(),
            r#type: "test".to_string(),
            ..Default::default()
        };
        set_mock_input(&serde_json::to_string(&config)?);

        let plugin = Plugin::default();
        plugin
            .inner_run::<MockCni, MockEnv, MockIo>(&MockCni)
            .await?;

        clear_mock_input();
        set_mock_env("CNI_NETNS", "");
        set_mock_input(&serde_json::to_string(&config)?);
        let result = plugin.inner_run::<MockCni, MockEnv, MockIo>(&MockCni).await;
        assert!(matches!(result, Err(Error::InvalidEnvValue(_))));
        Ok(())
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_plugin_inner_run_null_stdin_rejected() {
        // A stdin of literal JSON `null` deserializes to no configuration without a
        // decode error; it must be rejected, not treated as "nothing to validate".
        clear_mock_env();
        clear_mock_input();
        set_mock_env("CNI_COMMAND", "ADD");
        set_mock_env("CNI_CONTAINERID", "test-container");
        set_mock_env("CNI_NETNS", "/var/run/netns/test");
        set_mock_env("CNI_IFNAME", "eth0");
        set_mock_env("CNI_PATH", "/opt/cni/bin");
        set_mock_env("CNI_ARGS", "");
        set_mock_input("null");

        let plugin = Plugin::default();
        let result = plugin.inner_run::<MockCni, MockEnv, MockIo>(&MockCni).await;
        assert!(matches!(result, Err(Error::InvalidNetworkConfig(_))));
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_plugin_inner_run_version_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        clear_mock_env();
        clear_mock_input();

        set_mock_env("CNI_COMMAND", "ADD");
        set_mock_env("CNI_CONTAINERID", "test-container");
        set_mock_env("CNI_NETNS", "/var/run/netns/test");
        set_mock_env("CNI_IFNAME", "eth0");
        set_mock_env("CNI_PATH", "/opt/cni/bin");
        set_mock_env("CNI_ARGS", "");

        // Plugin supports 1.0.0, but config specifies 0.4.0
        let config = NetConf {
            cni_version: "0.4.0".to_string(),
            name: "test-network".to_string(),
            r#type: "test".to_string(),
            ..Default::default()
        };
        set_mock_input(&serde_json::to_string(&config)?);

        let plugin = Plugin::new("1.0.0", vec!["1.0.0".to_string()]);
        let mock_cni = MockCni;

        let result = plugin
            .inner_run::<MockCni, MockEnv, MockIo>(&mock_cni)
            .await;
        assert!(result.is_err());
        if let Err(Error::IncompatibleVersion(_)) = result {
            // Expected error
        } else {
            panic!("Expected IncompatibleVersion error");
        }
        Ok(())
    }
}
