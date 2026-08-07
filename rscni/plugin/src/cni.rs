use std::io::Write;

use rscni_types::{
    error::Error,
    types::{CNIResult, CNIResultWithCNIVersion, Cmd, ErrorResult},
    version::PluginInfo,
};

use crate::{
    args::{Args, ArgsBuilder, cmd_from_env},
    util::{Env, Io, OsEnv, StdIo, about_text, version_json},
};

/// The core trait for implementing a CNI plugin.
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
/// ```rust
/// use rscni_plugin::{cni::Cni, error::Error, types::{Args, CNIResult}};
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
///
///     fn status(&self, _args: Args) -> Result<(), Error> {
///         // Plugin readiness check
///         Ok(())
///     }
///
///     fn gc(&self, _args: Args) -> Result<(), Error> {
///         // Garbage collection logic
///         Ok(())
///     }
/// }
/// ```
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
    fn add(&self, args: Args) -> Result<CNIResult, Error>;

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
    /// Returns a [`CNIResult`](../types/struct.CNIResult.html) for API compatibility;
    /// the spec defines no success output for this operation, so the value is not
    /// written to stdout.
    ///
    /// # Errors
    ///
    /// Returns an error if the DEL operation fails.
    fn del(&self, args: Args) -> Result<CNIResult, Error>;

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
    /// Returns a [`CNIResult`](../types/struct.CNIResult.html) for API compatibility;
    /// the spec defines no success output for this operation, so the value is not
    /// written to stdout.
    ///
    /// # Errors
    ///
    /// Returns an error if the CHECK operation fails.
    fn check(&self, args: Args) -> Result<CNIResult, Error>;

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
    fn status(&self, args: Args) -> Result<(), Error>;

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
    fn gc(&self, args: Args) -> Result<(), Error>;
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
/// # use rscni_plugin::{cni::{Cni, Plugin}, error::Error, types::{Args, CNIResult}};
/// #
/// # struct MyPlugin;
/// # impl Cni for MyPlugin {
/// #     fn add(&self, args: Args) -> Result<CNIResult, Error> { Ok(CNIResult::default()) }
/// #     fn del(&self, args: Args) -> Result<CNIResult, Error> { Ok(CNIResult::default()) }
/// #     fn check(&self, args: Args) -> Result<CNIResult, Error> { Ok(CNIResult::default()) }
/// #     fn status(&self, _args: Args) -> Result<(), Error> { Ok(()) }
/// #     fn gc(&self, _args: Args) -> Result<(), Error> { Ok(()) }
/// # }
/// #
/// let plugin = Plugin::default().msg("MyPlugin v1.0.0");
/// let my_plugin = MyPlugin;
/// plugin.run(&my_plugin).expect("Failed to run plugin");
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
    /// Note that the ADD success output is always serialized in the specification's
    /// current result layout (`interfaces`/`ips`/`routes`/`dns`); the framework does
    /// not convert results to the pre-0.3.0 `ip4`/`ip6` layout those spec versions
    /// define. Listing a version before 0.3.0 in `versions` therefore produces ADD
    /// results consumers of that version cannot decode.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rscni_plugin::cni::Plugin;
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
    /// use rscni_plugin::cni::Plugin;
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
    /// 1. Reads the `CNI_COMMAND` environment variable
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
    /// # use rscni_plugin::{cni::{Cni, Plugin}, error::Error, types::{Args, CNIResult}};
    /// #
    /// # struct MyPlugin;
    /// # impl Cni for MyPlugin {
    /// #     fn add(&self, args: Args) -> Result<CNIResult, Error> { Ok(CNIResult::default()) }
    /// #     fn del(&self, args: Args) -> Result<CNIResult, Error> { Ok(CNIResult::default()) }
    /// #     fn check(&self, args: Args) -> Result<CNIResult, Error> { Ok(CNIResult::default()) }
    /// #     fn status(&self, _args: Args) -> Result<(), Error> { Ok(()) }
    /// #     fn gc(&self, _args: Args) -> Result<(), Error> { Ok(()) }
    /// # }
    /// #
    /// let plugin = Plugin::default();
    /// let my_plugin = MyPlugin;
    ///
    /// if let Err(e) = plugin.run(&my_plugin) {
    ///     eprintln!("CNI plugin failed: {}", e);
    ///     std::process::exit(1);
    /// }
    /// ```
    pub fn run<T: Cni>(&self, cni: &T) -> Result<(), Error> {
        self.run_with::<T, OsEnv, StdIo>(cni)
    }

    /// [`run`](Self::run) with its environment and I/O seams exposed, so tests can
    /// assert what actually lands on stdout — the success result and the error
    /// result structure both exist only on this side of `inner_run`.
    fn run_with<C: Cni, E: Env, I: Io>(&self, cni: &C) -> Result<(), Error> {
        match self.inner_run::<C, E, I>(cni) {
            Ok(res) => I::io_out()
                .write_all(res.as_bytes())
                .map_err(|e| Error::IOFailure(e.to_string())),
            Err(err) => {
                // The spec requires a failing plugin to put the error result structure
                // on stdout alongside the non-zero exit; that JSON is what runtimes
                // (libcni included) parse for diagnostics. Emission is best-effort — the
                // original error is what the caller must see either way.
                let error_result = ErrorResult::new(self.info.cni_version(), &err);
                if let Ok(json) = serde_json::to_string(&error_result) {
                    let _ = I::io_out().write_all(json.as_bytes());
                }
                Err(err)
            }
        }
    }

    fn inner_run<C: Cni, E: Env, I: Io>(&self, cni: &C) -> Result<String, Error> {
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
                // The spec requires the ADD result to carry a `cniVersion` key echoing
                // the version supplied on input.
                let cni_version = self.info.negotiate((&args).try_into()?, cmd)?;
                let res = cni.add(args)?;
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
                self.info.negotiate((&args).try_into()?, cmd)?;
                // The spec defines no success output for DEL; the returned value is
                // kept in the trait for API compatibility but is not written out.
                cni.del(args)?;
                Ok(String::new())
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
                self.info.negotiate((&args).try_into()?, cmd)?;
                // The spec defines no success output for CHECK; the returned value is
                // kept in the trait for API compatibility but is not written out.
                cni.check(args)?;
                Ok(String::new())
            }
            Cmd::Status => {
                // STATUS command only requires CNI_PATH (optional) and config from stdin
                let args = ArgsBuilder::<E, I>::new()
                    .path()?
                    .config()?
                    .validate(cmd)?
                    .build()?;
                self.info.negotiate((&args).try_into()?, cmd)?;
                cni.status(args)?;
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
                self.info.negotiate((&args).try_into()?, cmd)?;
                cni.gc(args)?;
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
    use std::cell::{Cell, RefCell};
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
        static MOCK_OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
        static MOCK_OUTPUT_BROKEN: Cell<bool> = const { Cell::new(false) };
    }

    struct MockIo;

    /// Appends to the thread-local output buffer, so tests can assert what the
    /// plugin put on its stdout via [`take_mock_output`] — or fails every write
    /// after [`break_mock_output`], like a closed stdout would.
    struct MockOut;

    impl Write for MockOut {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if MOCK_OUTPUT_BROKEN.with(Cell::get) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "mock stdout is broken",
                ));
            }
            MOCK_OUTPUT.with(|out| out.borrow_mut().extend_from_slice(buf));
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Makes every subsequent mock-stdout write fail. Test threads are fresh per
    /// test, so there is nothing to reset.
    fn break_mock_output() {
        MOCK_OUTPUT_BROKEN.with(|broken| broken.set(true));
    }

    impl Io for MockIo {
        fn io_in() -> impl Read {
            MOCK_INPUT.with(|input| {
                let data = input.borrow().clone();
                Cursor::new(data)
            })
        }

        fn io_out() -> impl Write {
            MockOut
        }

        fn io_err() -> impl Write {
            Vec::new()
        }
    }

    /// Drains and returns everything written to the mock stdout so far.
    fn take_mock_output() -> String {
        MOCK_OUTPUT.with(|out| String::from_utf8_lossy(&out.borrow_mut().split_off(0)).into_owned())
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

    impl Cni for MockCni {
        fn add(&self, _args: Args) -> Result<CNIResult, Error> {
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

        fn del(&self, _args: Args) -> Result<CNIResult, Error> {
            Ok(CNIResult::default())
        }

        fn check(&self, _args: Args) -> Result<CNIResult, Error> {
            Ok(CNIResult::default())
        }

        fn status(&self, _args: Args) -> Result<(), Error> {
            Ok(())
        }

        fn gc(&self, _args: Args) -> Result<(), Error> {
            Ok(())
        }
    }

    #[rstest]
    #[case("ADD")]
    #[case("DEL")]
    #[case("CHECK")]
    fn test_plugin_inner_run_commands(
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
            .map_err(|e| format!("Command {command} should succeed: {e}"))?;
        if command == "ADD" {
            assert!(!json_output.is_empty());
        } else {
            // The spec defines success output only for ADD (and VERSION).
            assert!(
                json_output.is_empty(),
                "{command} must produce no success output"
            );
        }
        Ok(())
    }

    #[test]
    fn test_plugin_inner_run_add_echoes_cni_version() -> Result<(), Box<dyn std::error::Error>> {
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
        let output = plugin.inner_run::<MockCni, MockEnv, MockIo>(&MockCni)?;

        // The spec: the ADD result must carry the cniVersion supplied on input, and
        // the result's own fields sit beside it at the top level — the wire wrapper
        // is flattened, not nested.
        let parsed: serde_json::Value = serde_json::from_str(&output)?;
        assert_eq!(parsed["cniVersion"], "1.0.0");
        assert_eq!(parsed["interfaces"][0]["name"], "eth0");
        Ok(())
    }

    #[test]
    fn test_plugin_inner_run_version() -> Result<(), Box<dyn std::error::Error>> {
        clear_mock_env();
        set_mock_env("CNI_COMMAND", "VERSION");

        let plugin = Plugin::default();
        let mock_cni = MockCni;

        let json_output = plugin.inner_run::<MockCni, MockEnv, MockIo>(&mock_cni)?;
        assert!(json_output.contains("cniVersion"));
        assert!(json_output.contains("supportedVersions"));
        Ok(())
    }

    #[test]
    fn test_plugin_inner_run_unset() {
        // Unset and empty are the same thing per the spec's reference implementation,
        // and CNI_COMMAND is required for every operation: both are error code 4.
        for setup in [(|| clear_mock_env()) as fn(), || {
            clear_mock_env();
            set_mock_env("CNI_COMMAND", "");
        }] {
            setup();
            let plugin = Plugin::default().msg("Test Plugin v1.0.0");
            let result = plugin.inner_run::<MockCni, MockEnv, MockIo>(&MockCni);
            assert!(matches!(result, Err(Error::InvalidEnvValue(_))));
        }
    }

    /// Arranges the mock environment (empty = unset, which the plugin treats
    /// identically) and a well-formed 1.1.0 config on stdin.
    fn set_dispatch_env(command: &str, container_id: &str, netns: &str, ifname: &str) {
        clear_mock_env();
        clear_mock_input();
        set_mock_env("CNI_COMMAND", command);
        set_mock_env("CNI_CONTAINERID", container_id);
        set_mock_env("CNI_NETNS", netns);
        set_mock_env("CNI_IFNAME", ifname);
        set_mock_input(r#"{"cniVersion":"1.1.0","name":"test-network","type":"test"}"#);
    }

    fn dispatch_with_env(
        command: &str,
        container_id: &str,
        netns: &str,
        ifname: &str,
    ) -> Result<String, Error> {
        set_dispatch_env(command, container_id, netns, ifname);
        Plugin::default().inner_run::<MockCni, MockEnv, MockIo>(&MockCni)
    }

    // `ArgsBuilder::validate`'s doc carries the spec's full required/optional
    // environment matrix; these tables drive it through dispatch, where the builder
    // wiring lives. Every violation is error code 4 naming the missing variable.
    #[rstest]
    #[case::add_without_netns("ADD", "c1", "", "eth0", "CNI_NETNS")]
    #[case::add_empty_container_id("ADD", "", "/ns", "eth0", "CNI_CONTAINERID")]
    #[case::del_without_container_id("DEL", "", "", "eth0", "CNI_CONTAINERID")]
    #[case::del_without_ifname("DEL", "c1", "", "", "CNI_IFNAME")]
    #[case::check_without_container_id("CHECK", "", "/ns", "eth0", "CNI_CONTAINERID")]
    #[case::gc_without_path("GC", "", "", "", "CNI_PATH")]
    fn test_plugin_inner_run_env_matrix_rejected(
        #[case] command: &str,
        #[case] container_id: &str,
        #[case] netns: &str,
        #[case] ifname: &str,
        #[case] missing: &str,
    ) {
        match dispatch_with_env(command, container_id, netns, ifname) {
            Err(Error::InvalidEnvValue(details)) => assert!(
                details.contains(missing),
                "{command}: details must name {missing}, got: {details}"
            ),
            other => panic!("{command} must fail naming {missing}, got: {other:?}"),
        }
    }

    // `run` owns what lands on stdout — the result JSON on success, the spec's error
    // result structure on failure — and a broken stdout must never replace the
    // plugin's own error (the best-effort discard in the error arm), while a failed
    // result write is itself an I/O failure (code 5). An expected code of 0 means
    // success; an empty expectation means nothing must land on stdout.
    #[rstest]
    #[case::success_puts_the_result("c1", false, 0, r#""interfaces""#)]
    #[case::failure_puts_the_error_result("", false, 4, r#""code":4"#)]
    #[case::broken_stdout_keeps_the_plugin_error("", true, 4, "")]
    #[case::broken_stdout_fails_a_success("c1", true, 5, "")]
    fn test_plugin_run_writes_stdout(
        #[case] container_id: &str,
        #[case] broken_stdout: bool,
        #[case] code: u32,
        #[case] expected: &str,
    ) {
        set_dispatch_env("ADD", container_id, "/ns", "eth0");
        if broken_stdout {
            break_mock_output();
        }

        let result = Plugin::default().run_with::<MockCni, MockEnv, MockIo>(&MockCni);
        let got = result.as_ref().map_or_else(u32::from, |()| 0);
        assert_eq!(got, code, "got: {result:?}");
        let stdout = take_mock_output();
        if expected.is_empty() {
            assert!(stdout.is_empty(), "stdout: {stdout}");
        } else {
            assert!(stdout.contains(expected), "stdout: {stdout}");
        }
    }

    #[rstest]
    #[case::add_required_only("ADD", "c1", "/ns", "eth0")]
    // CNI_NETNS is optional for DEL: teardown must complete after the netns is gone.
    #[case::del_without_netns("DEL", "c1", "", "eth0")]
    // STATUS requires nothing container-specific.
    #[case::status_bare("STATUS", "", "", "")]
    fn test_plugin_inner_run_env_matrix_accepted(
        #[case] command: &str,
        #[case] container_id: &str,
        #[case] netns: &str,
        #[case] ifname: &str,
    ) -> Result<(), Error> {
        dispatch_with_env(command, container_id, netns, ifname)?;
        Ok(())
    }

    #[test]
    fn test_plugin_inner_run_null_stdin_rejected() {
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
        let result = plugin.inner_run::<MockCni, MockEnv, MockIo>(&MockCni);
        assert!(matches!(result, Err(Error::InvalidNetworkConfig(_))));
    }

    #[test]
    fn test_plugin_inner_run_version_mismatch() -> Result<(), Box<dyn std::error::Error>> {
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

        let result = plugin.inner_run::<MockCni, MockEnv, MockIo>(&mock_cni);
        assert!(result.is_err());
        if let Err(Error::IncompatibleVersion(_)) = result {
            // Expected error
        } else {
            panic!("Expected IncompatibleVersion error");
        }
        Ok(())
    }

    #[rstest]
    #[case("CHECK", "0.3.1", "config version does not allow CHECK")]
    #[case("GC", "1.0.0", "config version does not allow GC")]
    #[case("STATUS", "1.0.0", "config version does not allow STATUS")]
    fn test_plugin_inner_run_operation_floor(
        #[case] command: &str,
        #[case] config_version: &str,
        #[case] expected_details: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // The config versions here are all in the default plugin's supported list, so
        // what must reject them is the operation floor (CHECK exists only from 0.4.0,
        // GC and STATUS from 1.1.0), not the supported-version membership check.
        clear_mock_env();
        clear_mock_input();
        set_mock_env("CNI_COMMAND", command);
        set_mock_env("CNI_CONTAINERID", "test-container");
        set_mock_env("CNI_NETNS", "/var/run/netns/test");
        set_mock_env("CNI_IFNAME", "eth0");
        set_mock_env("CNI_PATH", "/opt/cni/bin");
        let config = NetConf {
            cni_version: config_version.to_string(),
            name: "test-network".to_string(),
            r#type: "test".to_string(),
            ..Default::default()
        };
        set_mock_input(&serde_json::to_string(&config)?);

        let plugin = Plugin::default();
        let result = plugin.inner_run::<MockCni, MockEnv, MockIo>(&MockCni);
        match result {
            Err(Error::IncompatibleVersion(details)) => assert_eq!(details, expected_details),
            other => panic!("expected IncompatibleVersion, got {other:?}"),
        }
        Ok(())
    }

    #[rstest]
    #[case("CHECK", "0.4.0")]
    #[case("GC", "1.1.0")]
    #[case("STATUS", "1.1.0")]
    fn test_plugin_inner_run_operation_floor_boundary_accepted(
        #[case] command: &str,
        #[case] config_version: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // The exact floor version must dispatch: an off-by-one in the gate would
        // reject 1.1.0 — the only version a real runtime (libcni) ever issues GC and
        // STATUS with — and no other test dispatches GC successfully.
        clear_mock_env();
        clear_mock_input();
        set_mock_env("CNI_COMMAND", command);
        set_mock_env("CNI_CONTAINERID", "test-container");
        set_mock_env("CNI_NETNS", "/var/run/netns/test");
        set_mock_env("CNI_IFNAME", "eth0");
        set_mock_env("CNI_PATH", "/opt/cni/bin");
        let config = NetConf {
            cni_version: config_version.to_string(),
            name: "test-network".to_string(),
            r#type: "test".to_string(),
            ..Default::default()
        };
        set_mock_input(&serde_json::to_string(&config)?);

        let plugin = Plugin::default();
        let output = plugin.inner_run::<MockCni, MockEnv, MockIo>(&MockCni)?;
        // The spec defines no success output for any of these operations.
        assert!(output.is_empty());
        Ok(())
    }

    #[test]
    fn test_plugin_inner_run_missing_cni_version_means_010() {
        // `cniVersion` was only added to the config format in spec 0.2.0: its absence
        // means 0.1.0, which the default plugin does not support — error code 1, not a
        // decode failure.
        clear_mock_env();
        clear_mock_input();
        set_mock_env("CNI_COMMAND", "ADD");
        set_mock_env("CNI_CONTAINERID", "test-container");
        set_mock_env("CNI_NETNS", "/var/run/netns/test");
        set_mock_env("CNI_IFNAME", "eth0");
        set_mock_input(r#"{"name":"test-network","type":"test"}"#);

        let plugin = Plugin::default();
        let result = plugin.inner_run::<MockCni, MockEnv, MockIo>(&MockCni);
        assert!(matches!(result, Err(Error::IncompatibleVersion(_))));
    }

    #[test]
    fn test_plugin_inner_run_missing_cni_version_add_echoes_010()
    -> Result<(), Box<dyn std::error::Error>> {
        // A plugin that does support 0.1.0 serves the version-less config, and the ADD
        // result echoes the implied 0.1.0.
        clear_mock_env();
        clear_mock_input();
        set_mock_env("CNI_COMMAND", "ADD");
        set_mock_env("CNI_CONTAINERID", "test-container");
        set_mock_env("CNI_NETNS", "/var/run/netns/test");
        set_mock_env("CNI_IFNAME", "eth0");
        set_mock_input(r#"{"name":"test-network","type":"test"}"#);

        let plugin = Plugin::new("1.1.0", vec!["0.1.0".to_string(), "1.1.0".to_string()]);
        let output = plugin.inner_run::<MockCni, MockEnv, MockIo>(&MockCni)?;
        let parsed: serde_json::Value = serde_json::from_str(&output)?;
        assert_eq!(parsed["cniVersion"], "0.1.0");
        Ok(())
    }

    #[rstest]
    #[case("ADD")]
    #[case("CHECK")]
    fn test_plugin_inner_run_malformed_cni_version(
        #[case] command: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // The declared version is parsed once at the config boundary, so a version
        // that cannot parse is a decode failure (error code 6) on every operation.
        clear_mock_env();
        clear_mock_input();
        set_mock_env("CNI_COMMAND", command);
        set_mock_env("CNI_CONTAINERID", "test-container");
        set_mock_env("CNI_NETNS", "/var/run/netns/test");
        set_mock_env("CNI_IFNAME", "eth0");
        let config = NetConf {
            cni_version: "not-a-version".to_string(),
            name: "test-network".to_string(),
            r#type: "test".to_string(),
            ..Default::default()
        };
        set_mock_input(&serde_json::to_string(&config)?);

        let plugin = Plugin::default();
        let result = plugin.inner_run::<MockCni, MockEnv, MockIo>(&MockCni);
        assert!(matches!(result, Err(Error::FailedToDecode(_))));
        Ok(())
    }
}
