use std::io::Write;

use rscni_types::{
    error::Error,
    types::{CNI_COMMAND, CNIResult, Cmd, ErrorResult},
    version::{PluginInfo, SpecVersion},
};

use crate::{
    args::{Args, ArgsBuilder},
    util::{Env, Io, OsEnv, StdIo, result_json},
};

/// The core trait for implementing a CNI plugin.
///
/// Implement this trait to define the behavior of your CNI plugin for the
/// ADD, DEL, CHECK, STATUS and GC operations as specified by the CNI specification.
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
    /// The returned [`CNIResult`](../types/struct.CNIResult.html) is for API compatibility;
    /// the spec defines no success output, so it is never written to stdout.
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
    /// The returned [`CNIResult`](../types/struct.CNIResult.html) is for API compatibility;
    /// the spec defines no success output, so it is never written to stdout.
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
    /// attachments that do not exist in that set, which arrives in the configuration's
    /// `valid_attachments` field.
    ///
    /// Resources that may be cleaned up include:
    /// - IPAM reservations
    /// - Firewall rules
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
    /// The ADD success output is serialized in the result layout the negotiated
    /// config version requires: the legacy layout for versions 0.3.0 through 0.4.0,
    /// the current one for 1.0.0 and later. Versions 0.1.0 and 0.2.0 define yet
    /// another, `ip4`/`ip6`-shaped layout the framework does not produce, so listing
    /// them in `versions` produces ADD results consumers of those versions cannot
    /// decode.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rscni_plugin::{cni::Plugin, version::SpecVersion};
    ///
    /// let plugin = Plugin::new(
    ///     SpecVersion::new(1, 1, 0),
    ///     vec![SpecVersion::new(1, 0, 0), SpecVersion::new(1, 1, 0)]
    /// );
    /// ```
    #[must_use]
    pub const fn new(ver: SpecVersion, versions: Vec<SpecVersion>) -> Self {
        Self {
            info: PluginInfo::new(ver, versions),
            msg: None,
        }
    }

    /// Sets an optional message to display with version information.
    ///
    /// This message is shown when the plugin is called with the VERSION command.
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

    /// Renders the JSON this plugin answers `CNI_COMMAND=VERSION` with.
    ///
    /// Here rather than on [`PluginInfo`]: a runtime only ever reads this document,
    /// so the shared types crate should not promise the exact string.
    fn version_json(&self) -> Result<String, Error> {
        serde_json::to_string(&self.info).map_err(|e| Error::FailedToDecode(e.to_string()))
    }

    /// Prints the about text on stderr, which is what a bare invocation asks for.
    /// Without one there is no help to give, so the missing `CNI_COMMAND` is the
    /// error instead.
    fn print_about<I: Io>(&self) -> Result<(), Error> {
        let msg = self
            .msg
            .as_deref()
            .ok_or_else(|| Error::missing_env(&[CNI_COMMAND]))?;
        let help = format!(
            "{msg}\nCNI protocol versions supported: {}\n",
            self.info
                .supported_versions()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
        let _ = I::io_err().write_all(help.as_bytes());
        Ok(())
    }

    /// [`run`](Self::run) with its environment and I/O seams exposed, so tests can
    /// assert what actually lands on stdout — the success result and the error
    /// result structure both exist only on this side of `inner_run`.
    fn run_with<C: Cni, E: Env, I: Io>(&self, cni: &C) -> Result<(), Error> {
        // Flushed explicitly: the real stdout is buffered and its exit-time flush
        // discards errors, so a broken stream would otherwise lose the JSON silently.
        match self.inner_run::<C, E, I>(cni) {
            Ok(res) => {
                let mut out = I::io_out();
                out.write_all(res.as_bytes())
                    .and_then(|()| out.flush())
                    .map_err(|e| Error::IOFailure(e.to_string()))
            }
            Err(err) => {
                // The spec requires a failing plugin to put the error result on stdout
                // alongside the non-zero exit; that JSON is what runtimes parse for
                // diagnostics. Best-effort: the original error must reach the caller
                // either way, and a failed emission leaves a trace on stderr.
                let error_result = ErrorResult::new(self.info.cni_version(), &err);
                let mut out = I::io_out();
                if serde_json::to_writer(&mut out, &error_result).is_err() || out.flush().is_err() {
                    let _ = I::io_err().write_all(b"Error writing error JSON to stdout\n");
                }
                Err(err)
            }
        }
    }

    fn inner_run<C: Cni, E: Env, I: Io>(&self, cni: &C) -> Result<String, Error> {
        // CNI_COMMAND is required for every operation, so unset (or empty, the same
        // thing here) is error code 4 — unless an about text turns the bare
        // invocation into a help request, which succeeds with no stdout output.
        let Some(raw_cmd) = E::get::<String>(CNI_COMMAND)? else {
            self.print_about::<I>()?;
            return Ok(String::new());
        };
        let cmd: Cmd = raw_cmd.parse()?;

        match cmd {
            Cmd::Add => {
                let args = ArgsBuilder::<E, I>::new()
                    .container_id()?
                    .netns()?
                    .ifname()?
                    .args()?
                    .path()?
                    .validate(cmd)?
                    .config()?
                    .build()?;
                // The spec requires the ADD result to carry a `cniVersion` key echoing
                // the version supplied on input — and for versions before 1.0.0, to
                // use their legacy result layout. Refused before the callback runs, so
                // a version whose layout this crate cannot render fails without
                // leaving the attachment behind.
                let cni_version = self.info.negotiate(args.config(), cmd)?;
                if !cni_version.is_supported() {
                    return Err(Error::IncompatibleVersion(format!(
                        "unsupported CNI result version \"{cni_version}\""
                    )));
                }
                let res = cni.add(args)?;
                result_json(cni_version, res)
            }
            Cmd::Del => {
                let args = ArgsBuilder::<E, I>::new()
                    .container_id()?
                    .netns()?
                    .ifname()?
                    .args()?
                    .path()?
                    .validate(cmd)?
                    .config()?
                    .build()?;
                self.info.negotiate(args.config(), cmd)?;
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
                    .validate(cmd)?
                    .config()?
                    .build()?;
                self.info.negotiate(args.config(), cmd)?;
                cni.check(args)?;
                Ok(String::new())
            }
            Cmd::Status => {
                let args = ArgsBuilder::<E, I>::new()
                    .path()?
                    .validate(cmd)?
                    .config()?
                    .build()?;
                self.info.negotiate(args.config(), cmd)?;
                cni.status(args)?;
                Ok(String::new())
            }
            Cmd::Gc => {
                let args = ArgsBuilder::<E, I>::new()
                    .path()?
                    .validate(cmd)?
                    .config()?
                    .build()?;
                self.info.negotiate(args.config(), cmd)?;
                cni.gc(args)?;
                Ok(String::new())
            }
            Cmd::Version => self.version_json(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Dns, Interface, IpConfig, Route};
    use rscni_types::ipnet::{IpNet, Ipv4Net};
    use rstest::rstest;
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::io::{Cursor, Read, Write};
    use std::net::{IpAddr, Ipv4Addr};
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

    /// Makes every subsequent mock-stdout write fail; [`set_dispatch_env`] arms the
    /// next test with a working one again.
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

    const ADDRESS: IpNet = IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(10, 1, 0, 5), 16));
    const DEFAULT_ROUTE: IpNet = IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::UNSPECIFIED, 0));
    const GATEWAY: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));

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
                    address: ADDRESS,
                    gateway: Some(GATEWAY),
                }],
                routes: vec![Route {
                    dst: DEFAULT_ROUTE,
                    gw: Some(GATEWAY),
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

    // Accepted dispatches with no success output (the spec defines success output
    // only for ADD and VERSION), including the exact operation floors — an off-by-one
    // in the gate would reject 1.1.0, the only version a real runtime (libcni) ever
    // issues GC and STATUS with — and CHECK above its floor.
    #[rstest]
    #[case::del("DEL", "1.1.0")]
    #[case::check_at_floor("CHECK", "0.4.0")]
    #[case::check_above_floor("CHECK", "1.1.0")]
    #[case::gc_at_floor("GC", "1.1.0")]
    #[case::status_at_floor("STATUS", "1.1.0")]
    fn test_plugin_inner_run_accepted(
        #[case] command: &str,
        #[case] config_version: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        set_dispatch_env(command, "test-container", "/var/run/netns/test", "eth0");
        set_mock_env("CNI_PATH", "/opt/cni/bin");
        set_mock_config_version(config_version);

        let output = Plugin::default()
            .inner_run::<MockCni, MockEnv, MockIo>(&MockCni)
            .map_err(|e| format!("{command} must succeed: {e}"))?;
        assert!(output.is_empty(), "{command} got: {output}");
        Ok(())
    }

    #[rstest]
    #[case("1.0.0", None)]
    #[case("0.4.0", Some("4"))]
    fn test_plugin_inner_run_add_echoes_cni_version(
        #[case] version: &str,
        #[case] legacy_ip_family: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        set_dispatch_env("ADD", "test-container", "/var/run/netns/test", "eth0");
        set_mock_config_version(version);

        let plugin = Plugin::default();
        let output = plugin.inner_run::<MockCni, MockEnv, MockIo>(&MockCni)?;

        // The spec: the ADD result must carry the cniVersion supplied on input, and
        // the result's own fields sit beside it at the top level — the wire wrapper
        // is flattened, not nested.
        let parsed: serde_json::Value = serde_json::from_str(&output)?;
        assert_eq!(parsed["cniVersion"], version);
        assert_eq!(parsed["interfaces"][0]["name"], "eth0");
        // Pre-1.0 versions get the legacy layout, recognizable by the mandatory
        // ips[].version; the exact conversion is rscni-types' legacy tests' business.
        assert_eq!(
            parsed["ips"][0].get("version").and_then(|v| v.as_str()),
            legacy_ip_family
        );
        Ok(())
    }

    #[test]
    fn test_plugin_inner_run_version() -> Result<(), Box<dyn std::error::Error>> {
        set_dispatch_env("VERSION", "", "", "");

        let plugin = Plugin::default();
        let mock_cni = MockCni;

        let json_output = plugin.inner_run::<MockCni, MockEnv, MockIo>(&mock_cni)?;
        assert!(json_output.contains("cniVersion"));
        assert!(json_output.contains("supportedVersions"));
        Ok(())
    }

    // A missing CNI_COMMAND is a help request when an about text exists — help on
    // stderr, success with no output — and error code 4 otherwise.
    #[test]
    fn test_plugin_inner_run_unset_prints_help() -> Result<(), Error> {
        set_dispatch_env("", "", "", "");
        let plugin = Plugin::default().msg("Test Plugin v1.0.0");
        let out = plugin.inner_run::<MockCni, MockEnv, MockIo>(&MockCni)?;
        assert!(out.is_empty());
        Ok(())
    }

    #[test]
    fn test_plugin_inner_run_unset_without_about_text_is_code_4() {
        set_dispatch_env("", "", "", "");
        let result = Plugin::default().inner_run::<MockCni, MockEnv, MockIo>(&MockCni);
        assert!(
            matches!(result, Err(Error::InvalidEnvValue(_))),
            "got: {result:?}"
        );
    }

    /// Arranges every mock seam from scratch — the single test entry point, so
    /// isolation never leans on the harness giving each test a fresh thread. Empty
    /// variables are omitted, exactly what a spec-strict runtime sends; stdin gets a
    /// well-formed 1.1.0 config. Tests needing more layer overrides on top with
    /// [`set_mock_env`]/[`set_mock_input`].
    fn set_dispatch_env(command: &str, container_id: &str, netns: &str, ifname: &str) {
        MOCK_ENV.with(|env| env.borrow_mut().clear());
        MOCK_OUTPUT.with(|out| out.borrow_mut().clear());
        MOCK_OUTPUT_BROKEN.with(|broken| broken.set(false));
        let vars = [
            ("CNI_COMMAND", command),
            ("CNI_CONTAINERID", container_id),
            ("CNI_NETNS", netns),
            ("CNI_IFNAME", ifname),
        ];
        for (key, value) in vars {
            if !value.is_empty() {
                set_mock_env(key, value);
            }
        }
        set_mock_config_version("1.1.0");
    }

    /// Puts a well-formed config declaring `version` on stdin.
    fn set_mock_config_version(version: &str) {
        set_mock_input(&format!(
            r#"{{"cniVersion":"{version}","name":"test-network","type":"test"}}"#
        ));
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
    #[case::add_without_container_id("ADD", "", "/ns", "eth0", "CNI_CONTAINERID")]
    #[case::del_without_container_id("DEL", "", "", "eth0", "CNI_CONTAINERID")]
    #[case::del_without_ifname("DEL", "c1", "", "", "CNI_IFNAME")]
    #[case::check_without_container_id("CHECK", "", "/ns", "eth0", "CNI_CONTAINERID")]
    #[case::gc_without_path("GC", "", "", "", "CNI_PATH")]
    // Missing variables are reported together, in the reference's wording and order.
    #[case::add_bare("ADD", "", "", "", "[CNI_CONTAINERID,CNI_NETNS,CNI_IFNAME]")]
    // Present values are held to the spec's character rules.
    #[case::invalid_container_id(
        "ADD",
        "bad*id",
        "/ns",
        "eth0",
        "invalid characters in containerID"
    )]
    #[case::invalid_ifname(
        "ADD",
        "c1",
        "/ns",
        "eth0:0",
        "interface name contains / or : or whitespace"
    )]
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

    // Broken stdin, by error class: a literal `null` decodes to no configuration
    // without failing, so it is a config error (7), as is a bad network name; a
    // version that cannot parse is a decode failure (6).
    #[rstest]
    #[case::null_config("null", 7)]
    #[case::malformed_version(
        r#"{"cniVersion":"not-a-version","name":"test-network","type":"test"}"#,
        6
    )]
    #[case::missing_network_name(r#"{"cniVersion":"1.1.0","type":"test"}"#, 7)]
    #[case::invalid_network_name(r#"{"cniVersion":"1.1.0","name":"bad*name","type":"test"}"#, 7)]
    #[case::non_boolean_capability(
        r#"{"cniVersion":"1.1.0","name":"test-network","type":"test","capabilities":{"portMappings":"true"}}"#,
        6
    )]
    fn test_plugin_inner_run_broken_stdin_rejected(#[case] stdin: &str, #[case] code: u32) {
        set_dispatch_env("ADD", "test-container", "/var/run/netns/test", "eth0");
        set_mock_input(stdin);

        let Err(err) = Plugin::default().inner_run::<MockCni, MockEnv, MockIo>(&MockCni) else {
            panic!("ADD must reject this stdin");
        };
        assert_eq!(u32::from(&err), code, "got: {err:?}");
    }

    // Version negotiation rejections, all error code 1. The floor cases use versions
    // from the default plugin's supported list, so what must reject them is the
    // operation floor (CHECK exists only from 0.4.0, GC and STATUS from 1.1.0), not
    // the supported-version membership check; the membership cases are the reverse,
    // and ADD and DEL have no floor, so membership is their only gate.
    #[rstest]
    #[case::check_below_floor(
        Plugin::default(),
        "CHECK",
        "0.3.1",
        "config version does not allow CHECK"
    )]
    #[case::gc_below_floor(Plugin::default(), "GC", "1.0.0", "config version does not allow GC")]
    #[case::status_below_floor(
        Plugin::default(),
        "STATUS",
        "1.0.0",
        "config version does not allow STATUS"
    )]
    #[case::add_unsupported_version(
        Plugin::new(SpecVersion::new(1, 0, 0), vec![SpecVersion::new(1, 0, 0)]),
        "ADD",
        "0.4.0",
        r#"config is "0.4.0""#
    )]
    #[case::del_unsupported_version(
        Plugin::new(SpecVersion::new(1, 0, 0), vec![SpecVersion::new(1, 0, 0)]),
        "DEL",
        "0.4.0",
        r#"config is "0.4.0""#
    )]
    fn test_plugin_inner_run_version_rejected(
        #[case] plugin: Plugin,
        #[case] command: &str,
        #[case] config_version: &str,
        #[case] expected_details: &str,
    ) {
        set_dispatch_env(command, "test-container", "/var/run/netns/test", "eth0");
        set_mock_env("CNI_PATH", "/opt/cni/bin");
        set_mock_config_version(config_version);

        match plugin.inner_run::<MockCni, MockEnv, MockIo>(&MockCni) {
            Err(Error::IncompatibleVersion(details)) => {
                assert!(details.contains(expected_details), "got: {details}");
            }
            other => panic!("expected IncompatibleVersion, got {other:?}"),
        }
    }

    // `cniVersion` was only added to the config format in spec 0.2.0: its absence
    // means 0.1.0, rejected with code 1 — even by a plugin listing 0.1.0 as
    // supported, since this crate cannot produce that version's result layout.
    #[rstest]
    #[case::rejected_without_010_support(Plugin::default(), "plugin supports")]
    #[case::layout_unsupported_despite_010_support(
        Plugin::new(
            SpecVersion::new(1, 1, 0),
            vec![SpecVersion::new(0, 1, 0), SpecVersion::new(1, 1, 0)]
        ),
        "unsupported CNI result version \"0.1.0\""
    )]
    fn test_plugin_inner_run_missing_cni_version(
        #[case] plugin: Plugin,
        #[case] details_contain: &str,
    ) {
        set_dispatch_env("ADD", "test-container", "/var/run/netns/test", "eth0");
        set_mock_input(r#"{"name":"test-network","type":"test"}"#);

        let result = plugin.inner_run::<MockCni, MockEnv, MockIo>(&MockCni);
        match result {
            Err(Error::IncompatibleVersion(details)) => {
                assert!(details.contains(details_contain), "got: {details}");
            }
            other => panic!("expected IncompatibleVersion, got {other:?}"),
        }
    }
}
