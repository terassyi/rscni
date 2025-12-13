//! CNI specification types and data structures.
//!
//! This module contains all the types defined by the [CNI specification](https://www.cni.dev/),
//! including network configuration, results, and related structures.
//!
//! # Main Types
//!
//! - [`Args`] - Input parameters for CNI operations (from environment and stdin)
//! - [`NetConf`] - Network configuration passed to the plugin
//! - [`CNIResult`] - Result returned by ADD/DEL/CHECK operations
//! - [`Interface`], [`IpConfig`], [`Route`] - Components of the CNI result
//! - [`Dns`], [`Ipam`] - Network configuration components
//!

use std::{collections::HashMap, io::Read, path::PathBuf, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    error::Error,
    util::{Env, Io},
};

pub(super) const CNI_COMMAND: &str = "CNI_COMMAND";
pub(super) const CNI_CONTAINERID: &str = "CNI_CONTAINERID";
pub(super) const CNI_NETNS: &str = "CNI_NETNS";
pub(super) const CNI_IFNAME: &str = "CNI_IFNAME";
pub(super) const CNI_ARGS: &str = "CNI_ARGS";
pub(super) const CNI_PATH: &str = "CNI_PATH";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cmd {
    Add,
    Del,
    Check,
    Version,
    /// Unset state when `CNI_COMMAND` is not set.
    UnSet,
}

impl FromStr for Cmd {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ADD" => Ok(Self::Add),
            "DEL" => Ok(Self::Del),
            "CHECK" => Ok(Self::Check),
            "VERSION" => Ok(Self::Version),
            "" => Ok(Self::UnSet),
            _ => Err(Error::InvalidEnvValue(format!("unknown CNI_COMMAND: {s}"))),
        }
    }
}

impl From<Cmd> for &str {
    fn from(cmd: Cmd) -> Self {
        match cmd {
            Cmd::Add => "ADD",
            Cmd::Del => "DEL",
            Cmd::Check => "CHECK",
            Cmd::Version => "VERSION",
            Cmd::UnSet => "",
        }
    }
}

impl Cmd {
    pub(super) fn get_from_env<E: Env>() -> Result<Self, Error> {
        Self::from_str(&E::get::<String>(CNI_COMMAND)?)
    }
}

/// Args is input data for the CNI call.
///
/// All fields except for `config` are given as environment values.
/// `config` field is given as a JSON format data([`NetConf`]) from stdin.
/// Depending on the type of command, some fields are omitted.
/// Please see <https://github.com/containernetworking/cni/blob/v1.1.0/SPEC.md#parameters> and <https://github.com/containernetworking/cni/blob/v1.1.0/SPEC.md#cni-operations>.
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
        match E::get::<String>(CNI_CONTAINERID) {
            Ok(val) => self.container_id = Some(val),
            Err(e) => return Err(e),
        }
        Ok(self)
    }

    /// Reads network namespace from the `CNI_NETNS` environment variable.
    ///
    /// # Errors
    ///
    /// Returns an error if the environment variable is set but cannot be read properly.
    pub fn netns(mut self) -> Result<Self, Error> {
        match E::get::<String>(CNI_NETNS) {
            Ok(val) => {
                self.netns = PathBuf::from_str(&val)
                    .map_err(|e| Error::FailedToDecode(e.to_string()))
                    .ok();
            }
            Err(e) => return Err(e),
        }
        Ok(self)
    }

    /// Reads interface name from the `CNI_IFNAME` environment variable.
    ///
    /// # Errors
    ///
    /// Returns an error if the environment variable is set but cannot be read properly.
    pub fn ifname(mut self) -> Result<Self, Error> {
        match E::get::<String>(CNI_IFNAME) {
            Ok(val) => self.ifname = Some(val),
            Err(e) => return Err(e),
        }
        Ok(self)
    }

    /// Reads extra arguments from the `CNI_ARGS` environment variable.
    ///
    /// # Errors
    ///
    /// Returns an error if the environment variable is set but cannot be read properly.
    pub fn args(mut self) -> Result<Self, Error> {
        match E::get::<String>(CNI_ARGS) {
            Ok(val) => self.args = if val.is_empty() { None } else { Some(val) },
            Err(e) => return Err(e),
        }
        Ok(self)
    }

    /// Reads CNI plugin paths from the `CNI_PATH` environment variable.
    ///
    /// # Errors
    ///
    /// Returns an error if the environment variable is set but cannot be read properly.
    pub fn path(mut self) -> Result<Self, Error> {
        match E::get::<String>(CNI_PATH) {
            Ok(val) => self.path = val.split(':').map(PathBuf::from).collect(),
            Err(e) => return Err(e),
        }
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
            Cmd::Version | Cmd::UnSet => {
                // These commands don't require container-specific parameters
            }
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

/// `NetConf` will be given as a JSON serialized data from stdin when plugin is called.
/// Please see <https://github.com/containernetworking/cni/blob/v1.1.0/SPEC.md#section-1-network-configuration-format>.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct NetConf {
    /// Semantic Version 2.0 of CNI specification to which this configuration list and all the individual configurations conform.
    pub cni_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cni_versions: Option<Vec<String>>,
    /// Network name.
    /// This should be unique across all network configurations on a host (or other administrative domain).
    /// Must start with an alphanumeric character, optionally followed by any combination of one or more alphanumeric characters, underscore, dot (.) or hyphen (-).
    pub name: String,
    /// Matches the name of the CNI plugin binary on disk. Must not contain characters disallowed in file paths for the system (e.g. / or \).
    pub r#type: String,
    /// Either true or false.
    /// If disableCheck is true, runtimes must not call CHECK for this network configuration list.
    /// This allows an administrator to prevent `CHECKing` where a combination of plugins is known to return spurious errors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_check: Option<bool>,
    /// A JSON object, consisting of the union of capabilities provided by the plugin and requested by the runtime
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_config: Option<RuntimeConf>,
    /// See <https://github.com/containernetworking/cni/blob/v1.1.0/SPEC.md#deriving-runtimeconfig>.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<HashMap<String, Value>>,
    /// If supported by the plugin, sets up an IP masquerade on the host for this network.
    /// This is necessary if the host will act as a gateway to subnets that are not able to route to the IP assigned to the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_masq: Option<bool>,
    /// Dictionary with IPAM (IP Address Management) specific values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipam: Option<Ipam>,
    /// Dictionary with DNS specific values
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Dns>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<HashMap<String, Value>>,
    /// A JSON object, consisting of the result type returned by the "previous" plugin. The meaning of "previous" is defined by the specific operation (add, delete, or check).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_result: Option<CNIResult>,
    #[serde(flatten)]
    pub custom: HashMap<String, Value>,
}

/// `NetConfList` is a network configuration format for administrators.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetConfList {
    /// Semantic Version 2.0 of CNI specification to which this configuration list and all the individual configurations conform.
    pub cni_version: String,
    pub cni_versions: Vec<String>,
    /// Network name.
    /// This should be unique across all network configurations on a host (or other administrative domain).
    /// Must start with an alphanumeric character, optionally followed by any combination of one or more alphanumeric characters, underscore, dot (.) or hyphen (-).
    pub name: String,
    /// Either true or false.
    /// If disableCheck is true, runtimes must not call CHECK for this network configuration list.
    /// This allows an administrator to prevent `CHECKing` where a combination of plugins is known to return spurious errors.
    ///
    #[serde(default)] // default is false
    pub disable_check: bool,
    /// A list of CNI plugins and their configuration, which is a list of plugin configuration objects.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plugins: Vec<NetConf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeConf {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_mappings: Vec<PortMapping>,
    #[serde(flatten)]
    pub custom: HashMap<String, Value>,
}

/// Dictionary with IPAM (IP Address Management) specific values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Ipam {
    /// Refers to the filename of the IPAM plugin executable. Must not contain characters disallowed in file paths for the system (e.g. / or \).
    pub r#type: String,
    #[serde(flatten)]
    pub custom: HashMap<String, Value>,
}

/// DNS configuration information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Dns {
    /// List of a priority-ordered list of DNS nameservers that this network is aware of. Each entry in the list is a string containing either an IPv4 or an IPv6 address.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nameservers: Vec<String>,
    /// The local domain used for short hostname lookups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// List of priority ordered search domains for short hostname lookups. Will be preferred over domain by most resolvers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<Vec<String>>,
    /// List of options that can be passed to the resolver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
}

/// Route created by plugins.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Route {
    /// The destination of the route, in CIDR notation.
    pub dst: String, // represent ipnet::IpNet
    /// The next hop address.
    /// If unset, a value in `gateway` in the `ips` array in the CNI Result Type may be used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advmss: Option<u32>,
}

/// `CNIResult` represents the Success result type.
/// `CmdFm` returns this if it finish successfully.
/// Please see <https://github.com/containernetworking/cni/blob/v1.1.0/SPEC.md#success>.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct CNIResult {
    /// In case of delegated plugins(IPAM), it may omit interfaces or ips sections.
    /// Please see <https://github.com/containernetworking/cni/blob/v1.1.0/SPEC.md#delegated-plugins-ipam>.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<Interface>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<IpConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<Route>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Dns>,
}

/// `CNIResultWithCNIVersion` represents actual output of CNI success result type as a JSON format.
/// Users don't have to use this type directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CNIResultWithCNIVersion {
    pub cni_version: String,
    #[serde(flatten)]
    inner: CNIResult,
}

/// The interface created by the attachment, including any host-level interfaces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Interface {
    /// The name of the interface.
    pub name: String,
    /// The hardware address of the interface.
    pub mac: String,
    /// The isolation domain reference(e.g. path to network namespace) for the interface, or empty if on the host.
    /// For interfaces created inside the container, this should be the value passes via `CNI_NETNS`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<String>,
}

/// IP assigned by the plugin.
/// Plugins may include IPs assigned external to the container.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IpConfig {
    /// the index into the `interfaces` list for a `interfaces` list for a CNI Plugin Result(CNIResult type) indicating which interface this IP configuration should be applied to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<u32>,
    /// an IP address in CIDR notation.
    pub address: String,
    /// the default gateway for this subnet, if one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortMapping {
    pub host_port: u32,
    pub container_port: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// `ErrorResult` is converted from Error.
/// This is actual data structure of Error CNI Result Type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ErrorResult {
    /// The same value as provided by the configuration.
    pub(crate) cni_version: String,
    /// A numeric error code.
    pub(crate) code: u32,
    /// A short message characterizing the error.
    pub(crate) msg: String,
    /// A longer message describing the error.
    pub(crate) details: String,
}

impl From<&ErrorResult> for Error {
    fn from(res: &ErrorResult) -> Self {
        if res.code > 100 {
            return Self::Custom(res.code, res.msg.clone(), res.details.clone());
        }
        match res.code {
            1 => Self::IncompatibleVersion(res.details.clone()),
            2 => Self::UnsupportedNetworkConfiguration(res.details.clone()),
            3 => Self::NotExist(res.details.clone()),
            4 => Self::InvalidEnvValue(res.details.clone()),
            5 => Self::IOFailure(res.details.clone()),
            6 => Self::FailedToDecode(res.details.clone()),
            7 => Self::InvalidNetworkConfig(res.details.clone()),
            11 => Self::TryAgainLater(res.details.clone()),
            _ => Self::FailedToDecode(format!("unknown error code: {}", res.code)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr, vec};

    use rstest::rstest;
    use serde_json::json;

    use crate::error::Error;

    use super::{
        CNIResult, Cmd, Dns, Interface, IpConfig, Ipam, NetConf, PortMapping, Protocol, Route,
        RuntimeConf,
    };

    #[rstest]
    #[case("ADD", Cmd::Add)]
    #[case("DEL", Cmd::Del)]
    #[case("CHECK", Cmd::Check)]
    #[case("VERSION", Cmd::Version)]
    #[case("", Cmd::UnSet)]
    fn test_cmd_from_str(#[case] input: &str, #[case] expected: Cmd) {
        let result = Cmd::from_str(input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn test_cmd_from_str_invalid() {
        let result = Cmd::from_str("INVALID");
        assert!(result.is_err());
        if let Err(Error::InvalidEnvValue(msg)) = result {
            assert!(msg.contains("unknown CNI_COMMAND"));
        } else {
            panic!("Expected InvalidEnvValue error");
        }
    }

    #[rstest]
    #[case(Cmd::Add, "ADD")]
    #[case(Cmd::Del, "DEL")]
    #[case(Cmd::Check, "CHECK")]
    #[case(Cmd::Version, "VERSION")]
    #[case(Cmd::UnSet, "")]
    fn test_cmd_to_str(#[case] cmd: Cmd, #[case] expected: &str) {
        let result: &str = cmd.into();
        assert_eq!(result, expected);
    }

    #[rstest(
        input,
        expected,
        case(
            // ref: https://github.com/containernetworking/cni/blob/b62753aa2bfa365c1ceaff6f25774a8047c896b5/SPEC.md#add-example
            r#"{
  "cniVersion": "1.1.0",
  "name": "dbnet",
  "type": "bridge",
  "bridge": "cni0",
  "keyA": ["some more", "plugin specific", "configuration"],
  "ipam": {
    "type": "host-local",
    "subnet": "10.1.0.0/16",
    "gateway": "10.1.0.1"
  },
  "dns": {
    "nameservers": [ "10.1.0.1" ]
  }
}"#.to_string(),
            NetConf {
                cni_version: "1.1.0".to_string(),
                cni_versions: None,
                name: "dbnet".to_string(),
                r#type: "bridge".to_string(),
                disable_check: None,
                runtime_config: None,
                capabilities: None,
				ip_masq: None,
                ipam: Some(Ipam{
                    r#type: "host-local".to_string(),
                    custom: HashMap::from([
                        ("subnet".to_string(), serde_json::Value::String("10.1.0.0/16".to_string())),
                        ("gateway".to_string(), serde_json::Value::String("10.1.0.1".to_string())),
                    ]),
                }),
                dns: Some(Dns{
                    nameservers: vec!["10.1.0.1".to_string()],
                    domain: None,
                    search: None,
                    options: None,
                }),
                args: None,
                prev_result: None,
                custom: HashMap::from([
                    ("bridge".to_string(), serde_json::Value::String("cni0".to_string())),
                    ("keyA".to_string(), serde_json::Value::Array(vec![serde_json::Value::String("some more".to_string()), serde_json::Value::String("plugin specific".to_string()), serde_json::Value::String("configuration".to_string())])),
                ]),
            },
        ),
        case(
            // ref: https://github.com/containernetworking/cni/blob/b62753aa2bfa365c1ceaff6f25774a8047c896b5/SPEC.md#deriving-runtimeconfig
            r#"{
  "cniVersion": "1.1.0",
  "name": "test",
  "type": "myPlugin",
  "capabilities": {
    "portMappings": true
  }
}"#.to_string(),
            NetConf {
                cni_version: "1.1.0".to_string(),
                cni_versions: None,
                name: "test".to_string(),
                r#type: "myPlugin".to_string(),
                disable_check: None,
                runtime_config: None,
                capabilities: Some(HashMap::from([
                    ("portMappings".to_string(), serde_json::Value::Bool(true)),
                ])),
				ip_masq: None,
                ipam: None,
                dns: None,
                args: None,
                prev_result: None,
                custom: HashMap::new(),
            },
        ),
        case(
            // ref: https://github.com/containernetworking/cni/blob/b62753aa2bfa365c1ceaff6f25774a8047c896b5/SPEC.md#deriving-runtimeconfig
            r#"{
  "cniVersion": "1.1.0",
  "name": "test",
  "type": "myPlugin",
  "capabilities": {
    "portMappings": true
  },
  "runtimeConfig": {
    "portMappings": [ { "hostPort": 8080, "containerPort": 80, "protocol": "tcp" } ]
  }
}"#.to_string(),
            NetConf {
                cni_version: "1.1.0".to_string(),
                cni_versions: None,
                name: "test".to_string(),
                r#type: "myPlugin".to_string(),
                disable_check: None,
                runtime_config: Some(RuntimeConf{
                    port_mappings: vec![
                        PortMapping{
                            host_port: 8080,
                            container_port: 80,
                            protocol: Some(Protocol::Tcp),
                        },
                    ],
                    custom: HashMap::new(),
                }),
                capabilities: Some(HashMap::from([
                    ("portMappings".to_string(), serde_json::Value::Bool(true)),
                ])),
				ip_masq: None,
                ipam: None,
                dns: None,
                args: None,
                prev_result: None,
                custom: HashMap::new(),
            },
        ),
        case(
            // ref: https://github.com/containernetworking/cni/blob/b62753aa2bfa365c1ceaff6f25774a8047c896b5/SPEC.md#add-example
            r#"{
  "cniVersion": "1.1.0",
  "name": "dbnet",
  "type": "tuning",
  "sysctl": {
    "net.core.somaxconn": "500"
  },
  "runtimeConfig": {
    "mac": "00:11:22:33:44:66"
  },
  "prevResult": {
    "ips": [
        {
          "address": "10.1.0.5/16",
          "gateway": "10.1.0.1",
          "interface": 2
        }
    ],
    "routes": [
      {
        "dst": "0.0.0.0/0"
      }
    ],
    "interfaces": [
        {
            "name": "cni0",
            "mac": "00:11:22:33:44:55"
        },
        {
            "name": "veth3243",
            "mac": "55:44:33:22:11:11"
        },
        {
            "name": "eth0",
            "mac": "99:88:77:66:55:44",
            "sandbox": "/var/run/netns/blue"
        }
    ],
    "dns": {
      "nameservers": [ "10.1.0.1" ]
    }
  }
}"#.to_string(),
            NetConf {
                cni_version: "1.1.0".to_string(),
                cni_versions: None,
                name: "dbnet".to_string(),
                r#type: "tuning".to_string(),
                disable_check: None,
                runtime_config: Some(RuntimeConf{
                    port_mappings: Vec::new(),
                    custom: HashMap::from([("mac".to_string(), serde_json::Value::String("00:11:22:33:44:66".to_string()))])
                }),
                capabilities: None,
				ip_masq: None,
                ipam: None,
                dns: None,
                args: None,
                prev_result: Some(CNIResult{
                  ips: vec![
                    IpConfig{
                      interface: Some(2),
                      address: "10.1.0.5/16".to_string(),
                      gateway:Some("10.1.0.1".to_string()),
                    },
                  ],
                  interfaces: vec![
                    Interface{
                      name: "cni0".to_string(),
                      mac: "00:11:22:33:44:55".to_string(),
                      sandbox: None,
                    },
                    Interface{
                      name: "veth3243".to_string(),
                      mac: "55:44:33:22:11:11".to_string(),
                      sandbox: None,
                    },
                    Interface{
                      name: "eth0".to_string(),
                      mac: "99:88:77:66:55:44".to_string(),
                      sandbox: Some("/var/run/netns/blue".to_string()),
                    },
                  ],
                  routes: vec![
                    Route{
                      dst: "0.0.0.0/0".to_string(),
                      gw: None,
                      mtu: None,
                      advmss: None,
                    },
                  ],
                  dns: Some(Dns{
                    nameservers: vec!["10.1.0.1".to_string()],
                    domain: None,
                    search: None,
                    options: None,
                  }),
                }),
                custom: HashMap::from([
                    ("sysctl".to_string(), json!({"net.core.somaxconn": "500"})),
                ]),
            },
        ),
        case(
            // ref: https://github.com/containernetworking/cni/blob/b62753aa2bfa365c1ceaff6f25774a8047c896b5/SPEC.md#add-example
            r#"{
  "cniVersion": "1.1.0",
  "name": "dbnet",
  "type": "portmap",
  "runtimeConfig": {
    "portMappings" : [
      { "hostPort": 8080, "containerPort": 80, "protocol": "tcp" }
    ]
  },
  "prevResult": {
    "ips": [
        {
          "address": "10.1.0.5/16",
          "gateway": "10.1.0.1",
          "interface": 2
        }
    ],
    "routes": [
      {
        "dst": "0.0.0.0/0"
      }
    ],
    "interfaces": [
        {
            "name": "cni0",
            "mac": "00:11:22:33:44:55"
        },
        {
            "name": "veth3243",
            "mac": "55:44:33:22:11:11"
        },
        {
            "name": "eth0",
            "mac": "00:11:22:33:44:66",
            "sandbox": "/var/run/netns/blue"
        }
    ],
    "dns": {
      "nameservers": [ "10.1.0.1" ]
    }
  }
}"#.to_string(),
            NetConf {
                cni_version: "1.1.0".to_string(),
                cni_versions: None,
                name: "dbnet".to_string(),
                r#type: "portmap".to_string(),
                disable_check: None,
                runtime_config: Some(RuntimeConf{
                    port_mappings: vec![
                        PortMapping{
                            host_port: 8080,
                            container_port: 80,
                            protocol: Some(Protocol::Tcp),
                        },
                    ],
                    custom: HashMap::new(),
                }),
                capabilities: None,
				ip_masq: None,
                ipam: None,
                dns: None,
                args: None,
                prev_result: Some(CNIResult{
                  ips: vec![
                    IpConfig{
                      interface: Some(2),
                      address: "10.1.0.5/16".to_string(),
                      gateway:Some("10.1.0.1".to_string()),
                    },
                  ],
                  interfaces: vec![
                    Interface{
                      name: "cni0".to_string(),
                      mac: "00:11:22:33:44:55".to_string(),
                      sandbox: None,
                    },
                    Interface{
                      name: "veth3243".to_string(),
                      mac: "55:44:33:22:11:11".to_string(),
                      sandbox: None,
                    },
                    Interface{
                      name: "eth0".to_string(),
                      mac: "00:11:22:33:44:66".to_string(),
                      sandbox: Some("/var/run/netns/blue".to_string()),
                    },
                  ],
                  routes: vec![
                    Route{
                      dst: "0.0.0.0/0".to_string(),
                      gw: None,
                      mtu: None,
                      advmss: None,
                    },
                  ],
                  dns: Some(Dns{
                    nameservers: vec!["10.1.0.1".to_string()],
                    domain: None,
                    search: None,
                    options: None,
                  }),
                }),
                custom: HashMap::new(),
            },
        ),
        case(
            // ref: https://github.com/containernetworking/cni/blob/b62753aa2bfa365c1ceaff6f25774a8047c896b5/SPEC.md#delete-example
            r#"{
  "cniVersion": "1.1.0",
  "name": "dbnet",
  "type": "portmap",
  "runtimeConfig": {
    "portMappings" : [
      { "hostPort": 8080, "containerPort": 80, "protocol": "tcp" }
    ]
  },
  "prevResult": {
    "ips": [
        {
          "address": "10.1.0.5/16",
          "gateway": "10.1.0.1",
          "interface": 2
        }
    ],
    "routes": [
      {
        "dst": "0.0.0.0/0"
      }
    ],
    "interfaces": [
        {
            "name": "cni0",
            "mac": "00:11:22:33:44:55"
        },
        {
            "name": "veth3243",
            "mac": "55:44:33:22:11:11"
        },
        {
            "name": "eth0",
            "mac": "00:11:22:33:44:66",
            "sandbox": "/var/run/netns/blue"
        }
    ],
    "dns": {
      "nameservers": [ "10.1.0.1" ]
    }
  }
}"#.to_string(),
            NetConf {
                cni_version: "1.1.0".to_string(),
                cni_versions: None,
                name: "dbnet".to_string(),
                r#type: "portmap".to_string(),
                disable_check: None,
                runtime_config: Some(RuntimeConf{
                    port_mappings: vec![
                        PortMapping{
                            host_port: 8080,
                            container_port: 80,
                            protocol: Some(Protocol::Tcp),
                        },
                    ],
                    custom: HashMap::new(),
                }),
                capabilities: None,
				ip_masq: None,
                ipam: None,
                dns: None,
                args: None,
                prev_result: Some(CNIResult{
                  ips: vec![
                    IpConfig{
                      interface: Some(2),
                      address: "10.1.0.5/16".to_string(),
                      gateway:Some("10.1.0.1".to_string()),
                    },
                  ],
                  interfaces: vec![
                    Interface{
                      name: "cni0".to_string(),
                      mac: "00:11:22:33:44:55".to_string(),
                      sandbox: None,
                    },
                    Interface{
                      name: "veth3243".to_string(),
                      mac: "55:44:33:22:11:11".to_string(),
                      sandbox: None,
                    },
                    Interface{
                      name: "eth0".to_string(),
                      mac: "00:11:22:33:44:66".to_string(),
                      sandbox: Some("/var/run/netns/blue".to_string()),
                    },
                  ],
                  routes: vec![
                    Route{
                      dst: "0.0.0.0/0".to_string(),
                      gw: None,
                      mtu: None,
                      advmss: None,
                    },
                  ],
                  dns: Some(Dns{
                    nameservers: vec!["10.1.0.1".to_string()],
                    domain: None,
                    search: None,
                    options: None,
                  }),
                }),
                custom: HashMap::new(),
            },
        ),
        case(
            // ref: https://github.com/containernetworking/cni/blob/b62753aa2bfa365c1ceaff6f25774a8047c896b5/SPEC.md#delete-example
            r#"{
  "cniVersion": "1.1.0",
  "name": "dbnet",
  "type": "tuning",
  "sysctl": {
    "net.core.somaxconn": "500"
  },
  "runtimeConfig": {
    "mac": "00:11:22:33:44:66"
  },
  "prevResult": {
    "ips": [
        {
          "address": "10.1.0.5/16",
          "gateway": "10.1.0.1",
          "interface": 2
        }
    ],
    "routes": [
      {
        "dst": "0.0.0.0/0"
      }
    ],
    "interfaces": [
        {
            "name": "cni0",
            "mac": "00:11:22:33:44:55"
        },
        {
            "name": "veth3243",
            "mac": "55:44:33:22:11:11"
        },
        {
            "name": "eth0",
            "mac": "00:11:22:33:44:66",
            "sandbox": "/var/run/netns/blue"
        }
    ],
    "dns": {
      "nameservers": [ "10.1.0.1" ]
    }
  }
}"#.to_string(),
            NetConf {
                cni_version: "1.1.0".to_string(),
                cni_versions: None,
                name: "dbnet".to_string(),
                r#type: "tuning".to_string(),
                disable_check: None,
                runtime_config: Some(RuntimeConf{
                    port_mappings: Vec::new(),
                    custom: HashMap::from([("mac".to_string(), serde_json::Value::String("00:11:22:33:44:66".to_string()))])
                }),
                capabilities: None,
				ip_masq: None,
                ipam: None,
                dns: None,
                args: None,
                prev_result: Some(CNIResult{
                  ips: vec![
                    IpConfig{
                      interface: Some(2),
                      address: "10.1.0.5/16".to_string(),
                      gateway:Some("10.1.0.1".to_string()),
                    },
                  ],
                  interfaces: vec![
                    Interface{
                      name: "cni0".to_string(),
                      mac: "00:11:22:33:44:55".to_string(),
                      sandbox: None,
                    },
                    Interface{
                      name: "veth3243".to_string(),
                      mac: "55:44:33:22:11:11".to_string(),
                      sandbox: None,
                    },
                    Interface{
                      name: "eth0".to_string(),
                      mac: "00:11:22:33:44:66".to_string(),
                      sandbox: Some("/var/run/netns/blue".to_string()),
                    },
                  ],
                  routes: vec![
                    Route{
                      dst: "0.0.0.0/0".to_string(),
                      gw: None,
                      mtu: None,
                      advmss: None,
                    },
                  ],
                  dns: Some(Dns{
                    nameservers: vec!["10.1.0.1".to_string()],
                    domain: None,
                    search: None,
                    options: None,
                  }),
                }),
                custom: HashMap::from([
                    ("sysctl".to_string(), json!({"net.core.somaxconn": "500"})),
                ]),
            },
        ),
        case(
            // ref: https://github.com/containernetworking/cni/blob/b62753aa2bfa365c1ceaff6f25774a8047c896b5/SPEC.md#delete-example
            r#"{
  "cniVersion": "1.1.0",
  "name": "dbnet",
  "type": "bridge",
  "bridge": "cni0",
  "keyA": ["some more", "plugin specific", "configuration"],
  "ipam": {
    "type": "host-local",
    "subnet": "10.1.0.0/16",
    "gateway": "10.1.0.1"
  },
  "dns": {
    "nameservers": [ "10.1.0.1" ]
  },
  "prevResult": {
    "ips": [
        {
          "address": "10.1.0.5/16",
          "gateway": "10.1.0.1",
          "interface": 2
        }
    ],
    "routes": [
      {
        "dst": "0.0.0.0/0"
      }
    ],
    "interfaces": [
        {
            "name": "cni0",
            "mac": "00:11:22:33:44:55"
        },
        {
            "name": "veth3243",
            "mac": "55:44:33:22:11:11"
        },
        {
            "name": "eth0",
            "mac": "00:11:22:33:44:66",
            "sandbox": "/var/run/netns/blue"
        }
    ],
    "dns": {
      "nameservers": [ "10.1.0.1" ]
    }
  }
}"#.to_string(),
            NetConf {
                cni_version: "1.1.0".to_string(),
                cni_versions: None,
                name: "dbnet".to_string(),
                r#type: "bridge".to_string(),
                disable_check: None,
                runtime_config: None,
                capabilities: None,
				ip_masq: None,
                ipam: Some(Ipam{
                    r#type: "host-local".to_string(),
                    custom: HashMap::from([
                        ("subnet".to_string(), serde_json::Value::String("10.1.0.0/16".to_string())),
                        ("gateway".to_string(), serde_json::Value::String("10.1.0.1".to_string())),
                    ]),
                }),
                dns: Some(Dns{
                    nameservers: vec!["10.1.0.1".to_string()],
                    domain: None,
                    search: None,
                    options: None
                }),
                args: None,
                prev_result: Some(CNIResult{
                  ips: vec![
                    IpConfig{
                      interface: Some(2),
                      address: "10.1.0.5/16".to_string(),
                      gateway:Some("10.1.0.1".to_string()),
                    },
                  ],
                  interfaces: vec![
                    Interface{
                      name: "cni0".to_string(),
                      mac: "00:11:22:33:44:55".to_string(),
                      sandbox: None,
                    },
                    Interface{
                      name: "veth3243".to_string(),
                      mac: "55:44:33:22:11:11".to_string(),
                      sandbox: None,
                    },
                    Interface{
                      name: "eth0".to_string(),
                      mac: "00:11:22:33:44:66".to_string(),
                      sandbox: Some("/var/run/netns/blue".to_string()),
                    },
                  ],
                  routes: vec![
                    Route{
                      dst: "0.0.0.0/0".to_string(),
                      gw: None,
                      mtu: None,
                      advmss: None,
                    },
                  ],
                  dns: Some(Dns{
                    nameservers: vec!["10.1.0.1".to_string()],
                    domain: None,
                    search: None,
                    options: None,
                  }),
                }),
                custom: HashMap::from([
                    ("bridge".to_string(), serde_json::Value::String("cni0".to_string())),
                    ("keyA".to_string(), serde_json::Value::Array(vec![serde_json::Value::String("some more".to_string()), serde_json::Value::String("plugin specific".to_string()), serde_json::Value::String("configuration".to_string())])),
                ]),
            },
        ),
        case(
          // ref: https://github.com/containernetworking/cni/blob/b62753aa2bfa365c1ceaff6f25774a8047c896b5/SPEC.md#check-example
            r#"{
  "cniVersion": "1.1.0",
  "name": "dbnet",
  "type": "bridge",
  "bridge": "cni0",
  "keyA": ["some more", "plugin specific", "configuration"],
  "ipam": {
    "type": "host-local",
    "subnet": "10.1.0.0/16",
    "gateway": "10.1.0.1"
  },
  "dns": {
    "nameservers": [ "10.1.0.1" ]
  },
  "prevResult": {
    "ips": [
        {
          "address": "10.1.0.5/16",
          "gateway": "10.1.0.1",
          "interface": 2
        }
    ],
    "routes": [
      {
        "dst": "0.0.0.0/0"
      }
    ],
    "interfaces": [
        {
            "name": "cni0",
            "mac": "00:11:22:33:44:55"
        },
        {
            "name": "veth3243",
            "mac": "55:44:33:22:11:11"
        },
        {
            "name": "eth0",
            "mac": "00:11:22:33:44:66",
            "sandbox": "/var/run/netns/blue"
        }
    ],
    "dns": {
      "nameservers": [ "10.1.0.1" ]
    }
  }
}"#.to_string(),
            NetConf {
                cni_version: "1.1.0".to_string(),
                cni_versions: None,
                name: "dbnet".to_string(),
                r#type: "bridge".to_string(),
                disable_check: None,
                runtime_config: None,
                capabilities: None,
				ip_masq: None,
                ipam: Some(Ipam{
                    r#type: "host-local".to_string(),
                    custom: HashMap::from([
                        ("subnet".to_string(), serde_json::Value::String("10.1.0.0/16".to_string())),
                        ("gateway".to_string(), serde_json::Value::String("10.1.0.1".to_string())),
                    ]),
                }),
                dns: Some(Dns{
                    nameservers: vec!["10.1.0.1".to_string()],
                    domain: None,
                    search: None,
                    options: None
                }),
                args: None,
                prev_result: Some(CNIResult{
                  ips: vec![
                    IpConfig{
                      interface: Some(2),
                      address: "10.1.0.5/16".to_string(),
                      gateway:Some("10.1.0.1".to_string()),
                    },
                  ],
                  interfaces: vec![
                    Interface{
                      name: "cni0".to_string(),
                      mac: "00:11:22:33:44:55".to_string(),
                      sandbox: None,
                    },
                    Interface{
                      name: "veth3243".to_string(),
                      mac: "55:44:33:22:11:11".to_string(),
                      sandbox: None,
                    },
                    Interface{
                      name: "eth0".to_string(),
                      mac: "00:11:22:33:44:66".to_string(),
                      sandbox: Some("/var/run/netns/blue".to_string()),
                    },
                  ],
                  routes: vec![
                    Route{
                      dst: "0.0.0.0/0".to_string(),
                      gw: None,
                      mtu: None,
                      advmss: None,
                    },
                  ],
                  dns: Some(Dns{
                    nameservers: vec!["10.1.0.1".to_string()],
                    domain: None,
                    search: None,
                    options: None,
                  }),
                }),
                custom: HashMap::from([
                    ("keyA".to_string(), serde_json::Value::Array(vec![serde_json::Value::String("some more".to_string()), serde_json::Value::String("plugin specific".to_string()), serde_json::Value::String("configuration".to_string())])),
                    ("bridge".to_string(), serde_json::Value::String("cni0".to_string())),
                ]),
            },
        ),
    )]
    fn deserialize_and_serialize_net_conf(input: String, expected: NetConf) {
        let conf: NetConf = serde_json::from_str(&input).unwrap();
        assert_eq!(expected, conf);

        let data = serde_json::to_string_pretty(&conf).unwrap();

        let conf_again: NetConf = serde_json::from_str(&data).unwrap();
        assert_eq!(expected, conf_again);
    }

    #[rstest(
      input,
      expected,
      case(
        // ref: https://github.com/containernetworking/cni/blob/b62753aa2bfa365c1ceaff6f25774a8047c896b5/SPEC.md#add-example
        r#"{
    "ips": [
        {
          "address": "10.1.0.5/16",
          "gateway": "10.1.0.1"
        }
    ],
    "routes": [
      {
        "dst": "0.0.0.0/0"
      }
    ],
    "dns": {
      "nameservers": [ "10.1.0.1" ]
    }
}"#.to_string(),
        CNIResult{
          interfaces: Vec::new(),
          ips: vec![IpConfig{
            interface: None,
            address: "10.1.0.5/16".to_string(),
            gateway: Some("10.1.0.1".to_string()),
          }],
          routes: vec![
            Route{
              dst: "0.0.0.0/0".to_string(),
              gw: None,
              mtu: None,
              advmss: None,
            },
          ],
          dns: Some(Dns{
            nameservers: vec!["10.1.0.1".to_string()],
            domain: None,
            search: None,
            options: None,
          })
        },
      ),
      case(
        // ref: https://github.com/containernetworking/cni/blob/b62753aa2bfa365c1ceaff6f25774a8047c896b5/SPEC.md#add-example
        r#"{
    "ips": [
        {
          "address": "10.1.0.5/16",
          "gateway": "10.1.0.1",
          "interface": 2
        }
    ],
    "routes": [
      {
        "dst": "0.0.0.0/0"
      }
    ],
    "interfaces": [
        {
            "name": "cni0",
            "mac": "00:11:22:33:44:55"
        },
        {
            "name": "veth3243",
            "mac": "55:44:33:22:11:11"
        },
        {
            "name": "eth0",
            "mac": "99:88:77:66:55:44",
            "sandbox": "/var/run/netns/blue"
        }
    ],
    "dns": {
      "nameservers": [ "10.1.0.1" ]
    }
}"#.to_string(),
        CNIResult{
          interfaces: vec![
            Interface{
              name: "cni0".to_string(),
              mac: "00:11:22:33:44:55".to_string(),
              sandbox: None,
            },
            Interface{
              name: "veth3243".to_string(),
              mac: "55:44:33:22:11:11".to_string(),
              sandbox: None,
            },
            Interface{
              name: "eth0".to_string(),
              mac: "99:88:77:66:55:44".to_string(),
              sandbox: Some("/var/run/netns/blue".to_string()),
            },
          ],
          ips: vec![IpConfig{
            interface: Some(2),
            address: "10.1.0.5/16".to_string(),
            gateway: Some("10.1.0.1".to_string()),
          }],
          routes: vec![
            Route{
              dst: "0.0.0.0/0".to_string(),
              gw: None,
              mtu: None,
              advmss: None,
            },
          ],
          dns: Some(Dns{
            nameservers: vec!["10.1.0.1".to_string()],
            domain: None,
            search: None,
            options: None,
          }),
        },
      ),
      case(
        // ref: https://github.com/containernetworking/cni/blob/b62753aa2bfa365c1ceaff6f25774a8047c896b5/SPEC.md#add-example
        r#"{
    "ips": [
        {
          "address": "10.1.0.5/16",
          "gateway": "10.1.0.1",
          "interface": 2
        }
    ],
    "routes": [
      {
        "dst": "0.0.0.0/0"
      }
    ],
    "interfaces": [
        {
            "name": "cni0",
            "mac": "00:11:22:33:44:55"
        },
        {
            "name": "veth3243",
            "mac": "55:44:33:22:11:11"
        },
        {
            "name": "eth0",
            "mac": "99:88:77:66:55:44",
            "sandbox": "/var/run/netns/blue"
        }
    ],
    "dns": {
      "nameservers": [ "10.1.0.1" ]
    }
}"#.to_string(),
        CNIResult{
          interfaces: vec![
            Interface{
              name: "cni0".to_string(),
              mac: "00:11:22:33:44:55".to_string(),
              sandbox: None,
            },
            Interface{
              name: "veth3243".to_string(),
              mac: "55:44:33:22:11:11".to_string(),
              sandbox: None,
            },
            Interface{
              name: "eth0".to_string(),
              mac: "99:88:77:66:55:44".to_string(),
              sandbox: Some("/var/run/netns/blue".to_string()),
            },
          ],
          ips: vec![IpConfig{
            interface: Some(2),
            address: "10.1.0.5/16".to_string(),
            gateway: Some("10.1.0.1".to_string()),
          }],
          routes: vec![
            Route{
              dst: "0.0.0.0/0".to_string(),
              gw: None,
              mtu: None,
              advmss: None,
            },
          ],
          dns: Some(Dns{
            nameservers: vec!["10.1.0.1".to_string()],
            domain: None,
            search: None,
            options: None,
          })
        },
      ),
    )]
    fn deserialize_and_serialize_success_result(input: String, expected: CNIResult) {
        let result: CNIResult = serde_json::from_str(&input).unwrap();
        assert_eq!(expected, result);

        let data = serde_json::to_string_pretty(&result).unwrap();

        let result_again: CNIResult = serde_json::from_str(&data).unwrap();
        assert_eq!(expected, result_again);
    }

    #[rstest]
    #[case(
        Interface {
            name: "eth0".to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            sandbox: Some("/var/run/netns/test".to_string()),
        },
        true
    )]
    #[case(
        Interface {
            name: "veth0".to_string(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            sandbox: None,
        },
        false
    )]
    fn test_interface_serialize(#[case] interface: Interface, #[case] has_sandbox: bool) {
        let json = serde_json::to_string(&interface).unwrap();
        if !has_sandbox {
            assert!(!json.contains("sandbox"));
        }
        let deserialized: Interface = serde_json::from_str(&json).unwrap();
        assert_eq!(interface, deserialized);
    }

    #[rstest]
    #[case(
        IpConfig {
            interface: Some(0),
            address: "192.168.1.10/24".to_string(),
            gateway: Some("192.168.1.1".to_string()),
        },
        true,
        true
    )]
    #[case(
        IpConfig {
            interface: None,
            address: "10.0.0.1/8".to_string(),
            gateway: None,
        },
        false,
        false
    )]
    fn test_ip_config_serialize(
        #[case] ip_config: IpConfig,
        #[case] has_interface: bool,
        #[case] has_gateway: bool,
    ) {
        let json = serde_json::to_string(&ip_config).unwrap();
        if !has_interface {
            assert!(!json.contains("interface"));
        }
        if !has_gateway {
            assert!(!json.contains("gateway"));
        }
        let deserialized: IpConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(ip_config, deserialized);
    }

    #[rstest]
    #[case(
        Route {
            dst: "0.0.0.0/0".to_string(),
            gw: Some("192.168.1.1".to_string()),
            mtu: Some(1500),
            advmss: Some(1460),
        },
        true,
        true
    )]
    #[case(
        Route {
            dst: "10.0.0.0/8".to_string(),
            gw: None,
            mtu: None,
            advmss: None,
        },
        false,
        false
    )]
    fn test_route_serialize(#[case] route: Route, #[case] has_gw: bool, #[case] has_mtu: bool) {
        let json = serde_json::to_string(&route).unwrap();
        if !has_gw {
            assert!(!json.contains("\"gw\""));
        }
        if !has_mtu {
            assert!(!json.contains("\"mtu\""));
        }
        let deserialized: Route = serde_json::from_str(&json).unwrap();
        assert_eq!(route, deserialized);
    }

    #[rstest]
    #[case(
        Dns {
            nameservers: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
            domain: Some("example.com".to_string()),
            search: Some(vec!["example.com".to_string(), "test.com".to_string()]),
            options: Some(vec!["ndots:5".to_string()]),
        },
        true,
        true,
        true
    )]
    #[case(
        Dns {
            nameservers: vec!["1.1.1.1".to_string()],
            domain: None,
            search: None,
            options: None,
        },
        false,
        false,
        false
    )]
    fn test_dns_serialize(
        #[case] dns: Dns,
        #[case] has_domain: bool,
        #[case] has_search: bool,
        #[case] has_options: bool,
    ) {
        let json = serde_json::to_string(&dns).unwrap();
        if !has_domain {
            assert!(!json.contains("\"domain\""));
        }
        if !has_search {
            assert!(!json.contains("\"search\""));
        }
        if !has_options {
            assert!(!json.contains("\"options\""));
        }
        let deserialized: Dns = serde_json::from_str(&json).unwrap();
        assert_eq!(dns, deserialized);
    }

    #[rstest]
    #[case(Protocol::Tcp, "tcp")]
    #[case(Protocol::Udp, "udp")]
    fn test_protocol_serialize(#[case] protocol: Protocol, #[case] expected: &str) {
        let json = serde_json::to_string(&protocol).unwrap();
        assert_eq!(json, format!("\"{}\"", expected));
        let deserialized: Protocol = serde_json::from_str(&json).unwrap();
        assert_eq!(protocol, deserialized);
    }

    #[rstest]
    #[case(
        PortMapping {
            host_port: 8080,
            container_port: 80,
            protocol: Some(Protocol::Tcp),
        },
        true
    )]
    #[case(
        PortMapping {
            host_port: 443,
            container_port: 443,
            protocol: None,
        },
        false
    )]
    fn test_port_mapping_serialize(#[case] port_mapping: PortMapping, #[case] has_protocol: bool) {
        let json = serde_json::to_string(&port_mapping).unwrap();
        if !has_protocol {
            assert!(!json.contains("\"protocol\""));
        }
        let deserialized: PortMapping = serde_json::from_str(&json).unwrap();
        assert_eq!(port_mapping, deserialized);
    }

    #[rstest]
    #[case(CNIResult::default(), false, false, false, false)]
    #[case(
        CNIResult {
            interfaces: vec![Interface {
                name: "eth0".to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                sandbox: None,
            }],
            ips: vec![IpConfig {
                interface: Some(0),
                address: "192.168.1.10/24".to_string(),
                gateway: Some("192.168.1.1".to_string()),
            }],
            routes: vec![Route {
                dst: "0.0.0.0/0".to_string(),
                gw: Some("192.168.1.1".to_string()),
                mtu: None,
                advmss: None,
            }],
            dns: Some(Dns {
                nameservers: vec!["8.8.8.8".to_string()],
                domain: None,
                search: None,
                options: None,
            }),
        },
        true,
        true,
        true,
        true
    )]
    fn test_cni_result_serialize(
        #[case] result: CNIResult,
        #[case] has_interfaces: bool,
        #[case] has_ips: bool,
        #[case] has_routes: bool,
        #[case] has_dns: bool,
    ) {
        let json = serde_json::to_string(&result).unwrap();

        if !has_interfaces {
            assert!(!json.contains("\"interfaces\""));
        }
        if !has_ips {
            assert!(!json.contains("\"ips\""));
        }
        if !has_routes {
            assert!(!json.contains("\"routes\""));
        }
        if !has_dns {
            assert!(!json.contains("\"dns\""));
        }

        let deserialized: CNIResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    #[rstest]
    #[case(
        Ipam {
            r#type: "host-local".to_string(),
            custom: HashMap::from([
                ("subnet".to_string(), json!("10.1.0.0/16")),
                ("gateway".to_string(), json!("10.1.0.1")),
            ]),
        },
        vec!["subnet", "gateway"]
    )]
    #[case(
        Ipam {
            r#type: "dhcp".to_string(),
            custom: HashMap::new(),
        },
        vec![]
    )]
    fn test_ipam_serialize(#[case] ipam: Ipam, #[case] expected_keys: Vec<&str>) {
        let json = serde_json::to_string(&ipam).unwrap();
        let deserialized: Ipam = serde_json::from_str(&json).unwrap();
        assert_eq!(ipam.r#type, deserialized.r#type);
        for key in expected_keys {
            assert_eq!(ipam.custom.get(key), deserialized.custom.get(key));
        }
    }

    #[rstest]
    #[case(
        RuntimeConf {
            port_mappings: vec![PortMapping {
                host_port: 8080,
                container_port: 80,
                protocol: Some(Protocol::Tcp),
            }],
            custom: HashMap::new(),
        }
    )]
    #[case(
        RuntimeConf {
            port_mappings: vec![],
            custom: HashMap::from([("mac".to_string(), json!("00:11:22:33:44:66"))]),
        }
    )]
    fn test_runtime_conf_serialize(#[case] runtime_conf: RuntimeConf) {
        let json = serde_json::to_string(&runtime_conf).unwrap();
        let deserialized: RuntimeConf = serde_json::from_str(&json).unwrap();
        assert_eq!(runtime_conf, deserialized);
    }

    #[rstest]
    #[case(
        r#"{
  "cniVersion": "1.0.0",
  "interfaces": [
    {
      "name": "eth0",
      "mac": "00:11:22:33:44:55",
      "sandbox": "/var/run/netns/test"
    }
  ],
  "ips": [
    {
      "address": "10.1.0.5/16",
      "gateway": "10.1.0.1",
      "interface": 0
    }
  ],
  "routes": [
    {
      "dst": "0.0.0.0/0"
    }
  ],
  "dns": {
    "nameservers": ["10.1.0.1"]
  }
}"#,
        "1.0.0",
        1,
        1,
        1,
        true
    )]
    #[case(
        r#"{
  "cniVersion": "1.1.0",
  "interfaces": [],
  "ips": [],
  "routes": []
}"#,
        "1.1.0",
        0,
        0,
        0,
        false
    )]
    fn test_cni_result_with_cni_version(
        #[case] input: &str,
        #[case] expected_version: &str,
        #[case] expected_interfaces: usize,
        #[case] expected_ips: usize,
        #[case] expected_routes: usize,
        #[case] has_dns: bool,
    ) {
        // CNI spec requires cniVersion in the success result
        // ref: https://github.com/containernetworking/cni/blob/v1.1.0/SPEC.md#success
        let result: super::CNIResultWithCNIVersion = serde_json::from_str(input).unwrap();
        assert_eq!(result.cni_version, expected_version);
        assert_eq!(result.inner.interfaces.len(), expected_interfaces);
        assert_eq!(result.inner.ips.len(), expected_ips);
        assert_eq!(result.inner.routes.len(), expected_routes);
        assert_eq!(result.inner.dns.is_some(), has_dns);
    }

    #[test]
    fn test_ipam_delegated_plugin_result() {
        // IPAM delegated plugins return abbreviated Success object without interfaces
        // ref: https://github.com/containernetworking/cni/blob/v1.1.0/SPEC.md#delegated-plugins-ipam
        let input = r#"{
  "ips": [
    {
      "address": "10.1.0.5/16",
      "gateway": "10.1.0.1"
    }
  ],
  "routes": [
    {
      "dst": "0.0.0.0/0"
    }
  ],
  "dns": {
    "nameservers": ["10.1.0.1"]
  }
}"#;

        let result: CNIResult = serde_json::from_str(input).unwrap();
        assert!(result.interfaces.is_empty());
        assert_eq!(result.ips.len(), 1);
        assert!(
            result.ips[0].interface.is_none(),
            "IPAM result should not have interface field in ips"
        );
        assert_eq!(result.routes.len(), 1);
        assert!(result.dns.is_some());
    }

    #[rstest]
    #[case(
        Route {
            dst: "192.168.0.0/16".to_string(),
            gw: Some("10.1.0.1".to_string()),
            mtu: Some(1500),
            advmss: Some(1460),
        },
        true,
        true
    )]
    #[case(
        Route {
            dst: "10.0.0.0/8".to_string(),
            gw: None,
            mtu: Some(9000),
            advmss: None,
        },
        true,
        false
    )]
    fn test_route_with_mtu_and_advmss(
        #[case] route: Route,
        #[case] has_mtu: bool,
        #[case] has_advmss: bool,
    ) {
        // Route can have mtu and advmss fields (not in spec examples but valid fields)
        let json = serde_json::to_string(&route).unwrap();
        if has_mtu {
            assert!(json.contains("\"mtu\""));
        }
        if has_advmss {
            assert!(json.contains("\"advmss\""));
        }

        let deserialized: Route = serde_json::from_str(&json).unwrap();
        assert_eq!(route, deserialized);
    }

    #[rstest]
    #[case(
        r#"{
  "cniVersion": "1.0.0",
  "name": "test",
  "type": "bridge",
  "ipMasq": true
}"#,
        Some(true)
    )]
    #[case(
        r#"{
  "cniVersion": "1.0.0",
  "name": "test",
  "type": "bridge",
  "ipMasq": false
}"#,
        Some(false)
    )]
    #[case(
        r#"{
  "cniVersion": "1.0.0",
  "name": "test",
  "type": "bridge"
}"#,
        None
    )]
    fn test_net_conf_with_ip_masq(#[case] input: &str, #[case] expected: Option<bool>) {
        // ipMasq is a well-known optional field
        // ref: https://github.com/containernetworking/cni/blob/v1.1.0/SPEC.md#plugin-configuration-objects
        let conf: NetConf = serde_json::from_str(input).unwrap();
        assert_eq!(conf.ip_masq, expected);

        let json = serde_json::to_string(&conf).unwrap();
        if expected.is_some() {
            assert!(json.contains("ipMasq"));
        } else {
            assert!(!json.contains("ipMasq"));
        }
    }

    #[rstest]
    #[case(
        Dns {
            nameservers: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
            domain: Some("example.com".to_string()),
            search: Some(vec![
                "example.com".to_string(),
                "corp.example.com".to_string(),
            ]),
            options: Some(vec!["ndots:5".to_string(), "timeout:1".to_string()]),
        },
        true,
        true,
        true
    )]
    #[case(
        Dns {
            nameservers: vec!["1.1.1.1".to_string()],
            domain: None,
            search: None,
            options: None,
        },
        false,
        false,
        false
    )]
    #[case(
        Dns {
            nameservers: vec!["10.0.0.1".to_string()],
            domain: Some("local".to_string()),
            search: None,
            options: Some(vec!["ndots:1".to_string()]),
        },
        true,
        false,
        true
    )]
    fn test_dns_all_fields(
        #[case] dns: Dns,
        #[case] has_domain: bool,
        #[case] has_search: bool,
        #[case] has_options: bool,
    ) {
        // Test DNS with all optional fields populated
        // ref: https://github.com/containernetworking/cni/blob/v1.1.0/SPEC.md#plugin-configuration-objects
        let json = serde_json::to_string(&dns).unwrap();
        let deserialized: Dns = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.nameservers, dns.nameservers);
        assert_eq!(deserialized.domain, dns.domain);
        assert_eq!(deserialized.search, dns.search);
        assert_eq!(deserialized.options, dns.options);

        assert_eq!(deserialized.domain.is_some(), has_domain);
        assert_eq!(deserialized.search.is_some(), has_search);
        assert_eq!(deserialized.options.is_some(), has_options);
    }
}
