use std::{collections::HashMap, path::PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Error;

pub(super) const CNI_COMMAND: &str = "CNI_COMMAND";
pub(super) const CNI_CONTAINERID: &str = "CNI_CONTAINERID";
pub(super) const CNI_NETNS: &str = "CNI_NETNS";
pub(super) const CNI_IFNAME: &str = "CNI_IFNAME";
pub(super) const CNI_ARGS: &str = "CNI_ARGS";
pub(super) const CNI_PATH: &str = "CNI_PATH";

/// Args is input data for the CNI call.
/// All fields except for `config` are given as environment values.
/// `config` field is given as a JSON format data([NetConf]) from stdin.
/// Depending on the type of command, some fields are omitted.
/// Please see <https://github.com/containernetworking/cni/blob/v1.1.0/SPEC.md#parameters> and <https://github.com/containernetworking/cni/blob/v1.1.0/SPEC.md#cni-operations>.
#[derive(Debug, Default, Clone)]
pub struct Args {
    /// Container ID. A unique plaintext identifier for a container, allocated by the runtime.
    /// Must not be empty.
    /// Must start with an alphanumeric character, optionally followed by any combination of one or more alphanumeric characters, underscore (), dot (.) or hyphen (-).
    pub container_id: String,
    /// A reference to the container's "isolation domain".
    /// If using network namespaces, then a path to the network namespace (e.g. /run/netns/[nsname]).
    pub netns: Option<PathBuf>,
    /// Name of the interface to create inside the container; if the plugin is unable to use this interface name it must return an error.
    pub ifname: String,
    /// Extra arguments passed in by the user at invocation time. Alphanumeric key-value pairs separated by semicolons.
    pub args: Option<String>,
    /// List of paths to search for CNI plugin executables. Paths are separated by an OS-specific list separator; for example ':' on Linux and ';' on Windows.
    pub path: Vec<PathBuf>,
    /// Please see [NetConf].
    pub config: Option<NetConf>,
}

/// NetConf will be given as a JSON serialized data from stdin when plugin is called.
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
    /// This allows an administrator to prevent CHECKing where a combination of plugins is known to return spurious errors.
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

/// NetConfList is a network configuration format for administrators.
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
    /// This allows an administrator to prevent CHECKing where a combination of plugins is known to return spurious errors.
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

/// CNIResult represents the Success result type.
/// CmdFm returns this if it finish successfully.
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

/// CNIResultWithCNIVersion represents actual output of CNI success result type as a JSON format.
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

/// ErrorResult is converted from Error.
/// This is actual data structure of Error CNI Result Type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResult {
    /// The same value as provided by the configuration.
    pub cni_version: String,
    /// A numeric error code.
    pub code: u32,
    /// A short message characterizing the error.
    pub msg: String,
    /// A longer message describing the error.
    pub details: String,
}

impl From<&ErrorResult> for Error {
    fn from(res: &ErrorResult) -> Self {
        if res.code > 100 {
            return Error::Custom(res.code, res.msg.clone(), res.details.clone());
        }
        match res.code {
            1 => Error::IncompatibleVersion(res.details.clone()),
            2 => Error::UnsupportedNetworkConfiguration(res.details.clone()),
            3 => Error::NotExist(res.details.clone()),
            4 => Error::InvalidEnvValue(res.details.clone()),
            5 => Error::IOFailure(res.details.clone()),
            6 => Error::FailedToDecode(res.details.clone()),
            7 => Error::InvalidNetworkConfig(res.details.clone()),
            11 => Error::TryAgainLater(res.details.clone()),
            _ => Error::FailedToDecode(format!("unknown error code: {}", res.code)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, vec};

    use rstest::rstest;
    use serde_json::json;

    use super::{
        CNIResult, Dns, Interface, IpConfig, Ipam, NetConf, PortMapping, Protocol, Route,
        RuntimeConf,
    };

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
}
