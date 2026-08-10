//! CNI specification types and data structures.
//!
//! This module contains all the types defined by the [CNI specification](https://www.cni.dev/),
//! including network configuration, results, and related structures.
//!
//! # Main Types
//!
//! - [`NetConf`] - Network configuration passed to the plugin
//! - [`NetConfList`] - A chain of network configurations (`.conflist`)
//! - [`CNIResult`] - Result returned by ADD/DEL/CHECK operations
//! - [`Interface`], [`IpConfig`], [`Route`] - Components of the CNI result
//! - [`Dns`], [`Ipam`] - Network configuration components
//! - [`Cmd`] - The operation being requested, i.e. the value of `CNI_COMMAND`
//!

use std::{collections::HashMap, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{error::Error, version::SpecVersion};

/// Name of the environment variable carrying the requested operation. See [`Cmd`].
pub const CNI_COMMAND: &str = "CNI_COMMAND";
/// Name of the environment variable carrying the container ID.
pub const CNI_CONTAINERID: &str = "CNI_CONTAINERID";
/// Name of the environment variable carrying the network namespace path.
pub const CNI_NETNS: &str = "CNI_NETNS";
/// Name of the environment variable carrying the interface name.
pub const CNI_IFNAME: &str = "CNI_IFNAME";
/// Name of the environment variable carrying extra `key=value;…` arguments.
pub const CNI_ARGS: &str = "CNI_ARGS";
/// Name of the environment variable carrying the plugin search path list.
pub const CNI_PATH: &str = "CNI_PATH";

/// The CNI operation being requested, i.e. the value of the [`CNI_COMMAND`]
/// environment variable.
///
/// There is deliberately no "unset" variant: an empty or missing `CNI_COMMAND` is not an
/// operation, so [`FromStr`] rejects `""` and callers decide what absence means (a plugin
/// prints its about text; a runtime always sets the variable).
///
/// Please see <https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#cni-operations>.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmd {
    Add,
    Del,
    Check,
    Gc,
    Status,
    Version,
}

impl FromStr for Cmd {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ADD" => Ok(Self::Add),
            "DEL" => Ok(Self::Del),
            "CHECK" => Ok(Self::Check),
            "GC" => Ok(Self::Gc),
            "STATUS" => Ok(Self::Status),
            "VERSION" => Ok(Self::Version),
            "" => Err(Error::InvalidEnvValue("CNI_COMMAND is not set".to_string())),
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
            Cmd::Gc => "GC",
            Cmd::Status => "STATUS",
            Cmd::Version => "VERSION",
        }
    }
}

/// Deserializes a JSON `null` as the type's default, making `null` equivalent to
/// omitting the key. Go plugins parse their stdin with `json.Unmarshal`, which no-ops
/// a `null` into the field's zero value, so on the plugin side of the protocol every
/// `"key": null` reads like an absent key; serde's `#[serde(default)]` covers only
/// absent keys and rejects a present `null` (serde-rs/serde#1098 — this is that
/// issue's canonical workaround).
///
/// The attribute belongs on the defaulted non-`Option` fields of the documents a
/// PLUGIN parses — [`NetConf`] and everything nested in it — where `Option` fields
/// accept `null` natively and required fields treat `null` as the error omission
/// already is. It does NOT belong on [`NetConfList`]: that document's reference
/// parser is libcni's conflist code, which type-asserts its keys and rejects `null`.
fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// Deserializes what libcni's conflist parser accepts for a boolean key: JSON
/// `true`/`false`, or those words as a string in any case.
fn bool_or_string<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Bool(bool),
        Str(String),
    }
    match Raw::deserialize(deserializer)? {
        Raw::Bool(b) => Ok(b),
        Raw::Str(s) if s.eq_ignore_ascii_case("true") => Ok(true),
        Raw::Str(s) if s.eq_ignore_ascii_case("false") => Ok(false),
        Raw::Str(s) => Err(serde::de::Error::custom(format!(
            "invalid value {s:?} for a boolean key"
        ))),
    }
}

/// Resolves a declared `cniVersion` value: empty — the in-memory form of an absent
/// key, a JSON `null`, and the empty string alike — means 0.1.0, the only version to
/// predate the key (added in 0.2.0).
fn declared_version(declared: &str) -> Result<SpecVersion, Error> {
    if declared.is_empty() {
        "0.1.0"
    } else {
        declared
    }
    .parse()
}

/// `NetConf` will be given as a JSON serialized data from stdin when plugin is called.
/// Please see <https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#section-1-network-configuration-format>.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct NetConf {
    /// Semantic Version 2.0 of CNI specification to which this configuration list and all the individual configurations conform.
    /// May be undeclared — the key predates spec 0.2.0; this type's `version()`
    /// resolves what that means.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub cni_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cni_versions: Option<Vec<String>>,
    /// Network name.
    /// This should be unique across all network configurations on a host (or other administrative domain).
    /// Must start with an alphanumeric character, optionally followed by any combination of one or more alphanumeric characters, underscore, dot (.) or hyphen (-).
    ///
    /// Defaulted, not required: a plugin object inside a `.conflist` has no `name`
    /// (the runtime injects the list's). The stdin document's name is checked by
    /// [`validate_name`](Self::validate_name) instead, which is error code 7 rather
    /// than a decode failure.
    #[serde(default, deserialize_with = "null_as_default")]
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
    /// See <https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#deriving-runtimeconfig>.
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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "cni.dev/valid-attachments"
    )]
    pub valid_attachments: Option<Vec<GcAttachment>>,
    #[serde(flatten)]
    pub custom: HashMap<String, Value>,
}

impl NetConf {
    /// Returns the CNI specification version this configuration declares, parsed;
    /// the implied 0.1.0 when the field is undeclared (absent, `null`, or empty).
    ///
    /// Parsing here rather than passing the raw string around means a malformed
    /// version fails once, at this boundary, for every operation alike; the trade-off
    /// is that formatting the result yields the canonical three-component form (see
    /// [`SpecVersion`]'s `Display`), not necessarily the string as spelled.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FailedToDecode`] if the declared version is malformed.
    pub fn version(&self) -> Result<SpecVersion, Error> {
        declared_version(&self.cni_version)
    }

    /// The character rule the specification states for network names and, identically,
    /// for container IDs: an ASCII alphanumeric, then alphanumerics, `_`, `.` and `-`.
    #[must_use]
    pub fn valid_name(value: &str) -> bool {
        let mut chars = value.chars();
        chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
            && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    }

    /// Checks that the network name is present and satisfies
    /// [`valid_name`](Self::valid_name), as both sides of the protocol do.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidNetworkConfig`] (error code 7).
    pub fn validate_name(&self) -> Result<(), Error> {
        if self.name.is_empty() {
            return Err(Error::InvalidNetworkConfig(
                "missing network name".to_string(),
            ));
        }
        if !Self::valid_name(&self.name) {
            return Err(Error::InvalidNetworkConfig(format!(
                "invalid characters found in network name: {}",
                self.name
            )));
        }
        Ok(())
    }
}

/// `NetConfList` is a network configuration format for administrators.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetConfList {
    /// Semantic Version 2.0 of CNI specification to which this configuration list and all the individual configurations conform.
    /// May be absent or empty — the key predates spec 0.2.0; this type's `version()`
    /// resolves what that means. A `null` is rejected: libcni's conflist parser
    /// type-asserts this key, so `null` is a decode error there, and the fields of
    /// this runtime-side document deliberately follow that parser rather than the
    /// `null`-tolerant `json.Unmarshal` semantics the plugin-side documents get.
    #[serde(default)]
    pub cni_version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cni_versions: Vec<String>,
    /// Network name.
    /// This should be unique across all network configurations on a host (or other administrative domain).
    /// Must start with an alphanumeric character, optionally followed by any combination of one or more alphanumeric characters, underscore, dot (.) or hyphen (-).
    pub name: String,
    /// Either true or false.
    /// If disableCheck is true, runtimes must not call CHECK for this network configuration list.
    /// This allows an administrator to prevent `CHECKing` where a combination of plugins is known to return spurious errors.
    ///
    #[serde(default, deserialize_with = "bool_or_string")] // default is false
    pub disable_check: bool,
    /// Either true or false.
    /// If disableGC is true, runtimes must not call GC for this network configuration list.
    /// (CNI spec 1.1.0; added in the spec revision shipped with CNI v1.2.1)
    // Explicit rename: `rename_all = "camelCase"` would produce `disableGc`.
    #[serde(default, deserialize_with = "bool_or_string", rename = "disableGC")]
    pub disable_gc: bool,
    /// Either true or false.
    /// If loadOnlyInlinedPlugins is true, runtimes must not load any plugins from the filesystem.
    /// (CNI spec 1.1.0; added in the spec revision shipped with CNI v1.3.0)
    #[serde(default, deserialize_with = "bool_or_string")] // default is false
    pub load_only_inlined_plugins: bool,
    /// A list of CNI plugins and their configuration, which is a list of plugin configuration objects.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plugins: Vec<NetConf>,
}

impl NetConfList {
    /// Returns the effective version, resolved like libcni: the highest of
    /// `cniVersions` and `cniVersion` that does not exceed [`SpecVersion::CURRENT`],
    /// falling back to `cniVersion` alone.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FailedToDecode`] if any declared version is malformed.
    pub fn version(&self) -> Result<SpecVersion, Error> {
        let declared = declared_version(&self.cni_version)?;
        let mut best = None;
        for candidate in self
            .cni_versions
            .iter()
            .map(|raw| raw.parse())
            .chain([Ok(declared)])
        {
            let candidate = candidate?;
            if candidate <= SpecVersion::CURRENT {
                best = best.max(Some(candidate));
            }
        }
        Ok(best.unwrap_or(declared))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GcAttachment {
    // Explicit rename: camelCase would give `containerId`, not the spec's `containerID`.
    #[serde(rename = "containerID")]
    pub container_id: String,
    pub ifname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeConf {
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
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
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Dns {
    /// List of a priority-ordered list of DNS nameservers that this network is aware of. Each entry in the list is a string containing either an IPv4 or an IPv6 address.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
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
    /// Route priority (for OSes that support it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
    /// Routing table ID (for OSes that support it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<u32>,
    /// Route scope (for OSes that support it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<u32>,
}

/// `CNIResult` represents the Success result type.
/// `CmdFm` returns this if it finish successfully.
/// Please see <https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#add-success>.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct CNIResult {
    /// In case of delegated plugins(IPAM), it may omit interfaces or ips sections.
    /// Please see <https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#delegated-plugins-ipam>.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub interfaces: Vec<Interface>,
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ips: Vec<IpConfig>,
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub routes: Vec<Route>,
    // Skipped when empty of content, not just when `None`: the reference
    // implementation drops an all-empty `dns` from the current-layout result.
    #[serde(default, skip_serializing_if = "dns_is_empty")]
    pub dns: Option<Dns>,
}

// `&Option<Dns>` is the signature `skip_serializing_if` calls with, not a style choice.
#[allow(clippy::ref_option)]
fn dns_is_empty(dns: &Option<Dns>) -> bool {
    dns.as_ref().is_none_or(|dns| {
        dns.nameservers.is_empty()
            && dns.domain.as_ref().is_none_or(String::is_empty)
            && dns.search.as_ref().is_none_or(Vec::is_empty)
            && dns.options.as_ref().is_none_or(Vec::is_empty)
    })
}

/// The wire form of a successful ADD result: a [`CNIResult`] plus the `cniVersion` key
/// the spec requires ("The same version supplied on input").
///
/// A plugin serializes this to stdout on a successful ADD; a runtime deserializes a
/// plugin's ADD output into it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CNIResultWithVersion {
    cni_version: SpecVersion,
    #[serde(flatten)]
    inner: CNIResult,
}

impl CNIResultWithVersion {
    /// Wraps a result with the `cniVersion` it should be reported under — per the
    /// spec, the version supplied in the input configuration.
    #[must_use]
    pub const fn new(version: SpecVersion, result: CNIResult) -> Self {
        Self {
            cni_version: version,
            inner: result,
        }
    }

    /// Returns the `cniVersion` the result is reported under.
    #[must_use]
    pub const fn cni_version(&self) -> SpecVersion {
        self.cni_version
    }

    /// Returns the wrapped result.
    #[must_use]
    pub const fn result(&self) -> &CNIResult {
        &self.inner
    }

    /// Unwraps into the plain result, discarding the version.
    #[must_use]
    pub fn into_result(self) -> CNIResult {
        self.inner
    }
}

/// The interface created by the attachment, including any host-level interfaces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Interface {
    /// The name of the interface.
    pub name: String,
    /// The hardware address of the interface, empty when not applicable. The key is
    /// optional on the wire: omitted when empty, accepted when missing or `null`.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub mac: String,
    /// The MTU of the interface (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    /// The isolation domain reference(e.g. path to network namespace) for the interface, or empty if on the host.
    /// For interfaces created inside the container, this should be the value passes via `CNI_NETNS`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<String>,
    /// An absolute path to a socket file corresponding to this interface, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<String>,
    /// The platform-specific identifier of the PCI device corresponding to this interface, if applicable.
    #[serde(skip_serializing_if = "Option::is_none", rename = "pciID")]
    pub pci_id: Option<String>,
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

/// A port-mapping transport protocol. Serializes lowercase, deserializes any casing,
/// like the reference `portmap` plugin.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
}

impl<'de> Deserialize<'de> for Protocol {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        if raw.eq_ignore_ascii_case("tcp") {
            Ok(Self::Tcp)
        } else if raw.eq_ignore_ascii_case("udp") {
            Ok(Self::Udp)
        } else if raw.eq_ignore_ascii_case("sctp") {
            Ok(Self::Sctp)
        } else {
            Err(serde::de::Error::custom(format!("unknown protocol: {raw}")))
        }
    }
}

/// The wire form of the CNI error result type.
///
/// Both sides of the error protocol go through this type: a failing plugin serializes
/// it to stdout (built with [`ErrorResult::new`]), and a runtime deserializes a failed
/// plugin's stdout into it and converts it back with `Error::from(&result)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResult {
    /// The same value as provided by the configuration.
    ///
    /// Defaulted on deserialization: the spec requires this key and this type emits
    /// it, but the reference implementation's error output has none.
    #[serde(default)]
    pub(crate) cni_version: String,
    /// A numeric error code.
    pub(crate) code: u32,
    /// A short message characterizing the error.
    pub(crate) msg: String,
    /// A longer message describing the error.
    ///
    /// Defaulted on deserialization: the reference implementation omits it when empty.
    #[serde(default)]
    pub(crate) details: String,
}

impl ErrorResult {
    /// Builds the wire form of `error`, reported under `cni_version`.
    ///
    /// The code comes from the error's CNI error code, the message from its `Display`
    /// form (which is defined as the wire `msg`), and the details from
    /// [`Error::details`]. Note the spec reserves codes 0-99; an [`Error::Custom`]
    /// carrying a reserved code is serialized as-is, and a runtime reading it back
    /// will interpret it as the reserved meaning.
    #[must_use]
    pub fn new(cni_version: impl Into<String>, error: &Error) -> Self {
        Self {
            cni_version: cni_version.into(),
            code: u32::from(error),
            msg: error.to_string(),
            details: error.details(),
        }
    }
}

impl From<&ErrorResult> for Error {
    fn from(res: &ErrorResult) -> Self {
        match res.code {
            1 => Self::IncompatibleVersion(res.details.clone()),
            2 => Self::UnsupportedNetworkConfiguration(res.details.clone()),
            3 => Self::NotExist(res.details.clone()),
            4 => Self::InvalidEnvValue(res.details.clone()),
            5 => Self::IOFailure(res.details.clone()),
            6 => Self::FailedToDecode(res.details.clone()),
            7 => Self::InvalidNetworkConfig(res.details.clone()),
            8 => Self::InvalidNetNS(res.details.clone()),
            11 => Self::TryAgainLater(res.details.clone()),
            50 => Self::PluginNotAvailable(res.details.clone()),
            51 => Self::PluginNotAvailableLimitedConnectivity(res.details.clone()),
            // Plugin-defined codes and reserved ones without a variant alike: kept
            // verbatim, since rewriting them would misreport what the plugin said.
            // Only minting new errors is restricted to the >= 100 band.
            code => Self::Custom(code, res.msg.clone(), res.details.clone()),
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
        CNIResult, Cmd, Dns, GcAttachment, Interface, IpConfig, Ipam, NetConf, NetConfList,
        PortMapping, Protocol, Route, RuntimeConf,
    };

    #[rstest]
    #[case("ADD", Cmd::Add)]
    #[case("DEL", Cmd::Del)]
    #[case("CHECK", Cmd::Check)]
    #[case("GC", Cmd::Gc)]
    #[case("STATUS", Cmd::Status)]
    #[case("VERSION", Cmd::Version)]
    fn test_cmd_from_str(
        #[case] input: &str,
        #[case] expected: Cmd,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(Cmd::from_str(input)?, expected);
        Ok(())
    }

    #[rstest]
    #[case("INVALID", "unknown CNI_COMMAND")]
    #[case("", "CNI_COMMAND is not set")]
    fn test_cmd_from_str_invalid(#[case] input: &str, #[case] expected_msg: &str) {
        let result = Cmd::from_str(input);
        assert!(result.is_err());
        if let Err(Error::InvalidEnvValue(msg)) = result {
            assert!(msg.contains(expected_msg));
        } else {
            panic!("Expected InvalidEnvValue error");
        }
    }

    #[rstest]
    #[case(Cmd::Add, "ADD")]
    #[case(Cmd::Del, "DEL")]
    #[case(Cmd::Check, "CHECK")]
    #[case(Cmd::Gc, "GC")]
    #[case(Cmd::Version, "VERSION")]
    fn test_cmd_to_str(#[case] cmd: Cmd, #[case] expected: &str) {
        let result: &str = cmd.into();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_gc_attachment_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let attachment = GcAttachment {
            container_id: "container-123".to_string(),
            ifname: "eth0".to_string(),
        };
        let json = serde_json::to_string(&attachment)?;
        let expected = r#"{"containerID":"container-123","ifname":"eth0"}"#;
        assert_eq!(json, expected);

        let deserialized: GcAttachment = serde_json::from_str(&json)?;
        assert_eq!(deserialized.container_id, "container-123");
        assert_eq!(deserialized.ifname, "eth0");
        Ok(())
    }

    // The stdin document (NetConf and everything nested in it) is parsed by Go
    // plugins with json.Unmarshal, which reads `null` like an omitted key: absent,
    // `null`, and empty all resolve to the implied 0.1.0 (the key predates spec
    // 0.2.0), and `null` on any nested defaulted field decodes as its default.
    #[rstest]
    #[case::absent(r#"{"name":"n","type":"b"}"#)]
    #[case::null(r#"{"cniVersion":null,"name":"n","type":"b"}"#)]
    #[case::empty(r#"{"cniVersion":"","name":"n","type":"b"}"#)]
    #[case::nested_nulls(
        r#"{"cniVersion":null,"name":"n","type":"b",
            "runtimeConfig":{"portMappings":null},
            "dns":{"nameservers":null},
            "prevResult":{"interfaces":null,"ips":null,"routes":null,"dns":null}}"#
    )]
    fn test_net_conf_undeclared_version_means_010(
        #[case] json: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let conf: NetConf = serde_json::from_str(json)?;
        assert_eq!(conf.version()?.to_string(), "0.1.0");
        Ok(())
    }

    // The conflist is the runtime-side document; its reference parser (libcni's
    // conflist code) type-asserts its keys, so absent and empty resolve to 0.1.0 but
    // an explicit `null` is a decode error there — and here.
    #[rstest]
    #[case::absent(r#"{"name":"n"}"#, true)]
    #[case::empty(r#"{"cniVersion":"","name":"n"}"#, true)]
    #[case::null(r#"{"cniVersion":null,"name":"n"}"#, false)]
    fn test_net_conf_list_undeclared_version(
        #[case] json: &str,
        #[case] decodes: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match serde_json::from_str::<NetConfList>(json) {
            Ok(list) => {
                assert!(decodes, "null must be rejected like libcni does");
                assert_eq!(list.version()?.to_string(), "0.1.0");
            }
            Err(_) => assert!(!decodes, "absent/empty must decode"),
        }
        Ok(())
    }

    #[test]
    fn test_net_conf_with_valid_attachments() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "cniVersion": "1.1.0",
            "name": "test-network",
            "type": "bridge",
            "cni.dev/valid-attachments": [
                {"containerID": "container-1", "ifname": "eth0"},
                {"containerID": "container-2", "ifname": "eth1"}
            ]
        }"#;

        let conf: NetConf = serde_json::from_str(json)?;
        assert_eq!(conf.cni_version, "1.1.0");
        assert_eq!(conf.name, "test-network");
        assert_eq!(conf.r#type, "bridge");
        let attachments = conf
            .valid_attachments
            .ok_or("validAttachments should be present")?;
        assert_eq!(attachments.len(), 2);
        assert_eq!(attachments[0].container_id, "container-1");
        assert_eq!(attachments[0].ifname, "eth0");
        assert_eq!(attachments[1].container_id, "container-2");
        assert_eq!(attachments[1].ifname, "eth1");

        // Test serialization
        let conf_with_attachments = NetConf {
            cni_version: "1.1.0".to_string(),
            cni_versions: None,
            name: "test-network".to_string(),
            r#type: "bridge".to_string(),
            disable_check: None,
            runtime_config: None,
            capabilities: None,
            ip_masq: None,
            ipam: None,
            dns: None,
            args: None,
            prev_result: None,
            valid_attachments: Some(vec![GcAttachment {
                container_id: "container-1".to_string(),
                ifname: "eth0".to_string(),
            }]),
            custom: HashMap::new(),
        };
        let serialized = serde_json::to_value(&conf_with_attachments)?;
        assert!(serialized["cni.dev/valid-attachments"].is_array());
        assert_eq!(
            serialized["cni.dev/valid-attachments"][0]["containerID"],
            "container-1"
        );
        Ok(())
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
                valid_attachments: None,
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
                valid_attachments: None,
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
                valid_attachments: None,
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
                      mtu: None,
                      socket_path: None,
                      pci_id: None,
                    },
                    Interface{
                      name: "veth3243".to_string(),
                      mac: "55:44:33:22:11:11".to_string(),
                      sandbox: None,
                      mtu: None,
                      socket_path: None,
                      pci_id: None,
                    },
                    Interface{
                      name: "eth0".to_string(),
                      mac: "99:88:77:66:55:44".to_string(),
                      sandbox: Some("/var/run/netns/blue".to_string()),
                      mtu: None,
                      socket_path: None,
                      pci_id: None,
                    },
                  ],
                  routes: vec![
                    Route{
                      dst: "0.0.0.0/0".to_string(),
                      gw: None,
                      mtu: None,
                      advmss: None,
                      priority: None,
                      table: None,
                      scope: None,
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
                valid_attachments: None,
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
                      mtu: None,
                      socket_path: None,
                      pci_id: None,
                    },
                    Interface{
                      name: "veth3243".to_string(),
                      mac: "55:44:33:22:11:11".to_string(),
                      sandbox: None,
                      mtu: None,
                      socket_path: None,
                      pci_id: None,
                    },
                    Interface{
                      name: "eth0".to_string(),
                      mac: "00:11:22:33:44:66".to_string(),
                      sandbox: Some("/var/run/netns/blue".to_string()),
                      mtu: None,
                      socket_path: None,
                      pci_id: None,
                    },
                  ],
                  routes: vec![
                    Route{
                      dst: "0.0.0.0/0".to_string(),
                      gw: None,
                      mtu: None,
                      advmss: None,
                      priority: None,
                      table: None,
                      scope: None,
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
                valid_attachments: None,
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
                      mtu: None,
                      socket_path: None,
                      pci_id: None,
                    },
                    Interface{
                      name: "veth3243".to_string(),
                      mac: "55:44:33:22:11:11".to_string(),
                      sandbox: None,
                      mtu: None,
                      socket_path: None,
                      pci_id: None,
                    },
                    Interface{
                      name: "eth0".to_string(),
                      mac: "00:11:22:33:44:66".to_string(),
                      sandbox: Some("/var/run/netns/blue".to_string()),
                      mtu: None,
                      socket_path: None,
                      pci_id: None,
                    },
                  ],
                  routes: vec![
                    Route{
                      dst: "0.0.0.0/0".to_string(),
                      gw: None,
                      mtu: None,
                      advmss: None,
                      priority: None,
                      table: None,
                      scope: None,
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
                valid_attachments: None,
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
                      mtu: None,
                      socket_path: None,
                      pci_id: None,
                    },
                    Interface{
                      name: "veth3243".to_string(),
                      mac: "55:44:33:22:11:11".to_string(),
                      sandbox: None,
                      mtu: None,
                      socket_path: None,
                      pci_id: None,
                    },
                    Interface{
                      name: "eth0".to_string(),
                      mac: "00:11:22:33:44:66".to_string(),
                      sandbox: Some("/var/run/netns/blue".to_string()),
                      mtu: None,
                      socket_path: None,
                      pci_id: None,
                    },
                  ],
                  routes: vec![
                    Route{
                      dst: "0.0.0.0/0".to_string(),
                      gw: None,
                      mtu: None,
                      advmss: None,
                      priority: None,
                      table: None,
                      scope: None,
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
                valid_attachments: None,
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
                      mtu: None,
                      socket_path: None,
                      pci_id: None,
                    },
                    Interface{
                      name: "veth3243".to_string(),
                      mac: "55:44:33:22:11:11".to_string(),
                      sandbox: None,
                      mtu: None,
                      socket_path: None,
                      pci_id: None,
                    },
                    Interface{
                      name: "eth0".to_string(),
                      mac: "00:11:22:33:44:66".to_string(),
                      sandbox: Some("/var/run/netns/blue".to_string()),
                      mtu: None,
                      socket_path: None,
                      pci_id: None,
                    },
                  ],
                  routes: vec![
                    Route{
                      dst: "0.0.0.0/0".to_string(),
                      gw: None,
                      mtu: None,
                      advmss: None,
                      priority: None,
                      table: None,
                      scope: None,
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
                valid_attachments: None,
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
                      mtu: None,
                      socket_path: None,
                      pci_id: None,
                    },
                    Interface{
                      name: "veth3243".to_string(),
                      mac: "55:44:33:22:11:11".to_string(),
                      sandbox: None,
                      mtu: None,
                      socket_path: None,
                      pci_id: None,
                    },
                    Interface{
                      name: "eth0".to_string(),
                      mac: "00:11:22:33:44:66".to_string(),
                      sandbox: Some("/var/run/netns/blue".to_string()),
                      mtu: None,
                      socket_path: None,
                      pci_id: None,
                    },
                  ],
                  routes: vec![
                    Route{
                      dst: "0.0.0.0/0".to_string(),
                      gw: None,
                      mtu: None,
                      advmss: None,
                      priority: None,
                      table: None,
                      scope: None,
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
                valid_attachments: None,
            },
        ),
    )]
    fn deserialize_and_serialize_net_conf(
        input: String,
        expected: NetConf,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let conf: NetConf = serde_json::from_str(&input)?;
        assert_eq!(expected, conf);

        let data = serde_json::to_string_pretty(&conf)?;

        let conf_again: NetConf = serde_json::from_str(&data)?;
        assert_eq!(expected, conf_again);
        Ok(())
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
              priority: None,
              table: None,
              scope: None,
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
              mtu: None,
              socket_path: None,
              pci_id: None,
            },
            Interface{
              name: "veth3243".to_string(),
              mac: "55:44:33:22:11:11".to_string(),
              sandbox: None,
              mtu: None,
              socket_path: None,
              pci_id: None,
            },
            Interface{
              name: "eth0".to_string(),
              mac: "99:88:77:66:55:44".to_string(),
              sandbox: Some("/var/run/netns/blue".to_string()),
              mtu: None,
              socket_path: None,
              pci_id: None,
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
              priority: None,
              table: None,
              scope: None,
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
              mtu: None,
              socket_path: None,
              pci_id: None,
            },
            Interface{
              name: "veth3243".to_string(),
              mac: "55:44:33:22:11:11".to_string(),
              sandbox: None,
              mtu: None,
              socket_path: None,
              pci_id: None,
            },
            Interface{
              name: "eth0".to_string(),
              mac: "99:88:77:66:55:44".to_string(),
              sandbox: Some("/var/run/netns/blue".to_string()),
              mtu: None,
              socket_path: None,
              pci_id: None,
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
              priority: None,
              table: None,
              scope: None,
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
    fn deserialize_and_serialize_success_result(
        input: String,
        expected: CNIResult,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let result: CNIResult = serde_json::from_str(&input)?;
        assert_eq!(expected, result);

        let data = serde_json::to_string_pretty(&result)?;

        let result_again: CNIResult = serde_json::from_str(&data)?;
        assert_eq!(expected, result_again);
        Ok(())
    }

    #[rstest]
    // Basic interface with sandbox only
    #[case(
        Interface {
            name: "eth0".to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            sandbox: Some("/var/run/netns/test".to_string()),
            mtu: None,
            socket_path: None,
            pci_id: None,
        }
    )]
    // Minimal interface without optional fields
    #[case(
        Interface {
            name: "veth0".to_string(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            sandbox: None,
            mtu: None,
            socket_path: None,
            pci_id: None,
        }
    )]
    // Interface with MTU (CNI v1.1.0+)
    #[case(
        Interface {
            name: "eth1".to_string(),
            mac: "00:11:22:33:44:66".to_string(),
            mtu: Some(1500),
            sandbox: Some("/var/run/netns/test".to_string()),
            socket_path: None,
            pci_id: None,
        }
    )]
    // Interface with socket_path for vhost-user (CNI v1.1.0+)
    #[case(
        Interface {
            name: "tap0".to_string(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            mtu: None,
            sandbox: None,
            socket_path: Some("/var/run/vhost-user/tap0.sock".to_string()),
            pci_id: None,
        }
    )]
    // Interface with PCI device ID (CNI v1.1.0+)
    #[case(
        Interface {
            name: "net0".to_string(),
            mac: "11:22:33:44:55:66".to_string(),
            mtu: Some(9000),
            sandbox: Some("/var/run/netns/container1".to_string()),
            socket_path: None,
            pci_id: Some("0000:03:00.0".to_string()),
        }
    )]
    // Interface with all optional fields
    #[case(
        Interface {
            name: "eth2".to_string(),
            mac: "ff:ee:dd:cc:bb:aa".to_string(),
            mtu: Some(1500),
            sandbox: Some("/var/run/netns/test".to_string()),
            socket_path: Some("/var/run/socket/eth1.sock".to_string()),
            pci_id: Some("0000:04:00.1".to_string()),
        }
    )]
    fn test_interface_serialize(
        #[case] interface: Interface,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Serialize to JSON
        let json = serde_json::to_string(&interface)?;

        // Verify basic fields are always present
        assert!(json.contains(&format!("\"name\":\"{}\"", interface.name)));
        assert!(json.contains(&format!("\"mac\":\"{}\"", interface.mac)));

        // Verify optional fields serialization with correct camelCase naming
        if let Some(ref mtu) = interface.mtu {
            assert!(json.contains(&format!("\"mtu\":{mtu}")));
        } else {
            assert!(!json.contains("\"mtu\""));
        }

        if let Some(ref sandbox) = interface.sandbox {
            assert!(json.contains(&format!("\"sandbox\":\"{sandbox}\"")));
        } else {
            assert!(!json.contains("\"sandbox\""));
        }

        if let Some(ref socket_path) = interface.socket_path {
            assert!(json.contains(&format!("\"socketPath\":\"{socket_path}\"")));
        } else {
            assert!(!json.contains("\"socketPath\""));
        }

        if let Some(ref pci_id) = interface.pci_id {
            assert!(json.contains(&format!("\"pciID\":\"{pci_id}\"")));
        } else {
            assert!(!json.contains("\"pciID\""));
        }

        // Verify round-trip serialization
        let deserialized: Interface = serde_json::from_str(&json)?;
        assert_eq!(interface, deserialized);
        Ok(())
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(&ip_config)?;
        if !has_interface {
            assert!(!json.contains("interface"));
        }
        if !has_gateway {
            assert!(!json.contains("gateway"));
        }
        let deserialized: IpConfig = serde_json::from_str(&json)?;
        assert_eq!(ip_config, deserialized);
        Ok(())
    }

    #[rstest]
    #[case(
        Route {
            dst: "0.0.0.0/0".to_string(),
            gw: Some("192.168.1.1".to_string()),
            mtu: Some(1500),
            advmss: Some(1460),
            priority: None,
            table: None,
            scope: None,
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
            priority: None,
            table: None,
            scope: None,
        },
        false,
        false
    )]
    fn test_route_serialize(
        #[case] route: Route,
        #[case] has_gw: bool,
        #[case] has_mtu: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(&route)?;
        if !has_gw {
            assert!(!json.contains("\"gw\""));
        }
        if !has_mtu {
            assert!(!json.contains("\"mtu\""));
        }
        let deserialized: Route = serde_json::from_str(&json)?;
        assert_eq!(route, deserialized);
        Ok(())
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(&dns)?;
        if !has_domain {
            assert!(!json.contains("\"domain\""));
        }
        if !has_search {
            assert!(!json.contains("\"search\""));
        }
        if !has_options {
            assert!(!json.contains("\"options\""));
        }
        let deserialized: Dns = serde_json::from_str(&json)?;
        assert_eq!(dns, deserialized);
        Ok(())
    }

    #[rstest]
    #[case(Protocol::Tcp, "tcp")]
    #[case(Protocol::Udp, "udp")]
    fn test_protocol_serialize(
        #[case] protocol: Protocol,
        #[case] expected: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(&protocol)?;
        assert_eq!(json, format!("\"{expected}\""));
        let deserialized: Protocol = serde_json::from_str(&json)?;
        assert_eq!(protocol, deserialized);
        Ok(())
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
    fn test_port_mapping_serialize(
        #[case] port_mapping: PortMapping,
        #[case] has_protocol: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(&port_mapping)?;
        if !has_protocol {
            assert!(!json.contains("\"protocol\""));
        }
        let deserialized: PortMapping = serde_json::from_str(&json)?;
        assert_eq!(port_mapping, deserialized);
        Ok(())
    }

    #[rstest]
    #[case(CNIResult::default(), false, false, false, false)]
    #[case(
        CNIResult {
            interfaces: vec![Interface {
                name: "eth0".to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                sandbox: None,
                mtu: None,
                socket_path: None,
                pci_id: None,
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
                priority: None,
                table: None,
                scope: None,
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(&result)?;

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

        let deserialized: CNIResult = serde_json::from_str(&json)?;
        assert_eq!(result, deserialized);
        Ok(())
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
    fn test_ipam_serialize(
        #[case] ipam: Ipam,
        #[case] expected_keys: Vec<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(&ipam)?;
        let deserialized: Ipam = serde_json::from_str(&json)?;
        assert_eq!(ipam.r#type, deserialized.r#type);
        for key in expected_keys {
            assert_eq!(ipam.custom.get(key), deserialized.custom.get(key));
        }
        Ok(())
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
    fn test_runtime_conf_serialize(
        #[case] runtime_conf: RuntimeConf,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(&runtime_conf)?;
        let deserialized: RuntimeConf = serde_json::from_str(&json)?;
        assert_eq!(runtime_conf, deserialized);
        Ok(())
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        // CNI spec requires cniVersion in the success result
        // ref: https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#add-success
        let result: super::CNIResultWithVersion = serde_json::from_str(input)?;
        assert_eq!(result.cni_version.to_string(), expected_version);
        assert_eq!(result.inner.interfaces.len(), expected_interfaces);
        assert_eq!(result.inner.ips.len(), expected_ips);
        assert_eq!(result.inner.routes.len(), expected_routes);
        assert_eq!(result.inner.dns.is_some(), has_dns);
        Ok(())
    }

    #[test]
    fn test_ipam_delegated_plugin_result() -> Result<(), Box<dyn std::error::Error>> {
        // IPAM delegated plugins return abbreviated Success object without interfaces
        // ref: https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#delegated-plugins-ipam
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

        let result: CNIResult = serde_json::from_str(input)?;
        assert!(result.interfaces.is_empty());
        assert_eq!(result.ips.len(), 1);
        assert!(
            result.ips[0].interface.is_none(),
            "IPAM result should not have interface field in ips"
        );
        assert_eq!(result.routes.len(), 1);
        assert!(result.dns.is_some());
        Ok(())
    }

    #[rstest]
    #[case(
        Route {
            dst: "192.168.0.0/16".to_string(),
            gw: Some("10.1.0.1".to_string()),
            mtu: Some(1500),
            advmss: Some(1460),
            priority: None,
            table: None,
            scope: None,
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
            priority: None,
            table: None,
            scope: None,
        },
        true,
        false
    )]
    fn test_route_with_mtu_and_advmss(
        #[case] route: Route,
        #[case] has_mtu: bool,
        #[case] has_advmss: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Route can have mtu and advmss fields (not in spec examples but valid fields)
        let json = serde_json::to_string(&route)?;
        if has_mtu {
            assert!(json.contains("\"mtu\""));
        }
        if has_advmss {
            assert!(json.contains("\"advmss\""));
        }

        let deserialized: Route = serde_json::from_str(&json)?;
        assert_eq!(route, deserialized);
        Ok(())
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
    fn test_net_conf_with_ip_masq(
        #[case] input: &str,
        #[case] expected: Option<bool>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // ipMasq is a well-known optional field
        // ref: https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#plugin-configuration-objects
        let conf: NetConf = serde_json::from_str(input)?;
        assert_eq!(conf.ip_masq, expected);

        let json = serde_json::to_string(&conf)?;
        if expected.is_some() {
            assert!(json.contains("ipMasq"));
        } else {
            assert!(!json.contains("ipMasq"));
        }
        Ok(())
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Test DNS with all optional fields populated
        // ref: https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#plugin-configuration-objects
        let json = serde_json::to_string(&dns)?;
        let deserialized: Dns = serde_json::from_str(&json)?;

        assert_eq!(deserialized.nameservers, dns.nameservers);
        assert_eq!(deserialized.domain, dns.domain);
        assert_eq!(deserialized.search, dns.search);
        assert_eq!(deserialized.options, dns.options);

        assert_eq!(deserialized.domain.is_some(), has_domain);
        assert_eq!(deserialized.search.is_some(), has_search);
        assert_eq!(deserialized.options.is_some(), has_options);
        Ok(())
    }
}
