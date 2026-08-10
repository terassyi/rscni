//! The ADD success result in the wire layout that specification versions 0.3.0
//! through 0.4.0 share — what the reference implementation calls `types040`.
//!
//! Compared to the current layout, `ips[].version` (`"4"`/`"6"`) is mandatory and
//! derived from the address family, and the fields 1.1.0 added to interfaces and
//! routes do not exist — which the structs here guarantee by not having them. The
//! conversion mirrors the reference implementation's `convertTo04x`.
//!
//! A plugin serializes [`CNIResult`] to stdout when the negotiated version
//! [`is_legacy`](SpecVersion::is_legacy). Versions before 0.3.0 had yet another,
//! `ip4`/`ip6`-shaped layout; no maintained runtime issues those versions, and this
//! crate does not represent that layout.

use serde::Serialize;

use crate::{types, version::SpecVersion};

/// [`types::CNIResult`] in the legacy layout, with the `cniVersion` key it is
/// reported under.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CNIResult {
    cni_version: SpecVersion,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    interfaces: Vec<Interface>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ips: Vec<IpConfig>,
    // Whole routes, extra attributes included: the reference implementation shares
    // one route type between the layouts and marshals every field.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    routes: Vec<types::Route>,
    // Always serialized: this layout has no empty-dns fixup, so `"dns": {}` appears
    // even when empty.
    dns: types::Dns,
}

impl CNIResult {
    /// Converts a result into the legacy layout, reported under `version` — one for
    /// which [`is_legacy`](SpecVersion::is_legacy) holds; nothing checks that here.
    #[must_use]
    pub fn new(version: SpecVersion, result: types::CNIResult) -> Self {
        Self {
            cni_version: version,
            interfaces: result.interfaces.into_iter().map(Into::into).collect(),
            ips: result.ips.into_iter().map(Into::into).collect(),
            routes: result.routes,
            dns: result.dns.unwrap_or_default(),
        }
    }
}

/// [`types::Interface`] without the fields 1.1.0 added.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Interface {
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    mac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sandbox: Option<String>,
}

impl From<types::Interface> for Interface {
    fn from(interface: types::Interface) -> Self {
        Self {
            name: interface.name,
            mac: interface.mac,
            sandbox: interface.sandbox,
        }
    }
}

/// [`types::IpConfig`] plus the mandatory address-family marker of this layout.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IpConfig {
    version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface: Option<u32>,
    address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway: Option<String>,
}

impl From<types::IpConfig> for IpConfig {
    fn from(ip: types::IpConfig) -> Self {
        Self {
            version: Self::address_family(&ip.address),
            interface: ip.interface,
            address: ip.address,
            gateway: ip.gateway,
        }
    }
}

impl IpConfig {
    /// The family marker for a CIDR-notation address. An IPv4-mapped IPv6 address
    /// counts as IPv4, as in the reference; unparseable text falls back to the colon.
    fn address_family(address: &str) -> &'static str {
        use std::net::IpAddr;

        let ip = address.split_once('/').map_or(address, |(ip, _)| ip);
        match ip.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => "4",
            Ok(IpAddr::V6(v6)) if v6.to_ipv4_mapped().is_some() => "4",
            Ok(IpAddr::V6(_)) => "6",
            Err(_) => {
                if ip.contains(':') {
                    "6"
                } else {
                    "4"
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::CNIResult;
    use crate::types;

    #[test]
    fn legacy_layout_matches_the_reference_conversion() -> Result<(), Box<dyn std::error::Error>> {
        // A result exercising every field the conversion must drop or derive:
        // ips[].version comes from the address family, the fields 1.1.0 added to
        // interfaces and routes disappear, everything else passes through.
        let result = types::CNIResult {
            interfaces: vec![types::Interface {
                name: "eth0".to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                mtu: Some(1500),
                sandbox: Some("/var/run/netns/test".to_string()),
                socket_path: Some("/run/vhost.sock".to_string()),
                pci_id: Some("0000:00:1f.6".to_string()),
            }],
            ips: vec![
                types::IpConfig {
                    interface: Some(0),
                    address: "10.1.0.5/16".to_string(),
                    gateway: Some("10.1.0.1".to_string()),
                },
                types::IpConfig {
                    interface: None,
                    address: "fd00::2/64".to_string(),
                    gateway: None,
                },
            ],
            routes: vec![types::Route {
                dst: "0.0.0.0/0".to_string(),
                gw: Some("10.1.0.1".to_string()),
                mtu: Some(1400),
                advmss: None,
                priority: Some(100),
                table: None,
                scope: None,
            }],
            dns: Some(types::Dns {
                nameservers: vec!["10.1.0.1".to_string()],
                domain: None,
                search: None,
                options: None,
            }),
        };
        let legacy = CNIResult::new("0.4.0".parse()?, result);
        assert_eq!(
            serde_json::to_value(&legacy)?,
            json!({
                "cniVersion": "0.4.0",
                "interfaces": [
                    {"name": "eth0", "mac": "00:11:22:33:44:55", "sandbox": "/var/run/netns/test"}
                ],
                "ips": [
                    {"version": "4", "interface": 0, "address": "10.1.0.5/16", "gateway": "10.1.0.1"},
                    {"version": "6", "address": "fd00::2/64"}
                ],
                // Whole routes; only interfaces lose what 1.1.0 added.
                "routes": [
                    {"dst": "0.0.0.0/0", "gw": "10.1.0.1", "mtu": 1400, "priority": 100}
                ],
                "dns": {"nameservers": ["10.1.0.1"]}
            })
        );
        Ok(())
    }

    #[test]
    fn legacy_layout_of_an_empty_result() -> Result<(), Box<dyn std::error::Error>> {
        // The reference 0.4.0 result always carries a dns object, even empty.
        let legacy = CNIResult::new("0.4.0".parse()?, types::CNIResult::default());
        assert_eq!(
            serde_json::to_value(&legacy)?,
            json!({"cniVersion": "0.4.0", "dns": {}})
        );
        Ok(())
    }

    #[rstest::rstest]
    #[case("10.1.0.5/16", "4")]
    #[case("fd00::2/64", "6")]
    // An IPv4-mapped IPv6 address counts as IPv4.
    #[case("::ffff:10.1.0.5/96", "4")]
    fn family_matches_the_reference(#[case] address: &str, #[case] family: &str) {
        assert_eq!(super::IpConfig::address_family(address), family);
    }
}
