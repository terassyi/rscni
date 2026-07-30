//! Plugin version reporting and negotiation.

use serde::{Deserialize, Serialize};

use crate::error::Error;

/// `PluginInfo` is for supported CNI plugin version information.
/// Please see <https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#version>.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginInfo {
    pub(crate) cni_version: String,
    pub(crate) supported_versions: Vec<String>,
}

impl PluginInfo {
    #[must_use]
    pub fn new(cni_version: &str, supported_versions: Vec<String>) -> Self {
        Self {
            cni_version: cni_version.to_string(),
            supported_versions,
        }
    }
}

impl Default for PluginInfo {
    fn default() -> Self {
        Self {
            cni_version: "1.1.0".to_string(),
            supported_versions: vec![
                "0.3.1".to_string(),
                "0.4.0".to_string(),
                "1.0.0".to_string(),
                "1.1.0".to_string(),
            ],
        }
    }
}

impl PluginInfo {
    /// Returns the CNI specification version this plugin reports as its own.
    #[must_use]
    pub fn cni_version(&self) -> &str {
        &self.cni_version
    }

    /// Returns every CNI specification version this plugin can be asked to speak.
    #[must_use]
    pub fn supported_versions(&self) -> &[String] {
        &self.supported_versions
    }

    /// Checks that `ver` is a version this plugin can speak.
    ///
    /// A runtime uses this against the [`PluginInfo`] it got back from `VERSION` to
    /// confirm a plugin can handle the `cniVersion` in a network configuration before
    /// invoking it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IncompatibleVersion`] if `ver` is neither this plugin's own
    /// version nor one of its supported versions.
    pub fn validate(&self, ver: &str) -> Result<(), Error> {
        if self.cni_version.eq(ver) {
            return Ok(());
        }
        if !self.supported_versions.iter().any(|p| p.eq(ver)) {
            return Err(Error::IncompatibleVersion(format!(
                "{ver} is the incompatible version"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::PluginInfo;

    #[test]
    fn plugin_info_validate() {
        let plugin_info = PluginInfo {
            cni_version: "1.1.0".to_string(),
            supported_versions: vec![
                "0.3.1".to_string(),
                "0.4.0".to_string(),
                "1.0.0".to_string(),
                "1.1.0".to_string(),
            ],
        };

        let same_version = "1.1.0";

        let res = plugin_info.validate(same_version);
        assert!(res.is_ok());

        let other_compatible_version = "1.0.0";

        let res = plugin_info.validate(other_compatible_version);
        assert!(res.is_ok());

        let incompatible_version = "0.1.0";

        let res = plugin_info.validate(incompatible_version);
        assert!(res.is_err());
    }
}
