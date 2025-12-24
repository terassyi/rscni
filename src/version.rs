use serde::{Deserialize, Serialize};

use super::error::Error;

/// `PluginInfo` is for supported CNI plugin version information.
/// Please see <https://github.com/containernetworking/cni/blob/v1.1.0/SPEC.md#version>.
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
            cni_version: "1.3.0".to_string(),
            supported_versions: vec![
                "0.3.1".to_string(),
                "0.4.0".to_string(),
                "1.0.0".to_string(),
                "1.1.0".to_string(),
                "1.3.0".to_string(),
            ],
        }
    }
}

impl PluginInfo {
    pub(crate) fn version(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|e| Error::FailedToDecode(e.to_string()))
    }

    pub(crate) fn about(&self, msg: Option<String>) -> String {
        let versions = self.supported_versions.join(", ");
        msg.map_or_else(
            || format!("CNI protocol versions supported: {versions}"),
            |msg| format!("{msg}\nCNI protocol versions supported: {versions}"),
        )
    }

    // Version considerations
    pub(crate) fn validate(&self, ver: &str) -> Result<(), Error> {
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
            cni_version: "1.3.0".to_string(),
            supported_versions: vec![
                "0.3.1".to_string(),
                "0.4.0".to_string(),
                "1.0.0".to_string(),
                "1.1.0".to_string(),
                "1.3.0".to_string(),
            ],
        };

        let same_version = "1.3.0";

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
