use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::error::Error;

/// PluginInfo is for supported CNI plugin version information.
/// Please ses <https://github.com/containernetworking/cni/blob/v1.1.0/SPEC.md#version>.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginInfo {
    pub(crate) cni_version: String,
    pub(crate) supported_versions: Vec<String>,
}

impl PluginInfo {
    pub fn new(cni_version: &str, supported_versions: Vec<String>) -> PluginInfo {
        PluginInfo {
            cni_version: cni_version.to_string(),
            supported_versions,
        }
    }
}

impl Default for PluginInfo {
    fn default() -> Self {
        PluginInfo {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Version {
    cni_version: String,
    #[serde(flatten)]
    other: Option<HashMap<String, Value>>,
}

impl PluginInfo {
    pub(crate) fn version(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|e| Error::FailedToDecode(e.to_string()))
    }

    pub(crate) fn about(&self, msg: &str) -> Result<String, Error> {
        let versions = self.supported_versions.join(", ");
        Ok(format!(
            "{msg}\nCNI protocol versions supported: {versions}"
        ))
    }

    // Version considerations
    pub(crate) fn validate(&self, input: &str) -> Result<(), Error> {
        let version_info: Version =
            serde_json::from_str(input).map_err(|e| Error::FailedToDecode(e.to_string()))?;
        if self.cni_version.eq(&version_info.cni_version) {
            return Ok(());
        }
        if !self
            .supported_versions
            .iter()
            .any(|p| p.eq(&version_info.cni_version))
        {
            return Err(Error::IncompatibleVersion(format!(
                "{} is the incompatible version",
                version_info.cni_version
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

        let same_version = r#"{"cniVersion":"1.1.0","name":"test"}"#;

        let res = plugin_info.validate(same_version);
        assert!(res.is_ok());

        let other_compatible_version = r#"{"cniVersion":"1.0.0","name":"test"}"#;

        let res = plugin_info.validate(other_compatible_version);
        assert!(res.is_ok());

        let incompatible_version = r#"{"cniVersion":"0.1.0","name":"test"}"#;

        let res = plugin_info.validate(incompatible_version);
        assert!(res.is_err());
    }
}
