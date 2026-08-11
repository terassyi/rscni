//! CNI error types and error handling.
//!
//! This module defines the error types used throughout the library, following the
//! [CNI specification error format](https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#error).
//!
//! # Error Handling in CNI Plugins
//!
//! CNI plugins should return appropriate error types to help the container runtime
//! understand what went wrong and how to handle it.
//!

/// CNI error types as defined by the CNI specification.
///
/// Each variant corresponds to a specific error code and includes a detail message.
/// When returned from a CNI plugin, these errors are automatically formatted as
/// JSON error responses according to the CNI spec.
/// <https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#error>
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Incompatible CNI version (Error code: 1)
    ///
    /// Returned when the CNI version requested by the runtime is not supported
    /// by the plugin. The detail message should specify which version was requested.
    IncompatibleVersion(String),

    /// Unsupported field in network configuration (Error code: 2)
    ///
    /// Returned when the network configuration contains a field that the plugin
    /// does not support. The detail message should specify the unsupported field name and value.
    UnsupportedNetworkConfiguration(String),

    /// Container does not exist (Error code: 3)
    ///
    /// Returned when the container is unknown or does not exist. This implies
    /// the runtime does not need to perform any network cleanup.
    NotExist(String),

    /// Invalid environment variable (Error code: 4)
    ///
    /// Returned when required CNI environment variables (like `CNI_COMMAND`,
    /// `CNI_CONTAINERID`, etc.) are missing or have invalid values.
    InvalidEnvValue(String),

    /// I/O failure (Error code: 5)
    ///
    /// Returned for I/O errors such as failing to read network configuration
    /// from stdin or write results to stdout.
    IOFailure(String),

    /// Failed to decode/parse data (Error code: 6)
    ///
    /// Returned when failing to parse JSON configuration, unmarshal data,
    /// or decode version information.
    FailedToDecode(String),

    /// Invalid network configuration (Error code: 7)
    ///
    /// Returned when network configuration validation fails.
    InvalidNetworkConfig(String),

    /// Invalid network namespace (Error code: 8)
    ///
    /// Absent from the specification's error table, but defined and emitted by the
    /// reference implementation, so a runtime reads it back as this.
    InvalidNetNS(String),

    /// Try again later (Error code: 11)
    ///
    /// Returned when the plugin detects a transient condition that should clear up.
    /// The runtime should retry the operation later.
    TryAgainLater(String),

    /// Plugin not available (Error code: 50)
    ///
    /// Returned when the plugin is not available and cannot service ADD requests.
    /// Used in response to STATUS command.
    PluginNotAvailable(String),

    /// Plugin not available with limited connectivity (Error code: 51)
    ///
    /// Returned when the plugin is not available, and existing containers in the
    /// network may have limited connectivity. Used in response to STATUS command.
    PluginNotAvailableLimitedConnectivity(String),

    /// Custom plugin-specific error (Error code: 100+)
    ///
    /// For plugin-specific errors with custom error codes (100+), messages,
    /// and detailed descriptions.
    ///
    /// # Arguments
    ///
    /// * First field: Error code. Use >= 100 when raising one: the spec reserves
    ///   0-99. Reading a foreign plugin's error result can also yield a reserved code
    ///   this crate has no variant for, which lands here verbatim.
    /// * Second field: Short error message
    /// * Third field: Detailed error description
    ///
    /// # Example
    ///
    /// ```rust
    /// use rscni_types::error::Error;
    ///
    /// fn custom_validation() -> Result<(), Error> {
    ///     Err(Error::Custom(
    ///         100,
    ///         "Bridge creation failed".to_string(),
    ///         "Failed to create bridge br0: device already exists".to_string(),
    ///     ))
    /// }
    /// ```
    Custom(u32, String, String),
}

impl Error {
    /// The error for absent required environment variables, naming them in the
    /// details as the spec's code-4 entry requires.
    #[must_use]
    pub fn missing_env(vars: &[&str]) -> Self {
        Self::InvalidEnvValue(format!(
            "required env variables [{}] missing",
            vars.join(",")
        ))
    }

    /// The wire `msg`: the specification's short wording for this error's code. An
    /// [`Error::Custom`] carries its own.
    #[must_use]
    pub fn msg(&self) -> &str {
        match self {
            Self::IncompatibleVersion(_) => "Incompatible CNI version",
            Self::UnsupportedNetworkConfiguration(_) => "Unsupported network configuration",
            Self::NotExist(_) => "Container does not exist",
            Self::InvalidEnvValue(_) => "Invalid necessary environment variables",
            Self::IOFailure(_) => "I/O failure",
            Self::FailedToDecode(_) => "Failed to decode content",
            Self::InvalidNetworkConfig(_) => "Invalid network config",
            Self::InvalidNetNS(_) => "Invalid network namespace",
            Self::TryAgainLater(_) => "Try again later",
            Self::PluginNotAvailable(_) => "Plugin not available",
            Self::PluginNotAvailableLimitedConnectivity(_) => {
                "Plugin not available, limited connectivity"
            }
            Self::Custom(_, msg, _) => msg,
        }
    }

    /// The wire `details`: the longer description accompanying the error code.
    #[must_use]
    pub fn details(&self) -> &str {
        match self {
            Self::IncompatibleVersion(details)
            | Self::UnsupportedNetworkConfiguration(details)
            | Self::NotExist(details)
            | Self::InvalidEnvValue(details)
            | Self::IOFailure(details)
            | Self::FailedToDecode(details)
            | Self::InvalidNetworkConfig(details)
            | Self::InvalidNetNS(details)
            | Self::TryAgainLater(details)
            | Self::PluginNotAvailable(details)
            | Self::PluginNotAvailableLimitedConnectivity(details)
            | Self::Custom(_, _, details) => details,
        }
    }
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.details() {
            "" => f.write_str(self.msg()),
            details => write!(f, "{}; {details}", self.msg()),
        }
    }
}

impl From<&Error> for u32 {
    fn from(value: &Error) -> Self {
        match value {
            Error::IncompatibleVersion(_) => 1,
            Error::UnsupportedNetworkConfiguration(_) => 2,
            Error::NotExist(_) => 3,
            Error::InvalidEnvValue(_) => 4,
            Error::IOFailure(_) => 5,
            Error::FailedToDecode(_) => 6,
            Error::InvalidNetworkConfig(_) => 7,
            Error::InvalidNetNS(_) => 8,
            Error::TryAgainLater(_) => 11,
            Error::PluginNotAvailable(_) => 50,
            Error::PluginNotAvailableLimitedConnectivity(_) => 51,
            Error::Custom(code, _, _) => *code,
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::Error;
    use crate::types::ErrorResult;

    #[rstest]
    #[case(Error::IncompatibleVersion("test".to_string()), 1)]
    #[case(Error::UnsupportedNetworkConfiguration("test".to_string()), 2)]
    #[case(Error::NotExist("test".to_string()), 3)]
    #[case(Error::InvalidEnvValue("test".to_string()), 4)]
    #[case(Error::IOFailure("test".to_string()), 5)]
    #[case(Error::FailedToDecode("test".to_string()), 6)]
    #[case(Error::InvalidNetworkConfig("test".to_string()), 7)]
    #[case(Error::InvalidNetNS("test".to_string()), 8)]
    #[case(Error::TryAgainLater("test".to_string()), 11)]
    #[case(Error::PluginNotAvailable("test".to_string()), 50)]
    #[case(Error::PluginNotAvailableLimitedConnectivity("test".to_string()), 51)]
    #[case(Error::Custom(100, "msg".to_string(), "details".to_string()), 100)]
    #[case(Error::Custom(255, "msg".to_string(), "details".to_string()), 255)]
    fn test_error_code_conversion(#[case] error: Error, #[case] expected_code: u32) {
        assert_eq!(u32::from(&error), expected_code);
    }

    #[rstest]
    #[case(1, "version not supported", Error::IncompatibleVersion("version not supported".to_string()))]
    #[case(2, "field xyz", Error::UnsupportedNetworkConfiguration("field xyz".to_string()))]
    #[case(3, "container not found", Error::NotExist("container not found".to_string()))]
    #[case(4, "CNI_COMMAND not set", Error::InvalidEnvValue("CNI_COMMAND not set".to_string()))]
    #[case(5, "failed to read", Error::IOFailure("failed to read".to_string()))]
    #[case(6, "invalid JSON", Error::FailedToDecode("invalid JSON".to_string()))]
    #[case(7, "missing field", Error::InvalidNetworkConfig("missing field".to_string()))]
    #[case(8, "netns is the plugin's own", Error::InvalidNetNS("netns is the plugin's own".to_string()))]
    #[case(11, "resource busy", Error::TryAgainLater("resource busy".to_string()))]
    fn test_error_result_to_error_conversion_standard(
        #[case] code: u32,
        #[case] details: &str,
        #[case] expected: Error,
    ) {
        let error_result = ErrorResult {
            cni_version: "1.1.0".to_string(),
            code,
            msg: "Test message".to_string(),
            details: details.to_string(),
        };
        assert_eq!(Error::from(error_result), expected);
    }

    #[rstest]
    // A reserved code without a variant (99) survives like any plugin-defined one.
    #[case(99, "Unknown", "unknown code")]
    // 100 is the boundary: the spec reserves 0-99, so 100 itself is already custom.
    #[case(100, "Boundary custom", "first plugin-defined code")]
    #[case(101, "Custom error", "custom details")]
    #[case(200, "Another custom", "more details")]
    fn test_error_result_to_error_conversion_custom(
        #[case] code: u32,
        #[case] msg: &str,
        #[case] details: &str,
    ) {
        let error_result = ErrorResult {
            cni_version: "1.1.0".to_string(),
            code,
            msg: msg.to_string(),
            details: details.to_string(),
        };
        assert_eq!(
            Error::from(error_result),
            Error::Custom(code, msg.to_string(), details.to_string())
        );
    }

    #[test]
    fn test_error_result_reads_the_reference_wire_form() -> Result<(), Box<dyn std::error::Error>> {
        // The reference implementation emits no cniVersion and omits empty details.
        let error_result: ErrorResult =
            serde_json::from_str(r#"{"code":4,"msg":"required env variables missing"}"#)?;
        let error = Error::from(error_result);
        assert_eq!(u32::from(&error), 4);
        Ok(())
    }

    #[rstest]
    #[case(
        Error::InvalidEnvValue("CNI_NETNS is required".to_string()),
        4,
        "Invalid necessary environment variables"
    )]
    #[case(Error::TryAgainLater("resource busy".to_string()), 11, "Try again later")]
    #[case(Error::Custom(100, "custom".to_string(), "details".to_string()), 100, "custom")]
    fn test_error_result_new_round_trips(
        #[case] error: Error,
        #[case] code: u32,
        #[case] wire_msg: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let result = ErrorResult::new("1.1.0", &error);
        let json: serde_json::Value = serde_json::from_str(&serde_json::to_string(&result)?)?;
        assert_eq!(json["cniVersion"], "1.1.0");
        assert_eq!(json["code"], code);
        assert_eq!(json["msg"], wire_msg);
        assert_eq!(json["details"], error.details());

        // Reading its own wire form back yields an error with the same code and
        // details, and re-emitting that error reproduces the same wire msg — the
        // representation is stable across round trips.
        let read_back = Error::from(result);
        assert_eq!(u32::from(&read_back), code);
        assert_eq!(read_back.details(), error.details());
        assert_eq!(ErrorResult::new("1.1.0", &read_back).msg, wire_msg);
        Ok(())
    }
}
