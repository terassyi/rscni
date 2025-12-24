//! CNI error types and error handling.
//!
//! This module defines the error types used throughout the library, following the
//! [CNI specification error format](https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#Error).
//!
//! # Error Handling in CNI Plugins
//!
//! CNI plugins should return appropriate error types to help the container runtime
//! understand what went wrong and how to handle it.
//!

use thiserror::Error;

/// CNI error types as defined by the CNI specification.
///
/// Each variant corresponds to a specific error code and includes a detail message.
/// When returned from a CNI plugin, these errors are automatically formatted as
/// JSON error responses according to the CNI spec.
/// <https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#Error>
///
/// # CNI Error Codes
///
/// - 1: Incompatible CNI version
/// - 2: Unsupported network configuration field
/// - 3: Container does not exist
/// - 4: Invalid environment variable
/// - 5: I/O failure
/// - 6: Failed to decode/parse data
/// - 7: Invalid network configuration
/// - 11: Try again later
/// - 100+: Custom plugin-specific errors
///
#[allow(dead_code)]
#[derive(Debug, Error)]
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
    /// * First field: Error code (must be >= 100)
    /// * Second field: Short error message
    /// * Third field: Detailed error description
    ///
    /// # Example
    ///
    /// ```rust
    /// use rscni::error::Error;
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
    /// Outputs details
    #[must_use]
    pub fn details(&self) -> String {
        #[allow(clippy::match_same_arms)]
        match self {
            Self::IncompatibleVersion(details) => details.clone(),
            Self::UnsupportedNetworkConfiguration(details) => details.clone(),
            Self::NotExist(details) => details.clone(),
            Self::InvalidEnvValue(details) => details.clone(),
            Self::IOFailure(details) => details.clone(),
            Self::FailedToDecode(details) => details.clone(),
            Self::InvalidNetworkConfig(details) => details.clone(),
            Self::TryAgainLater(details) => details.clone(),
            Self::PluginNotAvailable(details) => details.clone(),
            Self::PluginNotAvailableLimitedConnectivity(details) => details.clone(),
            Self::Custom(_, _, details) => details.clone(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IncompatibleVersion(_) => write!(f, "Incompatible CNI version"),
            Self::UnsupportedNetworkConfiguration(_) => {
                write!(f, "Unsupported network configuration")
            }
            Self::NotExist(_) => write!(f, "Container does not exist"),
            Self::InvalidEnvValue(_) => {
                write!(f, "Invalid necessary environment variables")
            }
            Self::IOFailure(_) => write!(f, "I/O failure"),
            Self::FailedToDecode(_) => write!(f, "Failed to decode content"),
            Self::InvalidNetworkConfig(_) => write!(f, "Invalid network config"),
            Self::TryAgainLater(_) => write!(f, "Try again later"),
            Self::PluginNotAvailable(_) => write!(f, "Plugin not available"),
            Self::PluginNotAvailableLimitedConnectivity(_) => {
                write!(f, "Plugin not available, limited connectivity")
            }
            Self::Custom(_, msg, _) => write!(f, "Custom error: {msg}"),
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
    #[case(11, "resource busy", Error::TryAgainLater("resource busy".to_string()))]
    fn test_error_result_to_error_conversion_standard(
        #[case] code: u32,
        #[case] details: &str,
        #[case] expected: Error,
    ) {
        let error_result = ErrorResult {
            cni_version: "1.3.0".to_string(),
            code,
            msg: "Test message".to_string(),
            details: details.to_string(),
        };
        let error = Error::from(&error_result);
        assert_eq!(error.details(), expected.details());
        assert_eq!(u32::from(&error), u32::from(&expected));
    }

    #[rstest]
    #[case(101, "Custom error", "custom details")]
    #[case(200, "Another custom", "more details")]
    fn test_error_result_to_error_conversion_custom(
        #[case] code: u32,
        #[case] msg: &str,
        #[case] details: &str,
    ) {
        let error_result = ErrorResult {
            cni_version: "1.3.0".to_string(),
            code,
            msg: msg.to_string(),
            details: details.to_string(),
        };
        let error = Error::from(&error_result);
        if let Error::Custom(result_code, result_msg, result_details) = error {
            assert_eq!(result_code, code);
            assert_eq!(result_msg, msg);
            assert_eq!(result_details, details);
        } else {
            panic!("Expected Custom error, got: {error:?}");
        }
    }

    #[test]
    fn test_error_result_to_error_conversion_unknown() {
        let error_result = ErrorResult {
            cni_version: "1.3.0".to_string(),
            code: 99,
            msg: "Unknown".to_string(),
            details: "unknown code".to_string(),
        };
        let error = Error::from(&error_result);
        assert!(matches!(error, Error::FailedToDecode(_)));
        assert!(error.details().contains("unknown error code: 99"));
    }
}
