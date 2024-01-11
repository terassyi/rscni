use thiserror::Error;

/// Error represents CNI error result structure.
/// String value each variants have is for details in CNI errors.
/// Please see <https://github.com/containernetworking/cni/blob/v1.1.0/SPEC.md#Error> for details.
#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum Error {
    /// Incompatible CNI version
    IncompatibleVersion(String),
    /// Unsupported field in network configuration.
    /// This error message must contain the key and value of the unsupported field.
    UnsupportedNetworkConfiguration(String),
    /// Container unknown or does not exist.
    /// This errors implies the runtime does not need to perform any container network cleanup.
    NotExist(String),
    /// Invalid necessary environment variables, like CNI_COMMAND, CNI_CONTAINERID, etc.
    /// The error message must contain the names of invalid variables.
    InvalidEnvValue(String),
    /// I/O failure.
    /// For example, failed to read network configuration bytes from stdin.
    IOFailure(String),
    /// Failed to decode content.
    /// For example, failed to unmarshal network configurations from bytes or failed to decode version info from string.
    FailedToDecode(String),
    /// Invalid network configurations.
    /// If some validations on network configurations do no pass, this error will be raised.
    InvalidNetworkConfig(String),
    /// Try again later.
    /// If the plugin detects some transient condition that should clear up,
    /// it can use this code to notify the runtime it should re-try the operation later.
    TryAgainLater(String),
    /// Error codes 0-99 are reserved.
    /// So values of 100+ can be freely used for use specific errors.
    /// First value is for code.
    /// Second one is for message of the error.
    /// Third one is for a longer message describing the error.
    Custom(u32, String, String),
}

impl Error {
    /// Outputs details
    pub fn details(&self) -> String {
        match self {
            Error::IncompatibleVersion(details) => details.to_string(),
            Error::UnsupportedNetworkConfiguration(details) => details.to_string(),
            Error::NotExist(details) => details.to_string(),
            Error::InvalidEnvValue(details) => details.to_string(),
            Error::IOFailure(details) => details.to_string(),
            Error::FailedToDecode(details) => details.to_string(),
            Error::InvalidNetworkConfig(details) => details.to_string(),
            Error::TryAgainLater(details) => details.to_string(),
            Error::Custom(_, _, details) => details.to_string(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IncompatibleVersion(_) => write!(f, "Incompatible CNI version"),
            Error::UnsupportedNetworkConfiguration(_) => {
                write!(f, "Unsupported network configuration")
            }
            Error::NotExist(_) => write!(f, "Container does not exist"),
            Error::InvalidEnvValue(_) => {
                write!(f, "Invalid necessary environment variables")
            }
            Error::IOFailure(_) => write!(f, "I/O failure"),
            Error::FailedToDecode(_) => write!(f, "Failed to decode content"),
            Error::InvalidNetworkConfig(_) => write!(f, "Invalid network config"),
            Error::TryAgainLater(_) => write!(f, "Try again later"),
            Error::Custom(_, msg, _) => write!(f, "Custom error: {msg}"),
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
            Error::Custom(code, _, _) => *code,
        }
    }
}
