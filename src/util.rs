use std::{io::Read, io::Write, str::FromStr};

use crate::error::Error;

pub(super) struct IoTarget {
    pub(super) stdin: Box<dyn Read>,
    pub(super) stdout: Box<dyn Write>,
    pub(super) stderr: Box<dyn Write>,
}

impl Default for IoTarget {
    fn default() -> Self {
        IoTarget {
            stdin: Box::new(std::io::stdin()),
            stdout: Box::new(std::io::stdout()),
            stderr: Box::new(std::io::stderr()),
        }
    }
}

/// This function returns the environment value.
/// If the value doesn't exist or is invalid, this returns [Error::InvalidEnvValue].
pub fn get_env<T>(name: &str) -> Result<T, Error>
where
    T: FromStr,
    T::Err: std::error::Error + 'static,
{
    std::env::var(name)
        .map_err(|e| Error::InvalidEnvValue(e.to_string()))
        .and_then(|v| {
            v.parse()
                .map_err(|e: T::Err| Error::InvalidEnvValue(e.to_string()))
        })
}
