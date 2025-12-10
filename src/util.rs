use std::{io, str::FromStr};

use crate::error::Error;

pub trait Env {
    fn get<T>(name: &str) -> Result<T, Error>
    where
        T: FromStr,
        T::Err: std::error::Error + 'static;
}

pub struct OsEnv;

impl Env for OsEnv {
    /// This function returns the environment value.
    /// If the value doesn't exist or is invalid, this returns [`Error::InvalidEnvValue`].
    fn get<T>(name: &str) -> Result<T, Error>
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
}

pub trait Io {
    fn io_in() -> impl io::Read;
    fn io_out() -> impl io::Write;
    #[allow(dead_code)]
    fn io_err() -> impl io::Write;
}

pub struct StdIo;

impl Io for StdIo {
    fn io_in() -> impl io::Read {
        io::stdin()
    }

    fn io_out() -> impl io::Write {
        io::stdout()
    }

    fn io_err() -> impl io::Write {
        io::stderr()
    }
}
