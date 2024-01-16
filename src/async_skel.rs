use std::{future::Future, path::PathBuf, pin::Pin, str::FromStr};

use crate::{
    error::Error,
    types::{
        Args, CNIResult, ErrorResult, NetConf, CNI_ARGS, CNI_COMMAND, CNI_CONTAINERID, CNI_IFNAME,
        CNI_NETNS, CNI_PATH,
    },
    util::{get_env, IoTarget},
    version::PluginInfo,
};

/// Plugin is the core structure for a CNI plugin.
/// It has callback functions for Add, Del and Check CNI commands as [CmdFn].
pub struct Plugin {
    /// Callback function for Add command.
    add: CmdFn,
    /// Callback function for Del command.
    del: CmdFn,
    /// Callback function for Check command.
    check: CmdFn,
    /// CNI version information of this plugin supports.
    /// See [PluginInfo].
    version_info: PluginInfo,
    /// The message of this plugin.
    about: String,
    io: IoTarget,
}

impl Plugin {
    /// new() creates a Plugin instance.
    pub fn new(
        add: CmdFn,
        del: CmdFn,
        check: CmdFn,
        version_info: PluginInfo,
        about: &str,
    ) -> Plugin {
        Plugin {
            add,
            del,
            check,
            version_info,
            about: about.to_string(),
            io: IoTarget::default(),
        }
    }

    /// Plugin::run() processes given parameters and runs given async callback functions depending on called command types.
    pub async fn run(&mut self) -> Result<(), Error> {
        match self.inner_run(get_env).await {
            Ok(res) => {
                // If we get error here, should we return error result to stdout?
                self.io
                    .stdout
                    .write(res.as_bytes())
                    .map_err(|e| Error::IOFailure(e.to_string()))?;
                Ok(())
            }
            Err(e) => {
                let res = self.error_result(&e);
                // If we get error here, should we return error result to stdout?
                let data =
                    serde_json::to_vec(&res).map_err(|e| Error::FailedToDecode(e.to_string()))?;
                self.io
                    .stdout
                    .write(&data)
                    .map_err(|e| Error::FailedToDecode(e.to_string()))?;
                Err(e)
            }
        }
    }

    async fn inner_run<'a>(
        &mut self,
        get_env: impl Fn(&'a str) -> Result<String, Error>,
    ) -> Result<String, Error> {
        let cmd = self.get_cmd(get_env)?;
        cmd.run().await
    }

    fn get_cmd<'a>(
        &mut self,
        get_env: impl Fn(&'a str) -> Result<String, Error>,
    ) -> Result<Cmd, Error> {
        let cmd_str = get_env(CNI_COMMAND).unwrap_or_default();
        match cmd_str.as_str() {
            "ADD" => {
                let container_id = get_env(CNI_CONTAINERID)?;
                let ifname = get_env(CNI_IFNAME)?;
                let netns = PathBuf::from_str(&get_env(CNI_NETNS)?)
                    .map_err(|e| Error::InvalidEnvValue(e.to_string()))?;
                let paths = get_env(CNI_PATH)?;
                let path = paths.split(':').map(PathBuf::from).collect();
                let args = get_env(CNI_ARGS).ok();

                let mut buf = String::new();
                self.io
                    .stdin
                    .read_to_string(&mut buf)
                    .map_err(|e| Error::IOFailure(e.to_string()))?;

                self.version_info.validate(&buf)?;

                let config: NetConf =
                    serde_json::from_str(&buf).map_err(|e| Error::FailedToDecode(e.to_string()))?;

                Ok(Cmd::Add {
                    f: self.add,
                    args: Args {
                        container_id,
                        netns: Some(netns),
                        ifname,
                        args,
                        path,
                        // TODO: parse config from stdin
                        config: Some(config),
                    },
                })
            }
            "DEL" => {
                let container_id = get_env(CNI_CONTAINERID)?;
                let ifname = get_env(CNI_IFNAME)?;
                let netns = match get_env(CNI_NETNS).as_ref().ok() {
                    Some(netns) => Some(
                        PathBuf::from_str(netns)
                            .map_err(|e| Error::InvalidEnvValue(e.to_string()))?,
                    ),
                    None => None,
                };
                let paths = get_env(CNI_PATH)?;
                let path = paths.split(':').map(PathBuf::from).collect();
                let args = get_env(CNI_ARGS).ok();

                let mut buf = String::new();
                self.io
                    .stdin
                    .read_to_string(&mut buf)
                    .map_err(|e| Error::IOFailure(e.to_string()))?;

                self.version_info.validate(&buf)?;

                let config: NetConf =
                    serde_json::from_str(&buf).map_err(|e| Error::FailedToDecode(e.to_string()))?;

                Ok(Cmd::Del {
                    f: self.del,
                    args: Args {
                        container_id,
                        netns,
                        ifname,
                        args,
                        path,
                        // TODO: parse config from stdin
                        config: Some(config),
                    },
                })
            }
            "CHECK" => {
                let container_id = get_env(CNI_CONTAINERID)?;
                let ifname = get_env(CNI_IFNAME)?;
                let netns = PathBuf::from_str(&get_env(CNI_NETNS)?)
                    .map_err(|e| Error::InvalidEnvValue(e.to_string()))?;
                let paths = get_env(CNI_PATH)?;
                let path = paths.split(':').map(PathBuf::from).collect();
                let args = get_env(CNI_ARGS).ok();

                let mut buf = String::new();
                self.io
                    .stdin
                    .read_to_string(&mut buf)
                    .map_err(|e| Error::IOFailure(e.to_string()))?;

                self.version_info.validate(&buf)?;

                let config: NetConf =
                    serde_json::from_str(&buf).map_err(|e| Error::FailedToDecode(e.to_string()))?;

                Ok(Cmd::Check {
                    f: self.check,
                    args: Args {
                        container_id,
                        netns: Some(netns),
                        ifname,
                        args,
                        path,
                        // TODO: parse config from stdin
                        config: Some(config),
                    },
                })
            }
            "VERSION" => Ok(Cmd::Version(self.version_info.clone())),
            _ => Ok(Cmd::About(self.version_info.clone(), self.about.clone())),
        }
    }

    fn error_result(&self, err: &Error) -> ErrorResult {
        ErrorResult {
            cni_version: self.version_info.cni_version.clone(),
            code: err.into(),
            msg: err.to_string(),
            details: err.details(),
        }
    }
}

enum Cmd {
    Add { f: CmdFn, args: Args },
    Del { f: CmdFn, args: Args },
    Check { f: CmdFn, args: Args },
    Version(PluginInfo),
    // If CNI_COMMAND is not specified, Nop will run.
    About(PluginInfo, String),
}

/// CmdFn is the function type of async callback functions for CNI Add, Del and Check commands.
/// It accepts [Args] and returns [CNIResult] or [Error].
/// Users have to define three functions(add, del and check) satisfy this type as CNI commands.
pub type CmdFn = fn(Args) -> Pin<Box<dyn Future<Output = Result<CNIResult, Error>>>>;

impl Cmd {
    async fn run(&self) -> Result<String, Error> {
        match self {
            Cmd::Add { f, args } | Cmd::Del { f, args } | Cmd::Check { f, args } => {
                match f(args.clone()).await {
                    Ok(res) => serde_json::to_string(&res)
                        .map_err(|e| Error::FailedToDecode(format!("{e}: {:?}", args.config))),
                    Err(e) => Err(e),
                }
            }
            Cmd::Version(info) => {
                let out = info.version()?;
                Ok(out)
            }
            Cmd::About(info, about) => {
                let out = info.about(about)?;
                Ok(out)
            }
        }
    }
}

impl From<Cmd> for &str {
    fn from(value: Cmd) -> Self {
        match value {
            Cmd::Add { .. } => "ADD",
            Cmd::Del { .. } => "DEL",
            Cmd::Check { .. } => "CHECK",
            Cmd::Version(_) => "VERSION",
            Cmd::About(_, _) => "NOP",
        }
    }
}
