use std::{
    io::{Read, Write},
    path::PathBuf,
    str::FromStr,
};

use crate::{
    types::{Args, CNI_ARGS, CNI_COMMAND, CNI_CONTAINERID, CNI_IFNAME, CNI_NETNS, CNI_PATH},
    util::{get_env, IoTarget},
};

use super::{
    error::Error,
    types::{CNIResult, ErrorResult, NetConf},
    version::PluginInfo,
};

enum Cmd {
    Add { f: CmdFn, args: Args },
    Del { f: CmdFn, args: Args },
    Check { f: CmdFn, args: Args },
    Version(PluginInfo),
    // If CNI_COMMAND is not specified, Nop will run.
    About(PluginInfo, String),
}

impl Cmd {
    fn run(&self) -> Result<String, Error> {
        match self {
            Cmd::Add { f, args } | Cmd::Del { f, args } | Cmd::Check { f, args } => {
                match f(args.clone()) {
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

/// CmdFn is the function type of callback functions for CNI Add, Del and Check commands.
/// It accepts [Args] and returns [CNIResult] or [Error].
/// Users have to define three functions(add, del and check) satisfy this type as CNI commands.
pub type CmdFn = fn(args: Args) -> Result<CNIResult, Error>;

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

    /// Plugin::run() processes given parameters and runs given callback functions depending on called command types.
    pub fn run(&mut self) -> Result<(), Error> {
        match self.inner_run(get_env) {
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

    fn inner_run<'a>(
        &mut self,
        get_env: impl Fn(&'a str) -> Result<String, Error>,
    ) -> Result<String, Error> {
        let cmd = self.get_cmd(get_env)?;
        cmd.run()
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rstest::rstest;

    use crate::{
        error::Error,
        types::{CNIResult, Dns, IpConfig},
    };

    use super::Args;
    use super::*;

    const ADD_SUCCESS_RESULT: &str = r#"{"ips":[{"interface":0,"address":"added","gateway":"added"}],"dns":{"nameservers":["dummy"]}}"#;
    const DEL_SUCCESS_RESULT: &str = r#"{"ips":[{"interface":0,"address":"deleted","gateway":"deleted"}],"dns":{"nameservers":["dummy"]}}"#;
    const CHECK_SUCCESS_RESULT: &str = r#"{"ips":[{"interface":0,"address":"checked","gateway":"checked"}],"dns":{"nameservers":["dummy"]}}"#;

    fn dummy_add_success(_args: Args) -> Result<CNIResult, Error> {
        Ok(CNIResult {
            interfaces: vec![],
            ips: vec![IpConfig {
                interface: Some(0),
                address: "added".to_string(),
                gateway: Some("added".to_string()),
            }],
            routes: vec![],
            dns: Some(Dns {
                nameservers: vec!["dummy".to_string()],
                domain: None,
                search: None,
                options: None,
            }),
        })
    }

    fn dummy_del_success(_args: Args) -> Result<CNIResult, Error> {
        Ok(CNIResult {
            interfaces: vec![],
            ips: vec![IpConfig {
                interface: Some(0),
                address: "deleted".to_string(),
                gateway: Some("deleted".to_string()),
            }],
            routes: vec![],
            dns: Some(Dns {
                nameservers: vec!["dummy".to_string()],
                domain: None,
                search: None,
                options: None,
            }),
        })
    }

    fn dummy_check_success(_args: Args) -> Result<CNIResult, Error> {
        Ok(CNIResult {
            interfaces: vec![],
            ips: vec![IpConfig {
                interface: Some(0),
                address: "checked".to_string(),
                gateway: Some("checked".to_string()),
            }],
            routes: vec![],
            dns: Some(Dns {
                nameservers: vec!["dummy".to_string()],
                domain: None,
                search: None,
                options: None,
            }),
        })
    }

    #[rstest(
        env_values,
        stdin_data,
        expected_out,
        expected_err,
        case(
            HashMap::from([
                (CNI_COMMAND.to_string(), "VERSION".to_string())
            ]),
            "{}",
            r#"{"cniVersion":"9.8.7","supportedVersions":["9.8.7"]}"#,
            None,
        ),
        case(
            HashMap::from([
                (CNI_COMMAND.to_string(), "ADD".to_string()),
                (CNI_CONTAINERID.to_string(), "some-container-id".to_string()),
                (CNI_NETNS.to_string(), "/some/netns/path".to_string()),
                (CNI_IFNAME.to_string(), "eth0".to_string()),
                (CNI_PATH.to_string(), "/some/cni/path".to_string()),
                (CNI_ARGS.to_string(), "some;extra;args".to_string()),
            ]),
            r#"{ "name":"skel-test", "type": "test", "some": "config", "cniVersion": "9.8.7" }"#,
            ADD_SUCCESS_RESULT.to_string(),
            None,
        ),
        case(
            HashMap::from([
                (CNI_COMMAND.to_string(), "ADD".to_string()),
                (CNI_CONTAINERID.to_string(), "some-container-id".to_string()),
                (CNI_IFNAME.to_string(), "eth0".to_string()),
                (CNI_PATH.to_string(), "/some/cni/path".to_string()),
                (CNI_ARGS.to_string(), "some;extra;args".to_string()),
            ]),
            r#"{ "name":"skel-test", "type": "test", "some": "config", "cniVersion": "9.8.7" }"#,
            String::new(),
            Some(Error::InvalidEnvValue("CNI_NETNS must be set".to_string())),
        ),
        case(
            HashMap::from([
                (CNI_COMMAND.to_string(), "ADD".to_string()),
                (CNI_CONTAINERID.to_string(), "some-container-id".to_string()),
                (CNI_NETNS.to_string(), "/some/netns/path".to_string()),
                (CNI_IFNAME.to_string(), "eth0".to_string()),
                (CNI_PATH.to_string(), "/some/cni/path".to_string()),
                (CNI_ARGS.to_string(), "some;extra;args".to_string()),
            ]),
            r#"{ "name":"skel-test", "type": "test", "some": "config", "cniVersion": "9.0.0" }"#,
            String::new(),
            Some(Error::IncompatibleVersion("9.0.0 is not supported".to_string())),
        ),
        case(
            HashMap::from([
                (CNI_COMMAND.to_string(), "CHECK".to_string()),
                (CNI_CONTAINERID.to_string(), "some-container-id".to_string()),
                (CNI_NETNS.to_string(), "/some/netns/path".to_string()),
                (CNI_IFNAME.to_string(), "eth0".to_string()),
                (CNI_PATH.to_string(), "/some/cni/path".to_string()),
                (CNI_ARGS.to_string(), "some;extra;args".to_string()),
            ]),
            r#"{ "name":"skel-test", "type": "test", "some": "config", "cniVersion": "9.8.7" }"#,
            CHECK_SUCCESS_RESULT.to_string(),
            None,
        ),
        case(
            HashMap::from([
                (CNI_COMMAND.to_string(), "CHECK".to_string()),
                (CNI_CONTAINERID.to_string(), "some-container-id".to_string()),
                (CNI_IFNAME.to_string(), "eth0".to_string()),
                (CNI_PATH.to_string(), "/some/cni/path".to_string()),
                (CNI_ARGS.to_string(), "some;extra;args".to_string()),
            ]),
            r#"{ "name":"skel-test", "type": "test", "some": "config", "cniVersion": "9.8.7" }"#,
            String::new(),
            Some(Error::InvalidEnvValue("CNI_NETNS must be set".to_string())),
        ),
        case(
            HashMap::from([
                (CNI_COMMAND.to_string(), "DEL".to_string()),
                (CNI_CONTAINERID.to_string(), "some-container-id".to_string()),
                (CNI_NETNS.to_string(), "/some/netns/path".to_string()),
                (CNI_IFNAME.to_string(), "eth0".to_string()),
                (CNI_PATH.to_string(), "/some/cni/path".to_string()),
                (CNI_ARGS.to_string(), "some;extra;args".to_string()),
            ]),
            r#"{ "name":"skel-test", "type": "test", "some": "config", "cniVersion": "9.8.7" }"#,
            DEL_SUCCESS_RESULT.to_string(),
            None,
        ),
        case(
            HashMap::from([
                (CNI_COMMAND.to_string(), "DEL".to_string()),
                (CNI_CONTAINERID.to_string(), "some-container-id".to_string()),
                (CNI_IFNAME.to_string(), "eth0".to_string()),
                (CNI_PATH.to_string(), "/some/cni/path".to_string()),
                (CNI_ARGS.to_string(), "some;extra;args".to_string()),
            ]),
            r#"{ "name":"skel-test", "type": "test", "some": "config", "cniVersion": "9.8.7" }"#,
            DEL_SUCCESS_RESULT.to_string(),
            None,
        ),
        case(
            HashMap::from([
                (CNI_COMMAND.to_string(), "DEL".to_string()),
                (CNI_IFNAME.to_string(), "eth0".to_string()),
                (CNI_PATH.to_string(), "/some/cni/path".to_string()),
                (CNI_ARGS.to_string(), "some;extra;args".to_string()),
            ]),
            r#"{ "name":"skel-test", "type": "test", "some": "config", "cniVersion": "9.8.7" }"#,
            String::new(),
            Some(Error::InvalidEnvValue("CNI_CONTAINERID must be set".to_string())),
        ),
    )]
    fn plugin_dispatcher_run<'a>(
        env_values: HashMap<String, String>,
        stdin_data: &'static str,
        expected_out: String,
        expected_err: Option<Error>,
    ) {
        let dummy_get_env = |name: &'a str| -> Result<String, Error> {
            env_values
                .get(name)
                .map(|v| v.to_string())
                .ok_or(Error::InvalidEnvValue("dummy".to_string()))
        };

        let plugin_info = PluginInfo {
            cni_version: "9.8.7".to_string(),
            supported_versions: vec!["9.8.7".to_string()],
        };

        let stdin_data = stdin_data.as_bytes();

        let dummy_in = Box::new(stdin_data);
        let stdout = Box::new(std::io::stdout());
        let stderr = Box::new(std::io::stderr());

        let mut dispatcher = Plugin {
            add: dummy_add_success,
            del: dummy_del_success,
            check: dummy_check_success,
            version_info: plugin_info,
            about: "".to_string(),
            io: IoTarget {
                stdin: dummy_in,
                stdout,
                stderr,
            },
        };
        let result = dispatcher.inner_run(dummy_get_env);

        match result {
            Ok(success) => {
                assert_json_diff::assert_json_eq!(expected_out, success);
            }
            Err(e) => {
                println!("{}: {}", e, e.details());
                assert_eq!(u32::from(&expected_err.unwrap()), u32::from(&e))
            }
        }
    }
}
