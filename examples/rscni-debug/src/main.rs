use std::{collections::HashMap, fs, io::Write, path::PathBuf};

use rscni::{
    cni::{Cni, Plugin},
    error::Error,
    types::{Args, CNIResult},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const ABOUT_MSG: &str = "RsCNI Debug Plugin shows CNI args";
const OUTPUT_FILE_PATH: &str = "/tmp/rscni-debug";
const ERROR_CODE_FILE_OPEN: u32 = 100;
const ERROR_MSG_FILE_OPEN: &str = "Failed to open file";

fn main() {
    let plugin = Plugin::default().msg(ABOUT_MSG);

    let debug_conf = DebugConf {
        cni_output: PathBuf::from(OUTPUT_FILE_PATH),
    };

    plugin
        .run(&debug_conf)
        .expect("Failed to complete the CNI call");
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DebugConf {
    cni_output: PathBuf,
}

impl Cni for DebugConf {
    fn add(&self, args: Args) -> Result<CNIResult, Error> {
        add(args)
    }

    fn del(&self, args: Args) -> Result<CNIResult, Error> {
        del(args)
    }

    fn check(&self, args: Args) -> Result<CNIResult, Error> {
        check(args)
    }

    fn status(&self, _args: Args) -> Result<(), Error> {
        Ok(())
    }

    fn gc(&self, _args: Args) -> Result<(), Error> {
        // No cleanup needed for debug plugin
        Ok(())
    }
}

impl DebugConf {
    fn open_file(&self, container_id: &str, cmd: &str) -> Result<std::fs::File, Error> {
        fs::create_dir_all(self.cni_output.as_os_str().to_str().unwrap()).map_err(|e| {
            Error::Custom(
                ERROR_CODE_FILE_OPEN,
                ERROR_MSG_FILE_OPEN.to_string(),
                e.to_string(),
            )
        })?;
        let path = self.cni_output.join(format!("{container_id}-{cmd}"));
        std::fs::File::create(path).map_err(|e| {
            Error::Custom(
                ERROR_CODE_FILE_OPEN,
                ERROR_MSG_FILE_OPEN.to_string(),
                e.to_string(),
            )
        })
    }

    fn parse(custom: &HashMap<String, Value>) -> Result<DebugConf, Error> {
        let debug_conf_str = serde_json::to_string(custom)
            .map_err(|e| Error::InvalidNetworkConfig(e.to_string()))?;

        serde_json::from_str(&debug_conf_str)
            .map_err(|e| Error::InvalidNetworkConfig(e.to_string()))
    }
}

fn add(args: Args) -> Result<CNIResult, Error> {
    let cmd = "Add";
    let cni_output = output_args(cmd, &args)?;

    let net_conf = args
        .config()
        .ok_or_else(|| Error::InvalidNetworkConfig("cniOutput must be given".to_string()))?;
    let debug_conf = DebugConf::parse(&net_conf.custom)?;

    let container_id = args.container_id().unwrap_or("unknown");
    let mut file = debug_conf.open_file(container_id, cmd)?;
    file.write(cni_output.as_bytes())
        .map_err(|e| Error::IOFailure(e.to_string()))?;

    Ok(match &net_conf.prev_result {
        Some(prev) => prev.clone(),
        None => CNIResult::default(),
    })
}

fn del(args: Args) -> Result<CNIResult, Error> {
    let cmd = "Del";
    let cni_output = output_args(cmd, &args)?;

    let net_conf = args
        .config()
        .ok_or_else(|| Error::InvalidNetworkConfig("cniOutput must be given".to_string()))?;
    let debug_conf = DebugConf::parse(&net_conf.custom)?;

    let container_id = args.container_id().unwrap_or("unknown");
    let mut file = debug_conf.open_file(container_id, cmd)?;
    file.write(cni_output.as_bytes())
        .map_err(|e| Error::IOFailure(e.to_string()))?;

    Ok(match &net_conf.prev_result {
        Some(prev) => prev.clone(),
        None => CNIResult::default(),
    })
}

fn check(args: Args) -> Result<CNIResult, Error> {
    let cmd = "Check";
    let cni_output = output_args(cmd, &args)?;

    let net_conf = args
        .config()
        .ok_or_else(|| Error::InvalidNetworkConfig("cniOutput must be given".to_string()))?;
    let debug_conf = DebugConf::parse(&net_conf.custom)?;

    let container_id = args.container_id().unwrap_or("unknown");
    let mut file = debug_conf.open_file(container_id, cmd)?;
    file.write(cni_output.as_bytes())
        .map_err(|e| Error::IOFailure(e.to_string()))?;

    Ok(match &net_conf.prev_result {
        Some(prev) => prev.clone(),
        None => CNIResult::default(),
    })
}

fn output_args(cmd: &str, args: &Args) -> Result<String, Error> {
    let stdin_data = match args.config() {
        Some(conf) => {
            serde_json::to_string(&conf).map_err(|e| Error::FailedToDecode(e.to_string()))?
        }
        None => "{}".to_string(),
    };
    let out = format!(
        r#"CNI_COMMAND: {}
CNI_CONTAINERID: {}
CNI_IFNAME: {}
CNI_NETNS: {:?}
CNI_PATH: {:?}
CNI_ARGS: {:?},
STDIN_DATA: {}
--------------------
"#,
        cmd,
        args.container_id().unwrap_or("<none>"),
        args.ifname().unwrap_or("<none>"),
        args.netns(),
        args.path(),
        args.args(),
        stdin_data,
    );
    Ok(out)
}
