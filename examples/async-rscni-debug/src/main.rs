use std::{collections::HashMap, future::Future, path::PathBuf, pin::Pin};

use rscni::{
    async_skel::Plugin,
    error::Error,
    types::{Args, CNIResult},
    version::PluginInfo,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::AsyncWriteExt;

const ABOUT_MSG: &str = "RsCNI Debug Plugin shows CNI args";
const ERROR_CODE_FILE_OPEN: u32 = 100;
const ERROR_MSG_FILE_OPEN: &str = "Failed to open file";

#[tokio::main]
async fn main() {
    let version_info = PluginInfo::default();
    let mut dispatcher = Plugin::new(add, del, check, version_info, ABOUT_MSG);

    dispatcher
        .run()
        .await
        .expect("Failed to complete the CNI call");
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DebugConf {
    cni_output: PathBuf,
}

impl DebugConf {
    async fn open_file(&self, container_id: &str, cmd: &str) -> Result<tokio::fs::File, Error> {
        tokio::fs::create_dir_all(self.cni_output.as_os_str().to_str().unwrap())
            .await
            .map_err(|e| {
                Error::Custom(
                    ERROR_CODE_FILE_OPEN,
                    ERROR_MSG_FILE_OPEN.to_string(),
                    e.to_string(),
                )
            })?;
        let path = self.cni_output.join(format!("{container_id}-{cmd}"));
        tokio::fs::File::create(path).await.map_err(|e| {
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

fn add(args: Args) -> Pin<Box<dyn Future<Output = Result<CNIResult, Error>>>> {
    let fut = async { inner_add(args).await };
    Box::pin(fut)
}

async fn inner_add(args: Args) -> Result<CNIResult, Error> {
    let cmd = "Add";
    let cni_output = output_args(cmd, &args)?;

    let net_conf = args.config.ok_or(Error::InvalidNetworkConfig(
        "cniOutput must be given".to_string(),
    ))?;
    let debug_conf = DebugConf::parse(&net_conf.custom)?;

    let mut file = debug_conf.open_file(&args.container_id, cmd).await?;
    file.write(cni_output.as_bytes())
        .await
        .map_err(|e| Error::IOFailure(e.to_string()))?;

    Ok(match net_conf.prev_result {
        Some(prev) => prev,
        None => CNIResult::default(),
    })
}

fn del(args: Args) -> Pin<Box<dyn Future<Output = Result<CNIResult, Error>>>> {
    let fut = async { inner_del(args).await };
    Box::pin(fut)
}

async fn inner_del(args: Args) -> Result<CNIResult, Error> {
    let cmd = "Del";
    let cni_output = output_args(cmd, &args)?;

    let net_conf = args.config.ok_or(Error::InvalidNetworkConfig(
        "cniOutput must be given".to_string(),
    ))?;
    let debug_conf = DebugConf::parse(&net_conf.custom)?;

    let mut file = debug_conf.open_file(&args.container_id, cmd).await?;
    file.write(cni_output.as_bytes())
        .await
        .map_err(|e| Error::IOFailure(e.to_string()))?;

    Ok(match net_conf.prev_result {
        Some(prev) => prev,
        None => CNIResult::default(),
    })
}

fn check(args: Args) -> Pin<Box<dyn Future<Output = Result<CNIResult, Error>>>> {
    let fut = async { inner_check(args).await };
    Box::pin(fut)
}

async fn inner_check(args: Args) -> Result<CNIResult, Error> {
    let cmd = "Check";
    let cni_output = output_args(cmd, &args)?;

    let net_conf = args.config.ok_or(Error::InvalidNetworkConfig(
        "cniOutput must be given".to_string(),
    ))?;
    let debug_conf = DebugConf::parse(&net_conf.custom)?;

    let mut file = debug_conf.open_file(&args.container_id, cmd).await?;
    file.write(cni_output.as_bytes())
        .await
        .map_err(|e| Error::IOFailure(e.to_string()))?;

    Ok(match net_conf.prev_result {
        Some(prev) => prev,
        None => CNIResult::default(),
    })
}

fn output_args(cmd: &str, args: &Args) -> Result<String, Error> {
    let stdin_data = match &args.config {
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
        cmd, args.container_id, args.ifname, args.netns, args.path, args.args, stdin_data,
    );
    Ok(out)
}
