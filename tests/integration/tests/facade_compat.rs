//! Pins the deprecated `rscni` 0.3.0 facade to the API 0.2.x exposed.
//!
//! Everything below is written the way a 0.2.x user would have written it, against
//! `rscni::*` rather than `rscni_plugin::*`. If this stops compiling, upgrading from
//! 0.2.x to the facade is no longer source-compatible and the facade has failed at its
//! only job.
//!
//! One path here is wider than 0.2.x: `rscni::version` was `pub(crate)` then, so
//! `PluginInfo` was unreachable. The shim exposes it because `rscni-plugin` does. That is
//! additive, and pinning it costs nothing.
//!
//! `Plugin` is a deprecated type alias in the facade, so naming it warns — that warning
//! is the facade's whole point, so it is silenced here rather than fixed. Removing the
//! `allow` below and running `cargo check -p integration-tests --tests` is how to confirm
//! the warning still reaches users.
#![allow(deprecated)]

use async_trait::async_trait;
use rscni::async_cni::{Cni as AsyncCni, Plugin as AsyncPlugin};
use rscni::cni::{Cni, Plugin};
use rscni::error::Error;
use rscni::types::{Args, CNIResult, NetConf};
use rscni::version::PluginInfo;

struct SyncPlugin;

impl Cni for SyncPlugin {
    fn add(&self, args: Args) -> Result<CNIResult, Error> {
        // Exercise the accessors, not just the type names.
        let _ = args.container_id();
        let _ = args.netns();
        let _ = args.ifname();
        let _ = args.args();
        let _ = args.path();
        let config: Option<&NetConf> = args.config();

        Ok(config
            .and_then(|c| c.prev_result.clone())
            .unwrap_or_default())
    }

    fn del(&self, _args: Args) -> Result<CNIResult, Error> {
        Ok(CNIResult::default())
    }

    fn check(&self, _args: Args) -> Result<CNIResult, Error> {
        Ok(CNIResult::default())
    }

    fn status(&self, _args: Args) -> Result<(), Error> {
        Ok(())
    }

    fn gc(&self, _args: Args) -> Result<(), Error> {
        Ok(())
    }
}

#[test]
fn sync_plugin_builds_through_the_facade() -> Result<(), Box<dyn std::error::Error>> {
    let _default = Plugin::default();
    let _custom = Plugin::new("1.3.0", vec!["1.0.0".to_string(), "1.3.0".to_string()]);
    let _with_msg = Plugin::default().msg("compat");

    // `run()` reads the CNI_* environment and stdin, so it is not called here. The point
    // is that a 0.2.x-shaped `Cni` impl still satisfies the trait.
    let result = SyncPlugin.add(Args::default())?;
    assert_eq!(result, CNIResult::default());
    Ok(())
}

/// Pins the remaining public paths. Constructing each is enough — a name that no longer
/// resolves is a compile error, which is what this file is for. Their behavior is
/// `rscni-types`' own tests' business.
#[test]
fn the_other_paths_still_resolve() {
    let _: PluginInfo = PluginInfo::default();
    let _: Error = Error::IncompatibleVersion(String::new());
    let _: NetConf = NetConf::default();
}

/// Pins that `Error` can still be matched exhaustively, with 0.2.1's variants and field
/// arities. 0.2.x users could write a wildcard-free match, so growing a variant or
/// adding `#[non_exhaustive]` is a breaking change — if this stops compiling, that is
/// what happened.
#[test]
fn error_is_still_exhaustively_matchable() {
    fn code(err: &Error) -> u32 {
        match err {
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

    let err = Error::Custom(100, String::new(), String::new());
    assert_eq!(code(&err), u32::from(&err));
}

struct AsyncTestPlugin;

#[async_trait]
impl AsyncCni for AsyncTestPlugin {
    async fn add(&self, _args: Args) -> Result<CNIResult, Error> {
        Ok(CNIResult::default())
    }

    async fn del(&self, _args: Args) -> Result<CNIResult, Error> {
        Ok(CNIResult::default())
    }

    async fn check(&self, _args: Args) -> Result<CNIResult, Error> {
        Ok(CNIResult::default())
    }

    async fn status(&self, _args: Args) -> Result<(), Error> {
        Ok(())
    }

    async fn gc(&self, _args: Args) -> Result<(), Error> {
        Ok(())
    }
}

#[tokio::test]
async fn async_plugin_builds_through_the_facade() -> Result<(), Box<dyn std::error::Error>> {
    let _plugin = AsyncPlugin::default();
    let result = AsyncTestPlugin.add(Args::default()).await?;
    assert_eq!(result, CNIResult::default());
    Ok(())
}
