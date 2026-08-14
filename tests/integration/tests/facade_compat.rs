//! Pins that every path and trait shape a 0.2.x user wrote still resolves through the
//! deprecated `rscni` facade.
//!
//! Everything below is written against `rscni::*` rather than `rscni_plugin::*`. If this
//! stops compiling, the facade no longer re-exports what it was published to re-export.
//! Signatures are not pinned: `rscni` is a path dependency on the workspace crate, so a
//! breaking change to `rscni-plugin` is respelled here rather than caught. Only a
//! dev-dependency on the published `rscni` would catch that.
//!
//! One path here is wider than 0.2.x: `rscni::version` was `pub(crate)` then, so
//! `PluginInfo` was unreachable. The shim exposes it because `rscni-plugin` does. That is
//! additive, and pinning it costs nothing.
//!
//! One is narrower: `rscni::types::ArgsBuilder` resolved in 0.2.x but could never be
//! instantiated from outside, so it is gone rather than pinned.
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
use rscni::version::{PluginInfo, SpecVersion};

struct SyncPlugin;

impl Cni for SyncPlugin {
    fn add(&self, args: Args) -> Result<CNIResult, Error> {
        // Exercise the accessors, not just the type names.
        let _ = args.container_id();
        let _ = args.netns();
        let _ = args.ifname();
        let _ = args.args();
        let _ = args.path();
        let config = args.config();

        Ok(config.prev_result.clone().unwrap_or_default())
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
    let _custom = Plugin::new(
        SpecVersion::new(1, 1, 0),
        vec![SpecVersion::new(1, 0, 0), SpecVersion::new(1, 1, 0)],
    );
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

/// Pins that every variant 0.2.x could name still exists with the same shape.
#[test]
fn error_variants_still_resolve() {
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
            _ => 0,
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
