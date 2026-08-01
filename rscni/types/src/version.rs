//! Plugin version reporting and negotiation.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    types::{Cmd, NetConf},
};

/// `PluginInfo` is for supported CNI plugin version information.
/// Please see <https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md#version>.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginInfo {
    pub(crate) cni_version: String,
    pub(crate) supported_versions: Vec<String>,
}

impl PluginInfo {
    #[must_use]
    pub fn new(cni_version: &str, supported_versions: Vec<String>) -> Self {
        Self {
            cni_version: cni_version.to_string(),
            supported_versions,
        }
    }
}

impl Default for PluginInfo {
    fn default() -> Self {
        Self {
            cni_version: SpecVersion::CURRENT.to_string(),
            // Spelled as literals, not derived from `CURRENT`: this is the history of
            // versions the crate can speak, which only ever grows. When `CURRENT` is
            // bumped, the new version is appended here — the old entries must survive,
            // or configs declaring them would silently start being rejected.
            supported_versions: vec![
                "0.3.1".to_string(),
                "0.4.0".to_string(),
                "1.0.0".to_string(),
                "1.1.0".to_string(),
            ],
        }
    }
}

impl PluginInfo {
    /// Returns the CNI specification version this plugin reports as its own.
    #[must_use]
    pub fn cni_version(&self) -> &str {
        &self.cni_version
    }

    /// Returns every CNI specification version this plugin can be asked to speak.
    #[must_use]
    pub fn supported_versions(&self) -> &[String] {
        &self.supported_versions
    }

    /// Checks that `ver` is a version this plugin can speak — a member of
    /// [`supported_versions`](Self::supported_versions), which is the whole test the
    /// reference implementation's reconciler applies. The plugin's own
    /// [`cni_version`](Self::cni_version) grants nothing by itself: it describes the
    /// plugin's VERSION output, not an implicit extra supported entry.
    ///
    /// A runtime uses this against the [`PluginInfo`] it got back from `VERSION` to
    /// confirm a plugin can handle the `cniVersion` in a network configuration before
    /// invoking it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IncompatibleVersion`] if `ver` is not a supported version.
    /// The details name the supported set — like the reference implementation's
    /// wording — so a runtime's diagnostics show what would have been accepted.
    pub fn validate(&self, ver: &str) -> Result<(), Error> {
        if !self.supported_versions.iter().any(|p| p.eq(ver)) {
            return Err(Error::IncompatibleVersion(format!(
                "config is \"{ver}\", plugin supports {:?}",
                self.supported_versions
            )));
        }
        Ok(())
    }

    /// Runs the version negotiation every dispatchable operation performs: `conf`'s
    /// declared version must permit `cmd` and be one this plugin speaks. Returns the
    /// canonical version string the ADD result echoes.
    ///
    /// [`SpecVersion::allows`] is consulted unconditionally — it is total over
    /// [`Cmd`], so which operations have a version floor stays its knowledge alone,
    /// and no caller can forget the gate. The floor is checked before the
    /// supported-version membership, like the reference implementation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FailedToDecode`] for a malformed declared version, and
    /// [`Error::IncompatibleVersion`] when that version predates `cmd` or is not one
    /// this plugin supports.
    pub fn negotiate(&self, conf: &NetConf, cmd: Cmd) -> Result<String, Error> {
        let version = conf.version()?;
        version.allows(cmd)?;
        let version = version.to_string();
        self.validate(&version)?;
        Ok(version)
    }
}

/// A parsed CNI specification version: dotted numbers of up to three components
/// (`major[.minor[.patch]]`), missing components comparing as zero.
///
/// The specification introduces operations at particular versions, and the reference
/// implementation refuses to dispatch an operation for a config version predating it;
/// the derived `Ord` is what those gates compare with. Both sides of the protocol need
/// the same ordering — a plugin to refuse an operation its config version predates, a
/// runtime to know which operations it may issue — which is why the type lives in the
/// shared types crate.
///
/// ```
/// use std::str::FromStr;
/// use rscni_types::{types::Cmd, version::SpecVersion};
///
/// let config_version = SpecVersion::from_str("0.3.1")?;
/// assert!(config_version.allows(Cmd::Check).is_err());
/// # Ok::<(), rscni_types::error::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SpecVersion(u32, u32, u32);

impl SpecVersion {
    /// The specification version this crate currently targets: what to declare when
    /// producing new configurations or results, and what [`Default`] returns. Bumped
    /// as the crate adopts newer specification revisions.
    pub const CURRENT: Self = Self(1, 1, 0);
    /// The lowest config version for which CHECK exists (introduced in 0.4.0).
    const CHECK_FLOOR: Self = Self(0, 4, 0);
    /// The lowest config version for which GC and STATUS exist (introduced in 1.1.0).
    const GC_AND_STATUS_FLOOR: Self = Self(1, 1, 0);

    /// Checks that `cmd` exists at this specification version.
    ///
    /// The specification introduces operations at particular versions — CHECK at
    /// 0.4.0, GC and STATUS at 1.1.0 — and the reference implementation refuses to
    /// dispatch an operation for a config version predating it, ahead of the
    /// supported-version membership check (a plugin may well support 0.3.x for
    /// ADD/DEL while CHECK still cannot exist there). Operations with no floor —
    /// including any a future specification adds — always pass.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IncompatibleVersion`] (error code 1) with the reference
    /// implementation's wording, e.g. `config version does not allow CHECK`.
    pub fn allows(self, cmd: Cmd) -> Result<(), Error> {
        let floor = match cmd {
            Cmd::Check => Self::CHECK_FLOOR,
            Cmd::Gc | Cmd::Status => Self::GC_AND_STATUS_FLOOR,
            _ => return Ok(()),
        };
        if self < floor {
            return Err(Error::IncompatibleVersion(format!(
                "config version does not allow {}",
                <&str>::from(cmd)
            )));
        }
        Ok(())
    }
}

impl Default for SpecVersion {
    /// Returns [`SpecVersion::CURRENT`] — the version for anything newly produced.
    /// Note that an *absent* version in an existing configuration does not mean this;
    /// it means 0.1.0, which [`NetConf::version`] resolves.
    ///
    /// [`NetConf::version`]: crate::types::NetConf::version
    fn default() -> Self {
        Self::CURRENT
    }
}

impl std::fmt::Display for SpecVersion {
    /// Formats the canonical three-component form. Parsing does not remember how many
    /// components the input spelled out, so a non-canonical `"0.4"` round-trips to
    /// `"0.4.0"`; every version the specification has actually released is
    /// three-component and round-trips unchanged.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

impl FromStr for SpecVersion {
    type Err = Error;

    /// A malformed version is a decode failure (error code 6), matching how the
    /// reference implementation classifies it.
    fn from_str(s: &str) -> Result<Self, Error> {
        // A single pass over the input; an empty string yields one empty part, which
        // fails the numeric parse like any other malformed component.
        let invalid = || Error::FailedToDecode(format!("invalid version format: {s}"));
        let mut parts = s.split('.');
        let mut components = [0; 3];
        for component in &mut components {
            if let Some(part) = parts.next() {
                *component = part.parse().map_err(|_| invalid())?;
            }
        }
        if parts.next().is_some() {
            return Err(invalid());
        }
        Ok(Self(components[0], components[1], components[2]))
    }
}

#[cfg(test)]
mod tests {
    use super::{Cmd, FromStr, PluginInfo, SpecVersion};
    use crate::error::Error;
    use rstest::rstest;

    #[rstest]
    #[case(PluginInfo::default(), "1.1.0", true)]
    #[case(PluginInfo::default(), "1.0.0", true)]
    #[case(PluginInfo::default(), "0.1.0", false)]
    // The reference reconciler consults the supported list alone: the plugin's own
    // version is not an implicit extra entry.
    #[case(PluginInfo::new("1.1.0", vec!["1.0.0".to_string()]), "1.1.0", false)]
    fn plugin_info_validate(#[case] info: PluginInfo, #[case] ver: &str, #[case] ok: bool) {
        match info.validate(ver) {
            Ok(()) => assert!(ok, "{ver} must be rejected"),
            Err(Error::IncompatibleVersion(details)) => {
                assert!(!ok, "{ver} must be accepted, got: {details}");
                // The details must name the rejected version and the supported set.
                assert!(
                    details.contains(&format!("\"{ver}\""))
                        && details.contains(&format!("{:?}", info.supported_versions())),
                    "got: {details}"
                );
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[rstest]
    #[case("0.4.0", SpecVersion::CHECK_FLOOR, std::cmp::Ordering::Equal)]
    #[case("0.3.1", SpecVersion::CHECK_FLOOR, std::cmp::Ordering::Less)]
    #[case("1.0.0", SpecVersion::GC_AND_STATUS_FLOOR, std::cmp::Ordering::Less)]
    #[case("1.1.0", SpecVersion::GC_AND_STATUS_FLOOR, std::cmp::Ordering::Equal)]
    #[case("1.2.0", SpecVersion::GC_AND_STATUS_FLOOR, std::cmp::Ordering::Greater)]
    // Missing components compare as zero: "0.4" is 0.4.0, "1" is 1.0.0.
    #[case("0.4", SpecVersion::CHECK_FLOOR, std::cmp::Ordering::Equal)]
    #[case("1", SpecVersion::GC_AND_STATUS_FLOOR, std::cmp::Ordering::Less)]
    fn spec_version_ordering(
        #[case] version: &str,
        #[case] floor: SpecVersion,
        #[case] expected: std::cmp::Ordering,
    ) -> Result<(), Error> {
        assert_eq!(SpecVersion::from_str(version)?.cmp(&floor), expected);
        Ok(())
    }

    #[rstest]
    #[case("1.1.0", "1.1.0")]
    #[case("0.4", "0.4.0")]
    #[case("1", "1.0.0")]
    fn spec_version_displays_canonical(
        #[case] input: &str,
        #[case] expected: &str,
    ) -> Result<(), Error> {
        assert_eq!(SpecVersion::from_str(input)?.to_string(), expected);
        Ok(())
    }

    #[rstest]
    #[case(Cmd::Check, "0.3.1", false)]
    #[case(Cmd::Check, "0.4.0", true)]
    #[case(Cmd::Gc, "1.0.0", false)]
    #[case(Cmd::Gc, "1.1.0", true)]
    #[case(Cmd::Status, "1.0.0", false)]
    #[case(Cmd::Status, "1.1.0", true)]
    // ADD and DEL exist since the first specification version: no floor.
    #[case(Cmd::Add, "0.1.0", true)]
    #[case(Cmd::Del, "0.1.0", true)]
    fn spec_version_allows(
        #[case] cmd: Cmd,
        #[case] version: &str,
        #[case] allowed: bool,
    ) -> Result<(), Error> {
        let result = SpecVersion::from_str(version)?.allows(cmd);
        assert_eq!(result.is_ok(), allowed);
        if let Err(Error::IncompatibleVersion(details)) = result {
            assert_eq!(
                details,
                format!("config version does not allow {}", <&str>::from(cmd))
            );
        }
        Ok(())
    }

    #[test]
    fn spec_version_default_is_current() {
        assert_eq!(SpecVersion::default(), SpecVersion::CURRENT);
        // The default plugin claims the crate's current target version.
        assert_eq!(
            PluginInfo::default().cni_version,
            SpecVersion::CURRENT.to_string()
        );
    }

    #[rstest]
    #[case("")]
    #[case("not-a-version")]
    #[case("1.2.3.4")]
    #[case("1..0")]
    #[case("-1.0.0")]
    fn spec_version_rejects_malformed(#[case] version: &str) {
        assert!(matches!(
            SpecVersion::from_str(version),
            Err(Error::FailedToDecode(_))
        ));
    }
}
