use std::{env, path::PathBuf};

use rscni_types::{
    error::Error,
    types::{
        CNI_CONTAINERID, CNI_IFNAME, CNI_NETNS, CNI_PATH, Cmd, ContainerId, InterfaceName, NetConf,
    },
};

use crate::args::Args;

#[derive(Debug)]
pub struct ArgsBuilder {
    container_id: Option<ContainerId>,
    netns: Option<PathBuf>,
    ifname: Option<InterfaceName>,
    args: Option<String>,
    path: Vec<PathBuf>,
    config: Option<NetConf>,
}

impl ArgsBuilder {
    /// An empty builder: every field unset, as for a `VERSION` call.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            container_id: None,
            netns: None,
            ifname: None,
            args: None,
            path: Vec::new(),
            config: None,
        }
    }

    /// Sets `CNI_CONTAINERID`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEnvValue`] if `container_id` is empty or carries a
    /// character the spec's name rule rejects.
    pub fn container_id(mut self, container_id: &str) -> Result<Self, Error> {
        self.container_id = Some(ContainerId::try_from(container_id.to_string())?);
        Ok(self)
    }

    /// Sets `CNI_NETNS`.
    #[must_use]
    pub fn netns(mut self, netns: &str) -> Self {
        self.netns = Some(PathBuf::from(netns));
        self
    }

    /// Sets `CNI_IFNAME`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEnvValue`] if `ifname` breaks the kernel's interface
    /// naming rules (empty, over 15 characters, `.`/`..`, or containing `/`, `:` or
    /// whitespace).
    pub fn ifname(mut self, ifname: &str) -> Result<Self, Error> {
        self.ifname = Some(InterfaceName::try_from(ifname.to_string())?);
        Ok(self)
    }

    /// Sets `CNI_ARGS`.
    #[must_use]
    pub fn args(mut self, args: &str) -> Self {
        self.args = Some(args.to_string());
        self
    }

    /// Sets `CNI_PATH`, split on the OS-specific list separator.
    #[must_use]
    pub fn path(mut self, paths: &str) -> Self {
        self.path = env::split_paths(paths).collect();
        self
    }

    /// Sets the stdin network configuration from its JSON text.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FailedToDecode`] if `config` is not JSON that deserializes
    /// into a [`NetConf`].
    pub fn config(mut self, config: &str) -> Result<Self, Error> {
        self.config =
            serde_json::from_str(config).map_err(|e| Error::FailedToDecode(e.to_string()))?;
        Ok(self)
    }

    /// Checks the environment-sourced fields against the spec's parameter matrix for `cmd`.
    ///
    /// | command | required |
    /// |---|---|
    /// | ADD, CHECK | `CNI_CONTAINERID`, `CNI_NETNS`, `CNI_IFNAME` |
    /// | DEL | `CNI_CONTAINERID`, `CNI_IFNAME` — `CNI_NETNS` optional, as DEL must
    ///   complete after the namespace is gone |
    /// | GC | `CNI_PATH` |
    /// | STATUS, VERSION | nothing |
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEnvValue`] naming every variable `cmd` requires and
    /// the builder lacks.
    pub fn validate(self, cmd: Cmd) -> Result<Self, Error> {
        let mut missing = Vec::new();
        match cmd {
            Cmd::Add | Cmd::Check | Cmd::Del => {
                if self.container_id.is_none() {
                    missing.push(CNI_CONTAINERID);
                }
                if self.netns.is_none() && !matches!(cmd, Cmd::Del) {
                    missing.push(CNI_NETNS);
                }
                if self.ifname.is_none() {
                    missing.push(CNI_IFNAME);
                }
            }
            Cmd::Gc if self.path.is_empty() => missing.push(CNI_PATH),
            _ => {}
        }
        if missing.is_empty() {
            Ok(self)
        } else {
            Err(Error::missing_env(&missing))
        }
    }

    /// Consumes the builder and produces the [`Args`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidNetworkConfig`] (error code 7) if no configuration was
    /// set, or the configuration carries no usable network name.
    pub fn build(self) -> Result<Args, Error> {
        // A stdin of literal JSON `null` deserializes into no configuration, not an error.
        let config = self.config.ok_or_else(|| {
            Error::InvalidNetworkConfig("network configuration is required on stdin".to_string())
        })?;
        config.validate_name()?;
        Ok(Args {
            container_id: self.container_id,
            netns: self.netns,
            ifname: self.ifname,
            args: self.args,
            path: self.path,
            config,
        })
    }
}

impl Default for ArgsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    const CONFIG: &str = r#"{"cniVersion":"1.1.0","name":"test-net","type":"test"}"#;

    #[test]
    fn build_carries_every_field_through() -> Result<(), Error> {
        let args = ArgsBuilder::new()
            .container_id("c1")?
            .netns("/run/netns/aaaa")
            .ifname("eth0")?
            .args("K=V;FOO=bar")
            .path("/opt/cni/bin:/usr/lib/cni")
            .config(CONFIG)?
            .build()?;

        assert_eq!(args.container_id().map(ContainerId::as_ref), Some("c1"));
        assert_eq!(args.netns(), Some(&PathBuf::from("/run/netns/aaaa")));
        assert_eq!(args.ifname().map(InterfaceName::as_ref), Some("eth0"));
        assert_eq!(args.args(), Some("K=V;FOO=bar"));
        assert_eq!(
            args.path(),
            [PathBuf::from("/opt/cni/bin"), PathBuf::from("/usr/lib/cni")]
        );
        assert_eq!(args.config().name, "test-net");
        Ok(())
    }

    #[test]
    fn build_defaults_the_unset_environment_fields() -> Result<(), Error> {
        let args = ArgsBuilder::new().config(CONFIG)?.build()?;

        assert!(args.container_id().is_none());
        assert!(args.netns().is_none());
        assert!(args.ifname().is_none());
        assert!(args.args().is_none());
        assert!(args.path().is_empty());
        Ok(())
    }

    #[test]
    fn build_without_config_is_invalid_network_config() {
        let result = ArgsBuilder::new().build();
        assert!(
            matches!(result, Err(Error::InvalidNetworkConfig(_))),
            "got: {result:?}"
        );
    }

    // A literal `null` on stdin decodes to no configuration rather than failing, so it
    // reaches the same "configuration is required" path as never calling `config`.
    #[test]
    fn build_with_null_config_is_invalid_network_config() -> Result<(), Error> {
        let result = ArgsBuilder::new().config("null")?.build();
        assert!(
            matches!(result, Err(Error::InvalidNetworkConfig(_))),
            "got: {result:?}"
        );
        Ok(())
    }

    #[rstest]
    #[case::not_json("{ not json")]
    #[case::wrong_shape(r#"{"cniVersion":42}"#)]
    fn config_rejects_undecodable_json(#[case] json: &str) {
        let result = ArgsBuilder::new().config(json);
        assert!(
            matches!(result, Err(Error::FailedToDecode(_))),
            "got: {result:?}"
        );
    }

    #[rstest]
    #[case::empty_name(r#"{"cniVersion":"1.1.0","name":"","type":"test"}"#)]
    #[case::bad_name_chars(r#"{"cniVersion":"1.1.0","name":"bad name","type":"test"}"#)]
    fn build_rejects_config_without_a_usable_name(#[case] json: &str) -> Result<(), Error> {
        let result = ArgsBuilder::new().config(json)?.build();
        assert!(
            matches!(result, Err(Error::InvalidNetworkConfig(_))),
            "got: {result:?}"
        );
        Ok(())
    }

    #[rstest]
    #[case::bad_chars("bad*id")]
    #[case::empty("")]
    fn container_id_holds_the_value_to_the_spec_rule(#[case] value: &str) {
        let result = ArgsBuilder::new().container_id(value);
        assert!(
            matches!(result, Err(Error::InvalidEnvValue(_))),
            "got: {result:?}"
        );
    }

    #[rstest]
    #[case::slash_or_colon("eth0:0")]
    #[case::whitespace("eth 0")]
    #[case::too_long("interface-name-too-long")]
    #[case::empty("")]
    fn ifname_holds_the_value_to_the_kernel_rule(#[case] value: &str) {
        let result = ArgsBuilder::new().ifname(value);
        assert!(
            matches!(result, Err(Error::InvalidEnvValue(_))),
            "got: {result:?}"
        );
    }

    // `path` splits on the OS list separator, empty segments included, matching
    // `env::split_paths`.
    #[test]
    fn path_splits_on_the_list_separator() {
        let args = ArgsBuilder::new().path("/a::/b");
        assert_eq!(
            args.path,
            [PathBuf::from("/a"), PathBuf::from(""), PathBuf::from("/b")]
        );
    }

    fn matrix_builder(
        container_id: &str,
        netns: &str,
        ifname: &str,
        path: &str,
    ) -> Result<ArgsBuilder, Error> {
        let mut builder = ArgsBuilder::new();
        if !container_id.is_empty() {
            builder = builder.container_id(container_id)?;
        }
        if !netns.is_empty() {
            builder = builder.netns(netns);
        }
        if !ifname.is_empty() {
            builder = builder.ifname(ifname)?;
        }
        if !path.is_empty() {
            builder = builder.path(path);
        }
        Ok(builder)
    }

    #[rstest]
    #[case::add_required_only(Cmd::Add, "c1", "/ns", "eth0", "")]
    #[case::check_required_only(Cmd::Check, "c1", "/ns", "eth0", "")]
    // CNI_NETNS is optional for DEL: teardown must complete after the netns is gone.
    #[case::del_without_netns(Cmd::Del, "c1", "", "eth0", "")]
    #[case::gc_with_path(Cmd::Gc, "", "", "", "/opt/cni/bin")]
    #[case::status_bare(Cmd::Status, "", "", "", "")]
    #[case::version_bare(Cmd::Version, "", "", "", "")]
    fn validate_accepts_a_complete_environment(
        #[case] cmd: Cmd,
        #[case] container_id: &str,
        #[case] netns: &str,
        #[case] ifname: &str,
        #[case] path: &str,
    ) -> Result<(), Error> {
        matrix_builder(container_id, netns, ifname, path)?.validate(cmd)?;
        Ok(())
    }

    #[rstest]
    #[case::add_without_netns(Cmd::Add, "c1", "", "eth0", "", "CNI_NETNS")]
    #[case::add_without_container_id(Cmd::Add, "", "/ns", "eth0", "", "CNI_CONTAINERID")]
    #[case::del_without_container_id(Cmd::Del, "", "", "eth0", "", "CNI_CONTAINERID")]
    #[case::del_without_ifname(Cmd::Del, "c1", "", "", "", "CNI_IFNAME")]
    #[case::gc_without_path(Cmd::Gc, "", "", "", "", "CNI_PATH")]
    // Missing variables are reported together, in the reference's wording and order.
    #[case::add_bare(Cmd::Add, "", "", "", "", "[CNI_CONTAINERID,CNI_NETNS,CNI_IFNAME]")]
    fn validate_names_every_missing_variable(
        #[case] cmd: Cmd,
        #[case] container_id: &str,
        #[case] netns: &str,
        #[case] ifname: &str,
        #[case] path: &str,
        #[case] missing: &str,
    ) -> Result<(), Error> {
        match matrix_builder(container_id, netns, ifname, path)?.validate(cmd) {
            Err(Error::InvalidEnvValue(details)) => {
                assert!(
                    details.contains(missing),
                    "details must name {missing}: {details}"
                );
            }
            other => panic!("must fail naming {missing}, got: {other:?}"),
        }
        Ok(())
    }
}
