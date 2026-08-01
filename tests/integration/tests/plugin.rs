use rscni::types::{CNI_ARGS, CNI_COMMAND, CNI_CONTAINERID, CNI_IFNAME, CNI_NETNS, CNI_PATH, Cmd};
use serde_json::Value;
use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy)]
enum PluginType {
    Sync,
    Async,
}

impl PluginType {
    const fn name(&self) -> &str {
        match self {
            Self::Sync => "rscni-debug",
            Self::Async => "async-rscni-debug",
        }
    }
}

/// Directory the current profile's artifacts are in, e.g. `<workspace>/target/debug`.
///
/// Derived from this test binary's own location rather than from `CARGO_MANIFEST_DIR`,
/// since the target directory is not under this package and need not be under the
/// workspace root at all — `CARGO_TARGET_DIR` can put it anywhere.
fn target_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut dir = env::current_exe()?;
    dir.pop(); // the test binary itself
    if dir.ends_with("deps") {
        dir.pop();
    }
    Ok(dir)
}

/// Builds both example plugins, once per test binary.
///
/// Every test needs a plugin binary, but `cargo build` takes the target directory's
/// build lock, so calling it per test would serialize the whole suite behind N
/// no-op builds. Both packages go in one invocation so that `rscni-plugin` is resolved
/// under a single feature set instead of being rebuilt for each.
fn build_plugins() {
    static BUILT: OnceLock<()> = OnceLock::new();
    BUILT.get_or_init(|| {
        let output = Command::new("cargo")
            .args([
                "build",
                "--package",
                PluginType::Sync.name(),
                "--package",
                PluginType::Async.name(),
            ])
            .output()
            .unwrap_or_else(|e| panic!("Failed to spawn cargo build: {e}"));

        assert!(
            output.status.success(),
            "Failed to build the debug plugins: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    });
}

/// Test helper to build the debug plugin
fn build_plugin(plugin_type: PluginType) -> Result<PathBuf, Box<dyn std::error::Error>> {
    build_plugins();

    let plugin_path = target_dir()?.join(plugin_type.name());
    assert!(
        plugin_path.exists(),
        "Plugin binary not found: {}",
        plugin_path.display()
    );
    Ok(plugin_path)
}

/// Test helper to run plugin with environment and stdin
fn run_plugin(
    plugin_path: &PathBuf,
    cmd: Cmd,
    net_conf: &str,
    container_id: &str,
    netns: &str,
    ifname: &str,
    args: &str,
) -> Result<(bool, String, String), Box<dyn std::error::Error>> {
    // Empty means "omit the variable": the plugin treats unset and empty identically
    // (as the spec's reference implementation does), and omitting is what a spec-strict
    // runtime actually sends for optional parameters.
    let vars = [
        (CNI_COMMAND, <&str>::from(cmd)),
        (CNI_CONTAINERID, container_id),
        (CNI_NETNS, netns),
        (CNI_IFNAME, ifname),
        (CNI_ARGS, args),
        (CNI_PATH, "/opt/cni/bin"),
    ];
    let mut command = Command::new(plugin_path);
    for (key, value) in vars {
        if !value.is_empty() {
            command.env(key, value);
        }
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // VERSION command doesn't read stdin, so we only write for other commands
    // to avoid BrokenPipe errors when the plugin exits before reading
    if cmd != Cmd::Version {
        let stdin = child.stdin.as_mut().ok_or("Failed to open stdin")?;
        stdin.write_all(net_conf.as_bytes())?;
    }

    let output = child.wait_with_output()?;

    Ok((
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    ))
}

/// Common test helper for version command
fn test_version_command_helper(plugin_type: PluginType) -> Result<(), Box<dyn std::error::Error>> {
    let plugin_path = build_plugin(plugin_type)?;

    let net_conf = format!(
        r#"{{"cniVersion":"1.1.0","name":"test","type":"{}"}}"#,
        plugin_type.name()
    );

    let (success, stdout, stderr) =
        run_plugin(&plugin_path, Cmd::Version, &net_conf, "", "", "", "")?;

    assert!(success, "Plugin failed: {stderr}");

    let version_info: Value = serde_json::from_str(&stdout)?;
    assert!(version_info["cniVersion"].is_string());
    assert!(version_info["supportedVersions"].is_array());
    Ok(())
}

/// Common test helper for ADD command
fn test_add_command_helper(plugin_type: PluginType) -> Result<(), Box<dyn std::error::Error>> {
    let plugin_path = build_plugin(plugin_type)?;
    let temp_dir = tempfile::tempdir()?;
    let output_dir = temp_dir.path().to_path_buf();

    let net_conf = format!(
        r#"{{
        "cniVersion": "1.1.0",
        "name": "test-network",
        "type": "{}",
        "cniOutput": "{}"
    }}"#,
        plugin_type.name(),
        output_dir.display()
    );

    let container_id = format!("{}-container-123", plugin_type.name());
    let (success, stdout, stderr) = run_plugin(
        &plugin_path,
        Cmd::Add,
        &net_conf,
        &container_id,
        "/var/run/netns/test",
        "eth0",
        "",
    )?;

    assert!(success, "Plugin failed: {stderr}");

    // Verify result
    let result: Value = serde_json::from_str(&stdout)?;
    assert!(result.is_object(), "Result should be a JSON object");

    // Verify debug file was created
    let debug_file = output_dir.join(format!("{container_id}-Add"));
    assert!(
        debug_file.exists(),
        "Debug file should exist at {}",
        debug_file.display()
    );

    let debug_content = fs::read_to_string(&debug_file)?;
    assert!(debug_content.contains("CNI_COMMAND: Add"));
    assert!(debug_content.contains(&format!("CNI_CONTAINERID: {container_id}")));
    assert!(debug_content.contains("CNI_IFNAME: eth0"));
    Ok(())
}

/// Common test helper for DEL command
fn test_del_command_helper(plugin_type: PluginType) -> Result<(), Box<dyn std::error::Error>> {
    let plugin_path = build_plugin(plugin_type)?;
    let temp_dir = tempfile::tempdir()?;
    let output_dir = temp_dir.path().to_path_buf();

    let net_conf = format!(
        r#"{{
        "cniVersion": "1.1.0",
        "name": "test-network",
        "type": "{}",
        "cniOutput": "{}"
    }}"#,
        plugin_type.name(),
        output_dir.display()
    );

    let container_id = format!("{}-container-456", plugin_type.name());
    let (success, stdout, stderr) = run_plugin(
        &plugin_path,
        Cmd::Del,
        &net_conf,
        &container_id,
        "/var/run/netns/test",
        "eth0",
        "",
    )?;

    assert!(success, "Plugin failed: {stderr}");

    // DEL should return empty or default result
    if !stdout.trim().is_empty() {
        let result: Value = serde_json::from_str(&stdout)?;
        assert!(result.is_object());
    }

    // Verify debug file
    let debug_file = output_dir.join(format!("{container_id}-Del"));
    assert!(debug_file.exists());

    let debug_content = fs::read_to_string(&debug_file)?;
    assert!(debug_content.contains("CNI_COMMAND: Del"));
    assert!(debug_content.contains(&format!("CNI_CONTAINERID: {container_id}")));
    Ok(())
}

/// DEL must succeed without `CNI_NETNS`: the spec makes it optional there, because
/// teardown has to complete even after the namespace is gone.
fn test_del_without_netns_helper(
    plugin_type: PluginType,
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin_path = build_plugin(plugin_type)?;
    let temp_dir = tempfile::tempdir()?;
    let output_dir = temp_dir.path().to_path_buf();

    let net_conf = format!(
        r#"{{"cniVersion":"1.1.0","name":"test-network","type":"{}","cniOutput":"{}"}}"#,
        plugin_type.name(),
        output_dir.display()
    );

    let container_id = format!("{}-container-no-netns", plugin_type.name());
    let (success, _stdout, stderr) = run_plugin(
        &plugin_path,
        Cmd::Del,
        &net_conf,
        &container_id,
        "",
        "eth0",
        "",
    )?;

    assert!(success, "DEL without CNI_NETNS must succeed: {stderr}");
    Ok(())
}

/// Common test helper for CHECK command
fn test_check_command_helper(plugin_type: PluginType) -> Result<(), Box<dyn std::error::Error>> {
    let plugin_path = build_plugin(plugin_type)?;
    let temp_dir = tempfile::tempdir()?;
    let output_dir = temp_dir.path().to_path_buf();

    let net_conf = format!(
        r#"{{
        "cniVersion": "1.1.0",
        "name": "test-network",
        "type": "{}",
        "cniOutput": "{}"
    }}"#,
        plugin_type.name(),
        output_dir.display()
    );

    let container_id = format!("{}-container-789", plugin_type.name());
    let (success, _stdout, stderr) = run_plugin(
        &plugin_path,
        Cmd::Check,
        &net_conf,
        &container_id,
        "/var/run/netns/test",
        "eth0",
        "",
    )?;

    assert!(success, "Plugin failed: {stderr}");

    // Verify debug file
    let debug_file = output_dir.join(format!("{container_id}-Check"));
    assert!(debug_file.exists());

    let debug_content = fs::read_to_string(&debug_file)?;
    assert!(debug_content.contains("CNI_COMMAND: Check"));
    assert!(debug_content.contains(&format!("CNI_CONTAINERID: {container_id}")));
    Ok(())
}

/// Common test helper for CNI version compatibility
fn test_cni_version_compatibility_helper(
    plugin_type: PluginType,
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin_path = build_plugin(plugin_type)?;
    let temp_dir = tempfile::tempdir()?;
    let output_dir = temp_dir.path().to_path_buf();

    for version in &["0.4.0", "1.0.0", "1.1.0"] {
        let net_conf = format!(
            r#"{{"cniVersion":"{}","name":"test","type":"{}","cniOutput":"{}"}}"#,
            version,
            plugin_type.name(),
            output_dir.display()
        );

        let (success, stdout, stderr) = run_plugin(
            &plugin_path,
            Cmd::Add,
            &net_conf,
            &format!("container-{version}"),
            "/var/run/netns/test",
            "eth0",
            "",
        )?;

        assert!(success, "Plugin failed for version {version}: {stderr}");

        let result: Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|_| panic!("Failed to parse result for version {version}"));
        assert!(
            result.is_object(),
            "Result should be a JSON object for version {version}"
        );
    }
    Ok(())
}

/// Common test helper for prevResult
fn test_with_prev_result_helper(plugin_type: PluginType) -> Result<(), Box<dyn std::error::Error>> {
    let plugin_path = build_plugin(plugin_type)?;
    let temp_dir = tempfile::tempdir()?;
    let output_dir = temp_dir.path().to_path_buf();

    let ip_address = match plugin_type {
        PluginType::Sync => "10.1.2.3/24",
        PluginType::Async => "192.168.1.100/24",
    };
    let gateway = match plugin_type {
        PluginType::Sync => "10.1.2.1",
        PluginType::Async => "192.168.1.1",
    };

    let net_conf = format!(
        r#"{{
        "cniVersion": "1.1.0",
        "name": "test-network",
        "type": "{}",
        "cniOutput": "{}",
        "prevResult": {{
            "ips": [{{
                "address": "{}",
                "gateway": "{}"
            }}],
            "interfaces": [],
            "routes": [],
            "dns": null
        }}
    }}"#,
        plugin_type.name(),
        output_dir.display(),
        ip_address,
        gateway
    );

    let container_id = format!("{}-prev-result-test", plugin_type.name());
    let (success, stdout, stderr) = run_plugin(
        &plugin_path,
        Cmd::Add,
        &net_conf,
        &container_id,
        "/var/run/netns/test",
        "eth0",
        "",
    )?;

    assert!(success, "Plugin failed: {stderr}");

    // Plugin should return prevResult if provided
    let result: Value = serde_json::from_str(&stdout)?;
    assert!(result["ips"].is_array());
    let ips = result["ips"].as_array().ok_or("ips should be an array")?;
    assert!(!ips.is_empty(), "Should return prevResult IPs");
    assert_eq!(ips[0]["address"], ip_address);
    Ok(())
}

// Sync plugin tests
#[test]
fn test_plugin_version_command() -> Result<(), Box<dyn std::error::Error>> {
    test_version_command_helper(PluginType::Sync)
}

#[test]
fn test_plugin_add_command() -> Result<(), Box<dyn std::error::Error>> {
    test_add_command_helper(PluginType::Sync)
}

#[test]
fn test_plugin_del_command() -> Result<(), Box<dyn std::error::Error>> {
    test_del_command_helper(PluginType::Sync)
}

#[test]
fn test_plugin_check_command() -> Result<(), Box<dyn std::error::Error>> {
    test_check_command_helper(PluginType::Sync)
}

#[test]
fn test_plugin_del_without_netns() -> Result<(), Box<dyn std::error::Error>> {
    test_del_without_netns_helper(PluginType::Sync)
}

#[test]
fn test_cni_version_compatibility() -> Result<(), Box<dyn std::error::Error>> {
    test_cni_version_compatibility_helper(PluginType::Sync)
}

#[test]
fn test_plugin_with_prev_result() -> Result<(), Box<dyn std::error::Error>> {
    test_with_prev_result_helper(PluginType::Sync)
}

// Async plugin tests
#[test]
fn test_async_plugin_version_command() -> Result<(), Box<dyn std::error::Error>> {
    test_version_command_helper(PluginType::Async)
}

#[test]
fn test_async_plugin_add_command() -> Result<(), Box<dyn std::error::Error>> {
    test_add_command_helper(PluginType::Async)
}

#[test]
fn test_async_plugin_del_command() -> Result<(), Box<dyn std::error::Error>> {
    test_del_command_helper(PluginType::Async)
}

#[test]
fn test_async_plugin_check_command() -> Result<(), Box<dyn std::error::Error>> {
    test_check_command_helper(PluginType::Async)
}

#[test]
fn test_async_plugin_del_without_netns() -> Result<(), Box<dyn std::error::Error>> {
    test_del_without_netns_helper(PluginType::Async)
}

#[test]
fn test_async_plugin_with_prev_result() -> Result<(), Box<dyn std::error::Error>> {
    test_with_prev_result_helper(PluginType::Async)
}
