use serde_json::Value;
use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Copy)]
enum PluginType {
    Sync,
    Async,
}

impl PluginType {
    fn name(&self) -> &str {
        match self {
            PluginType::Sync => "rscni-debug",
            PluginType::Async => "async-rscni-debug",
        }
    }
}

/// Test helper to build the debug plugin
fn build_plugin(plugin_type: PluginType) -> PathBuf {
    let output = Command::new("cargo")
        .args(["build", "--package", plugin_type.name()])
        .output()
        .unwrap_or_else(|_| panic!("Failed to build {} plugin", plugin_type.name()));

    assert!(
        output.status.success(),
        "Failed to build {} plugin: {}",
        plugin_type.name(),
        String::from_utf8_lossy(&output.stderr)
    );

    let mut plugin_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    plugin_path.push(format!("target/debug/{}", plugin_type.name()));
    assert!(plugin_path.exists(), "Plugin binary not found");
    plugin_path
}

/// Test helper to run plugin with environment and stdin
fn run_plugin(
    plugin_path: &PathBuf,
    command: &str,
    net_conf: &str,
    container_id: &str,
    netns: &str,
    ifname: &str,
    args: &str,
) -> (bool, String, String) {
    let mut child = Command::new(plugin_path)
        .env("CNI_COMMAND", command)
        .env("CNI_CONTAINERID", container_id)
        .env("CNI_NETNS", netns)
        .env("CNI_IFNAME", ifname)
        .env("CNI_ARGS", args)
        .env("CNI_PATH", "/opt/cni/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn plugin process");

    // VERSION command doesn't read stdin, so we only write for other commands
    // to avoid BrokenPipe errors when the plugin exits before reading
    if command != "VERSION" {
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");
        stdin
            .write_all(net_conf.as_bytes())
            .expect("Failed to write to stdin");
    }

    let output = child.wait_with_output().expect("Failed to wait for plugin");

    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

/// Common test helper for version command
fn test_version_command_helper(plugin_type: PluginType) {
    let plugin_path = build_plugin(plugin_type);

    let net_conf = format!(
        r#"{{"cniVersion":"1.1.0","name":"test","type":"{}"}}"#,
        plugin_type.name()
    );

    let (success, stdout, stderr) = run_plugin(&plugin_path, "VERSION", &net_conf, "", "", "", "");

    assert!(success, "Plugin failed: {}", stderr);

    let version_info: Value = serde_json::from_str(&stdout).expect("Failed to parse version info");
    assert!(version_info["cniVersion"].is_string());
    assert!(version_info["supportedVersions"].is_array());
}

/// Common test helper for ADD command
fn test_add_command_helper(plugin_type: PluginType) {
    let plugin_path = build_plugin(plugin_type);
    let _temp_dir = tempfile::tempdir().unwrap();
    let output_dir = _temp_dir.path().to_path_buf();

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
        "ADD",
        &net_conf,
        &container_id,
        "/var/run/netns/test",
        "eth0",
        "",
    );

    assert!(success, "Plugin failed: {}", stderr);

    // Verify result
    let result: Value = serde_json::from_str(&stdout).expect("Failed to parse result");
    assert!(result.is_object(), "Result should be a JSON object");

    // Verify debug file was created
    let debug_file = output_dir.join(format!("{}-Add", container_id));
    assert!(
        debug_file.exists(),
        "Debug file should exist at {}",
        debug_file.display()
    );

    let debug_content = fs::read_to_string(&debug_file).expect("Failed to read debug file");
    assert!(debug_content.contains("CNI_COMMAND: Add"));
    assert!(debug_content.contains(&format!("CNI_CONTAINERID: {}", container_id)));
    assert!(debug_content.contains("CNI_IFNAME: eth0"));
}

/// Common test helper for DEL command
fn test_del_command_helper(plugin_type: PluginType) {
    let plugin_path = build_plugin(plugin_type);
    let _temp_dir = tempfile::tempdir().unwrap();
    let output_dir = _temp_dir.path().to_path_buf();

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
        "DEL",
        &net_conf,
        &container_id,
        "/var/run/netns/test",
        "eth0",
        "",
    );

    assert!(success, "Plugin failed: {}", stderr);

    // DEL should return empty or default result
    if !stdout.trim().is_empty() {
        let result: Value = serde_json::from_str(&stdout).expect("Failed to parse result");
        assert!(result.is_object());
    }

    // Verify debug file
    let debug_file = output_dir.join(format!("{}-Del", container_id));
    assert!(debug_file.exists());

    let debug_content = fs::read_to_string(&debug_file).expect("Failed to read debug file");
    assert!(debug_content.contains("CNI_COMMAND: Del"));
    assert!(debug_content.contains(&format!("CNI_CONTAINERID: {}", container_id)));
}

/// Common test helper for CHECK command
fn test_check_command_helper(plugin_type: PluginType) {
    let plugin_path = build_plugin(plugin_type);
    let _temp_dir = tempfile::tempdir().unwrap();
    let output_dir = _temp_dir.path().to_path_buf();

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
        "CHECK",
        &net_conf,
        &container_id,
        "/var/run/netns/test",
        "eth0",
        "",
    );

    assert!(success, "Plugin failed: {}", stderr);

    // Verify debug file
    let debug_file = output_dir.join(format!("{}-Check", container_id));
    assert!(debug_file.exists());

    let debug_content = fs::read_to_string(&debug_file).expect("Failed to read debug file");
    assert!(debug_content.contains("CNI_COMMAND: Check"));
    assert!(debug_content.contains(&format!("CNI_CONTAINERID: {}", container_id)));
}

/// Common test helper for CNI version compatibility
fn test_cni_version_compatibility_helper(plugin_type: PluginType) {
    let plugin_path = build_plugin(plugin_type);
    let _temp_dir = tempfile::tempdir().unwrap();
    let output_dir = _temp_dir.path().to_path_buf();

    for version in &["1.0.0", "1.1.0"] {
        let net_conf = format!(
            r#"{{"cniVersion":"{}","name":"test","type":"{}","cniOutput":"{}"}}"#,
            version,
            plugin_type.name(),
            output_dir.display()
        );

        let (success, stdout, stderr) = run_plugin(
            &plugin_path,
            "ADD",
            &net_conf,
            &format!("container-{}", version),
            "/var/run/netns/test",
            "eth0",
            "",
        );

        assert!(success, "Plugin failed for version {}: {}", version, stderr);

        let result: Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|_| panic!("Failed to parse result for version {}", version));
        assert!(
            result.is_object(),
            "Result should be a JSON object for version {}",
            version
        );
    }
}

/// Common test helper for prevResult
fn test_with_prev_result_helper(plugin_type: PluginType) {
    let plugin_path = build_plugin(plugin_type);
    let _temp_dir = tempfile::tempdir().unwrap();
    let output_dir = _temp_dir.path().to_path_buf();

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
        "ADD",
        &net_conf,
        &container_id,
        "/var/run/netns/test",
        "eth0",
        "",
    );

    assert!(success, "Plugin failed: {}", stderr);

    // Plugin should return prevResult if provided
    let result: Value = serde_json::from_str(&stdout).expect("Failed to parse result");
    assert!(result["ips"].is_array());
    let ips = result["ips"].as_array().unwrap();
    assert!(!ips.is_empty(), "Should return prevResult IPs");
    assert_eq!(ips[0]["address"], ip_address);
}

// Sync plugin tests
#[test]
fn test_plugin_version_command() {
    test_version_command_helper(PluginType::Sync);
}

#[test]
fn test_plugin_add_command() {
    test_add_command_helper(PluginType::Sync);
}

#[test]
fn test_plugin_del_command() {
    test_del_command_helper(PluginType::Sync);
}

#[test]
fn test_plugin_check_command() {
    test_check_command_helper(PluginType::Sync);
}

#[test]
fn test_cni_version_compatibility() {
    test_cni_version_compatibility_helper(PluginType::Sync);
}

#[test]
fn test_plugin_with_prev_result() {
    test_with_prev_result_helper(PluginType::Sync);
}

// Async plugin tests
#[test]
fn test_async_plugin_version_command() {
    test_version_command_helper(PluginType::Async);
}

#[test]
fn test_async_plugin_add_command() {
    test_add_command_helper(PluginType::Async);
}

#[test]
fn test_async_plugin_del_command() {
    test_del_command_helper(PluginType::Async);
}

#[test]
fn test_async_plugin_check_command() {
    test_check_command_helper(PluginType::Async);
}

#[test]
fn test_async_plugin_with_prev_result() {
    test_with_prev_result_helper(PluginType::Async);
}
