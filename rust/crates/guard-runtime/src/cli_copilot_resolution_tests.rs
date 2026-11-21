use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Root(PathBuf);

impl Root {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "guard-cli-support-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn portable(value: &mut Value, root: &Path) {
    match value {
        Value::String(text) => {
            *text = text
                .replace(root.to_str().unwrap(), "<root>")
                .replace('\\', "/")
        }
        Value::Array(values) => values.iter_mut().for_each(|value| portable(value, root)),
        Value::Object(values) => values.values_mut().for_each(|value| portable(value, root)),
        _ => {}
    }
}

#[test]
fn original_filesystem_selection_vectors() {
    let root = Root::new();
    let home = root.0.join("home");
    let workspace = root.0.join("workspace");
    for relative in [
        "workspace/.vscode/mcp.json",
        "workspace/.mcp.json",
        "home/.copilot/mcp-config.json",
    ] {
        let target = root.0.join(relative);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(target, serde_json::to_vec(&json!({"servers": {"demo": {"command": "node", "args": [relative]}, "demo-long": {"url": "https://example.com/mcp"}}})).unwrap()).unwrap();
    }
    let fixture: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/cli_runtime_support_vectors.json"
    ))
    .unwrap();
    let mut count = 0;
    for case in fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["operation"] == "selection_fixture")
    {
        let params = json!({"home_dir": home, "workspace": workspace, "caller_cwd": root.0,
            "payload": {"tool_name": case["params"]["tool_name"]}, "preferred": case["params"]["preferred"]});
        let mut result = select_server(&params).unwrap().map_or(
            Value::Null,
            |(server, tool)| json!({"server": server, "tool_name": tool}),
        );
        portable(&mut result, &root.0);
        assert_eq!(result, case["expected"], "{:?}", case["params"]);
        count += 1;
    }
    assert_eq!(count, 18);
}

#[test]
fn config_order_ties_and_relative_reads_preserve_selection() {
    let root = Root::new();
    std::fs::create_dir_all(root.0.join("workspace")).unwrap();
    std::fs::write(
        root.0.join("workspace/.mcp.json"),
        r#"{"servers":{"z-a":{"command":"first"},"z_a":{"command":"second"}}}"#,
    )
    .unwrap();
    let params = json!({"home_dir": "home", "workspace": "workspace", "caller_cwd": root.0,
        "payload": {"tool_name": "mcp_z_a_echo"}, "preferred": null});
    let (server, tool) = select_server(&params).unwrap().unwrap();
    assert_eq!(server["server_name"], "z-a");
    // The relative workspace is joined with the host separator, as Python's `Path` does.
    let expected = Path::new("workspace").join(".mcp.json");
    assert_eq!(server["config_path"], expected.to_str().unwrap());
    assert_eq!(tool, "echo");
}

#[test]
fn remote_identity_binds_config_without_returning_credentials() {
    let root = Root::new();
    let mut params = json!({"launch_cwd": root.0, "environment": {"TOKEN": "ambient-credential"},
        "server": {"config_path": "config.json", "server_config": {"url": "https://example.com/mcp", "env": {"TOKEN": "configured-credential"}, "headers": {"Authorization": "first"}}}});
    let first = server_identity(&params).unwrap();
    params["server"]["server_config"]["headers"]["Authorization"] = json!("second");
    let second = server_identity(&params).unwrap();
    assert_ne!(
        first["fingerprint"]["config_sha256"],
        second["fingerprint"]["config_sha256"]
    );
    assert_eq!(first["transport"], "http");
    assert_eq!(
        first["fingerprint"]["resolved_executable"]["status"],
        "remote_transport"
    );
    let encoded = serde_json::to_string(&first).unwrap();
    for credential in [
        "ambient-credential",
        "configured-credential",
        "Authorization",
    ] {
        assert!(!encoded.contains(credential));
    }
}

#[test]
fn unresolved_config_is_never_reusable_and_large_ignored_fields_are_hashed() {
    let root = Root::new();
    let mut params = json!({"launch_cwd": root.0, "environment": {}, "server": {"config_path": "config.json", "server_config": null}});
    let first = server_identity(&params).unwrap();
    let second = server_identity(&params).unwrap();
    assert_ne!(
        first["fingerprint"]["resolved_executable"]["reuse_nonce"],
        second["fingerprint"]["resolved_executable"]["reuse_nonce"]
    );
    params["server"]["server_config"] =
        json!({"url": "https://example.com/mcp", "description": "x".repeat(1_100_000)});
    assert!(server_identity(&params).unwrap()["fingerprint"]["config_sha256"].is_string());
}

#[test]
fn read_growth_and_invalid_files_never_fabricate_a_selected_server() {
    let root = Root::new();
    std::fs::create_dir_all(root.0.join("workspace")).unwrap();
    let target = root.0.join("workspace/.mcp.json");
    std::fs::write(&target, "not-json").unwrap();
    let params = json!({"home_dir": root.0.join("home"), "workspace": root.0.join("workspace"), "caller_cwd": root.0,
        "payload": {"tool_name": "mcp_demo_echo"}, "preferred": null});
    assert!(select_server(&params).unwrap().is_none());
    File::create(target)
        .unwrap()
        .set_len(MAX_CONFIG_BYTES + 1)
        .unwrap();
    assert_eq!(
        select_server(&params).unwrap_err(),
        "native_runner_authority_cli_support_config_too_large"
    );
}
