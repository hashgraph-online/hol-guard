#![cfg(windows)]

//! The native MCP catalog probe on Windows: a `.cmd` launcher found through
//! PATH and PATHEXT runs in its JobObject tree and lists the server's tools.

use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use guard_command::local_mcp_stdio::{
    mcp_launch_tokens, resolve_argv_from_tokens, run_mcp_stdio_probe,
};
use serde_json::json;

/// A newline-delimited JSON-RPC MCP server answering discovery,
/// `initialize` and one `tools/list` page.
const FAKE_SERVER: &str = r#"
import sys, json
def send(message):
    sys.stdout.buffer.write((json.dumps(message) + "\n").encode())
    sys.stdout.buffer.flush()
for line in sys.stdin:
    req = json.loads(line)
    mid = req.get("id"); method = req.get("method")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": "2024-11-05",
              "capabilities": {"tools": {}}, "serverInfo": {"name": "fake", "version": "1"}}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [
              {"name": "t0", "inputSchema": {"type": "object"}}]}})
    elif mid is not None:
        send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "Method not found"}})
"#;

fn write_launcher(dir: &Path) {
    std::fs::write(dir.join("fake_mcp_server.py"), FAKE_SERVER).unwrap();
    std::fs::write(
        dir.join("fake-mcp.cmd"),
        "@echo off\r\npython \"%~dp0fake_mcp_server.py\"\r\n",
    )
    .unwrap();
}

#[test]
fn a_cmd_launcher_on_path_is_probed_in_its_job() {
    let dir = std::env::temp_dir().join(format!("mcp_probe_windows_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    write_launcher(&dir);
    let original = std::env::var_os("PATH").unwrap_or_default();
    let mut entries = vec![dir.clone()];
    entries.extend(std::env::split_paths(&original));
    std::env::set_var("PATH", std::env::join_paths(entries).unwrap());

    let tokens = mcp_launch_tokens("fake-mcp", &dir, None).expect("launch tokens");
    let argv = resolve_argv_from_tokens(&tokens, &dir).expect("PATHEXT resolution");
    assert!(
        argv[0].to_ascii_lowercase().ends_with("fake-mcp.cmd"),
        "resolved {argv:?}"
    );
    let catalog = run_mcp_stdio_probe(
        &argv,
        20.0,
        None,
        Some(&dir),
        None,
        &Arc::new(AtomicBool::new(false)),
    );
    let payload = catalog.to_payload();
    assert_eq!(payload["status"], json!("ok"), "catalog: {payload:?}");
    let names: Vec<&str> = payload["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["t0"]);
    let _ = std::fs::remove_dir_all(&dir);
}
