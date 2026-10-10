//! Unit coverage for the bounded MCP stdio mediation helpers in
//! `local_mcp_stdio.rs`. These exercise the pure framing / strict-JSON /
//! launch-resolution surface; end-to-end subprocess negotiation is covered by
//! the Python oracle harness under `tests/test_guard_mcp_catalog_coverage.py`
//! when `HOL_GUARD_NATIVE_BINARY` points at a built runtime.

use super::local_mcp_stdio::*;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[test]
fn private_group_teardown_stops_descendant_and_preserves_unrelated_group() {
    use std::io::{BufRead, BufReader};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    #[cfg(target_os = "linux")]
    {
        // Fresh containers can allocate IDs within kill's signal-number
        // range, masking the missing operand separator. Exercise larger IDs.
        let mut reached_larger_pid = false;
        for _ in 0..128 {
            let mut warmup = Command::new("/bin/true").spawn().unwrap();
            let pid = warmup.id();
            assert!(warmup.wait().unwrap().success());
            if pid > 64 {
                reached_larger_pid = true;
                break;
            }
        }
        assert!(reached_larger_pid);
    }

    struct OwnedGroup(Child);
    impl Drop for OwnedGroup {
        fn drop(&mut self) {
            kill_process_group(self.0.id() as i32);
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut unrelated = OwnedGroup(
        Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap(),
    );
    let mut group = OwnedGroup(
        Command::new("/bin/sh")
            .args(["-c", "sleep 30 & echo $!; wait"])
            .process_group(0)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = group.0.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line).unwrap();
        let _ = sender.send(line);
    });
    let line = receiver.recv_timeout(Duration::from_secs(3)).unwrap();
    reader.join().unwrap();
    let descendant: u32 = line.trim().parse().unwrap();
    assert!(descendant > 1);

    // Check reserved IDs without ever issuing those dangerous kernel calls.
    for invalid in [i32::MIN, -1, 0, 1] {
        assert!(process_group_operand(invalid).is_none());
    }
    assert!(group.0.try_wait().unwrap().is_none());
    assert!(unrelated.0.try_wait().unwrap().is_none());
    kill_process_group(group.0.id() as i32);
    let deadline = Instant::now() + Duration::from_secs(3);
    while group.0.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(group.0.try_wait().unwrap().is_some());
    assert!(unrelated.0.try_wait().unwrap().is_none());
    #[cfg(target_os = "linux")]
    {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let status = std::fs::read_to_string(format!("/proc/{descendant}/stat"));
            match status {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Ok(status)
                    if matches!(
                        status
                            .rsplit_once(") ")
                            .and_then(|(_, rest)| rest.split_whitespace().next()),
                        Some("Z" | "X")
                    ) =>
                {
                    break
                }
                _ if Instant::now() >= deadline => panic!("owned descendant remains active"),
                _ => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    }
}

#[test]
fn pop_json_message_newline_framing() {
    let raw = b"{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}\n";
    let (msg, consumed) = pop_json_message(raw).unwrap();
    assert_eq!(consumed, raw.len());
    assert_eq!(msg.unwrap()["id"], json!(2));
}

#[test]
fn pop_json_message_content_length_framing() {
    let body = b"{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}";
    let mut framed = b"Content-Length: ".to_vec();
    framed.extend_from_slice(body.len().to_string().as_bytes());
    framed.extend_from_slice(b"\r\n\r\n");
    framed.extend_from_slice(body);
    let (msg, consumed) = pop_json_message(&framed).unwrap();
    assert_eq!(consumed, framed.len());
    assert_eq!(msg.unwrap()["id"], json!(2));
}

#[test]
fn pop_json_message_incomplete_returns_none() {
    // No newline and not enough bytes for a Content-Length body.
    assert!(pop_json_message(b"{\"id\":1").is_none());
    let body = b"{}";
    let mut framed = b"Content-Length: 10\r\n\r\n".to_vec();
    framed.extend_from_slice(body);
    assert!(pop_json_message(&framed).is_none());
}

#[test]
fn pop_json_message_blank_line_flood() {
    let mut raw = vec![b'\n'; 2000];
    raw.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":2}\n");
    let mut messages = 0;
    let mut rest: &[u8] = &raw;
    while let Some((m, consumed)) = pop_json_message(rest) {
        if m.is_some() {
            messages += 1;
        }
        rest = &rest[consumed..];
    }
    assert_eq!(messages, 1);
}

#[test]
fn strict_rpc_json_rejects_duplicate_keys() {
    let raw = b"{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"a\":1},\"result\":{\"a\":2}}";
    assert!(strict_rpc_json(raw).is_err());
}

#[test]
fn strict_rpc_json_rejects_nonfinite() {
    // serde_json rejects bare NaN/Infinity at parse time; this asserts the
    // helper surfaces that as Err rather than a panic.
    let raw = b"{\"id\":2,\"result\":{\"v\":NaN}}";
    assert!(strict_rpc_json(raw).is_err());
}

#[test]
fn strict_rpc_json_rejects_ambiguous_and_incomplete_frames() {
    for raw in [
        br#"{"id":2,"result":{"name":"safe","\u006eame":"unsafe"}}"#.as_slice(),
        br#"{"id":2,"result":{}} {"id":3}"#.as_slice(),
        br#"{"id":2,"result":{"value":1e999}}"#.as_slice(),
        br#"{"id":2,"result":{"value":"unterminated\"#.as_slice(),
    ] {
        assert!(strict_rpc_json(raw).is_err(), "{raw:?}");
    }
}

#[test]
fn content_length_above_frame_limit_never_indexes_body() {
    let raw = format!("Content-Length: {}\r\n\r\n{{}}", usize::MAX);
    let (message, consumed) = pop_json_message(raw.as_bytes()).unwrap();
    assert!(message.is_none());
    assert!(consumed > 0 && consumed <= raw.len());
}

#[test]
fn strict_rpc_json_preserves_large_integer_and_distinct_escaped_keys() {
    let raw = br#"{"id":2,"result":{"maximum":1208925819614629174706177,"name":"a","\u006eames":"b","nested":{"name":"c"}}}"#;
    let value = strict_rpc_json(raw).unwrap();
    assert_eq!(
        value["result"]["maximum"].as_number().unwrap().as_str(),
        "1208925819614629174706177"
    );
    assert_eq!(value["result"]["name"], "a");
    assert_eq!(value["result"]["names"], "b");
    assert_eq!(value["result"]["nested"]["name"], "c");
}

#[test]
fn strict_rpc_json_accepts_nested_object() {
    let raw = b"{\"id\":2,\"result\":{\"tools\":[{\"name\":\"x\",\"nested\":{\"a\":1}}]}}";
    let v = strict_rpc_json(raw).unwrap();
    assert_eq!(v["result"]["tools"][0]["name"], json!("x"));
}

#[test]
fn resource_uri_validation() {
    assert!(resource_uri("file:///skills/SKILL.md"));
    assert!(resource_uri("mcp://server/skills/SKILL.md"));
    assert!(!resource_uri("no-scheme/SKILL.md"));
    assert!(!resource_uri("file:///x/SKILL.md?query=1"));
    assert!(!resource_uri("file:///x/SKILL.md#frag"));
    assert!(!resource_uri("file:///x\n/SKILL.md"));
    assert!(!resource_uri("file:///skills/%252e%252e/SKILL.md"));
    assert!(!resource_uri("file:///skills/%2foutside/SKILL.md"));
    assert!(!resource_uri("1file:///skills/SKILL.md"));
    assert!(resource_uri("file:///skills/100%25/SKILL.md"));
}

#[test]
fn skills_declared_requires_version_and_extension() {
    // Protocol below the minimum date gate.
    assert!(!mcp_skills_declared(
        Some(&json!({"extensions":{"io.modelcontextprotocol/skills":{}}})),
        "2025-01-01"
    ));
    // Right version, no extension capability.
    assert!(!mcp_skills_declared(
        Some(&json!({"extensions":{}})),
        "2026-07-28"
    ));
    assert!(!mcp_skills_declared(
        Some(&json!({"extensions":{"io.modelcontextprotocol/skills":{}}})),
        "2026-07-28"
    ));
    assert!(!mcp_skills_declared(
        Some(&json!({"resources":{},"extensions":{"io.modelcontextprotocol/skills":{}}})),
        "2026-13-28"
    ));
    // Both satisfied.
    assert!(mcp_skills_declared(
        Some(&json!({"resources":{},"extensions":{"io.modelcontextprotocol/skills":{}}})),
        "2026-07-28"
    ));
    // Non-date protocol string rejected.
    assert!(!mcp_skills_declared(
        Some(&json!({"extensions":{"io.modelcontextprotocol/skills":{}}})),
        "latest"
    ));
}

#[test]
fn launch_argv_rejects_compound() {
    // A shell pipeline is not a single safe invocation.
    assert!(resolve_launch_argv("npx -y srv | tee log", Path::new("/tmp")).is_none());
}

#[test]
fn probe_env_locked_keys_filtered() {
    let mut extra = BTreeMap::new();
    extra.insert("PATH".to_owned(), "/evil".to_owned());
    extra.insert("HOME".to_owned(), "/evil".to_owned());
    extra.insert("INNOCENT".to_owned(), "yes".to_owned());
    let env = probe_env("/tmp/probe", Some(&extra), None);
    // Locked keys retain the probe-controlled value, not the caller's.
    assert_eq!(env.get("HOME").map(String::as_str), Some("/tmp/probe"));
    assert_eq!(env.get("INNOCENT").map(String::as_str), Some("yes"));
}

// ---------------------------------------------------------------------------
// End-to-end: spawn a real fake stdio MCP server and negotiate + paginate.
// ---------------------------------------------------------------------------

fn write_fake_server(dir: &Path, script: &str) -> PathBuf {
    let path = dir.join("fake_mcp_server.py");
    std::fs::write(&path, script).unwrap();
    path
}

/// A newline-delimited JSON-RPC MCP server: answers `server/discover` (modern
/// protocol), `initialize`, paginated `tools/list`, and sends a `roots/list`
/// request mid-stream that the probe must answer.
const FAKE_SERVER: &str = r#"
import sys, json
def page(tools, nxt=None):
    r = {"resultType":"complete","ttlMs":60000,"cacheScope":"private","tools":tools}
    if nxt is not None: r["nextCursor"]=nxt
    return r
pages = {
    None: page([{"name": "t0", "inputSchema": {"type": "object"}}], "c1"),
    "c1": page([{"name": "t1", "inputSchema": {"type": "object"}}]),
}
for line in sys.stdin:
    req = json.loads(line)
    mid = req.get("id"); method = req.get("method")
    if method == "server/discover":
        sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":mid,"result":
            {"resultType":"complete","supportedVersions":["2026-07-28"],
             "capabilities":{"tools":{}},
             "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"fake","version":"1"}}}})+"\n"); sys.stdout.flush()
    elif method == "initialize":
        sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":mid,"result":
            {"protocolVersion":"2024-11-05","capabilities":{"tools":{}},
             "serverInfo":{"name":"fake","version":"1"}}})+"\n"); sys.stdout.flush()
        sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":900,"method":"roots/list"})+"\n")
        sys.stdout.flush()
    elif method == "tools/list":
        cur = req.get("params",{}).get("cursor")
        if cur in pages:
            sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":mid,"result":pages[cur]})+"\n")
        else:
            sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":mid,
                "error":{"code":-32602,"message":"Unknown cursor"}})+"\n")
        sys.stdout.flush()
    elif mid is not None:
        sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":mid,
            "error":{"code":-32601,"message":"Method not found"}})+"\n"); sys.stdout.flush()
"#;

#[test]
fn end_to_end_probe_negotiates_and_paginates() {
    let dir = std::env::temp_dir().join(format!("mcp_probe_test_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let server = write_fake_server(&dir, FAKE_SERVER);
    let argv = vec!["python3".to_owned(), server.to_string_lossy().into_owned()];
    let catalog = run_mcp_stdio_probe(
        &argv,
        6.0,
        None,
        Some(&dir),
        None,
        &std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    );
    let payload = catalog.to_payload();
    assert_eq!(payload["status"], json!("ok"), "catalog: {payload:?}");
    let tools = payload["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["t0", "t1"]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn end_to_end_probe_handles_silent_discovery() {
    // A server that ignores `server/discover` must fall back to `initialize`.
    let script = r#"
import sys, json
for line in sys.stdin:
    req = json.loads(line)
    mid = req.get("id"); method = req.get("method")
    if method == "initialize":
        sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":mid,"result":
            {"protocolVersion":"2024-11-05","capabilities":{"tools":{}},
             "serverInfo":{"name":"legacy","version":"1"}}})+"\n"); sys.stdout.flush()
    elif method == "tools/list":
        sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":mid,"result":
            {"tools":[{"name":"only"}]}})+"\n"); sys.stdout.flush()
    elif mid is not None:
        sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":mid,
            "error":{"code":-32601,"message":"Method not found"}})+"\n"); sys.stdout.flush()
"#;
    let dir = std::env::temp_dir().join(format!("mcp_probe_leg_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let server = write_fake_server(&dir, script);
    let argv = vec!["python3".to_owned(), server.to_string_lossy().into_owned()];
    let catalog = run_mcp_stdio_probe(
        &argv,
        6.0,
        None,
        Some(&dir),
        None,
        &std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    );
    let payload = catalog.to_payload();
    assert_eq!(payload["status"], json!("ok"), "catalog: {payload:?}");
    assert_eq!(payload["server_info"]["name"], json!("legacy"));
    let _ = std::fs::remove_dir_all(&dir);
}
