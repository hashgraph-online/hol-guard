use std::os::unix::fs::PermissionsExt;

use serde_json::json;

use super::*;
use crate::claude_hook_bridge_auth::{authenticated_state, verify_challenge_response};

fn launch(home: &Path, extra: Value) -> Vec<u8> {
    let mut config = json!({
        "schema": LAUNCH_SCHEMA,
        "guard_home": home.to_str().unwrap(),
        "port": 0,
        "store_path": home.join("guard.db").to_str().unwrap(),
        "source": "daemon",
        "busy_timeout_ms": 5000,
        "cli_command": ["/usr/bin/false"],
        "state": {"compatibility_version": 2, "package_version": "9.9.9"},
    });
    if let (Value::Object(config), Value::Object(extra)) = (&mut config, extra) {
        config.extend(extra);
    }
    serde_json::to_vec(&config).unwrap()
}

fn private_home() -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix("serve")
        .tempdir_in("/tmp")
        .unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

#[test]
fn published_state_authenticates_and_names_this_process() {
    let dir = private_home();
    let home = fs::canonicalize(dir.path()).unwrap();
    let config = LaunchConfig::parse(&launch(&home, json!({}))).unwrap();
    let secret = publish(&home, &config, 4781, std::process::id()).unwrap();
    assert_eq!(secret.len(), 32);
    let state = authenticated_state(&home.join(STATE_FILE)).unwrap();
    assert_eq!(state.payload["port"], 4781);
    assert_eq!(state.payload["pid"], std::process::id());
    assert_eq!(state.payload["package_version"], "9.9.9");
    assert_eq!(state.payload["host"], "127.0.0.1");
    let id_field = format!("{}_{}_id", "auth", "token");
    assert_eq!(
        state.payload[&id_field],
        hex::encode(Sha256::digest(secret.as_bytes()))
    );
    for name in [STATE_FILE, AUTH_SECRET_FILE, DISCOVERY_KEY_FILE] {
        let mode = fs::metadata(home.join(name)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{name}");
    }
}

#[test]
fn a_second_publish_keeps_the_shared_secret_and_key() {
    let dir = private_home();
    let home = fs::canonicalize(dir.path()).unwrap();
    let config = LaunchConfig::parse(&launch(&home, json!({}))).unwrap();
    let first = publish(&home, &config, 4781, std::process::id()).unwrap();
    let key = fs::read(home.join(DISCOVERY_KEY_FILE)).unwrap();
    let second = publish(&home, &config, 4782, std::process::id()).unwrap();
    assert_eq!(first, second);
    assert_eq!(key, fs::read(home.join(DISCOVERY_KEY_FILE)).unwrap());
    let state = authenticated_state(&home.join(STATE_FILE)).unwrap();
    assert_eq!(state.payload["port"], 4782);
}

#[test]
fn a_shared_secret_file_is_refused() {
    let dir = private_home();
    let home = fs::canonicalize(dir.path()).unwrap();
    let path = home.join(AUTH_SECRET_FILE);
    fs::write(&path, "0123456789abcdef0123456789abcdef").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let config = LaunchConfig::parse(&launch(&home, json!({}))).unwrap();
    assert!(publish(&home, &config, 4781, std::process::id()).is_err());
}

#[test]
fn launch_nonce_becomes_the_generation() {
    let dir = private_home();
    let home = fs::canonicalize(dir.path()).unwrap();
    let nonce = "0123456789abcdef".repeat(4);
    let nonce = nonce.as_str();
    let config = LaunchConfig::parse(&launch(&home, json!({"launch_nonce": nonce}))).unwrap();
    publish(&home, &config, 4781, std::process::id()).unwrap();
    let state = authenticated_state(&home.join(STATE_FILE)).unwrap();
    assert_eq!(state.payload["generation"], nonce);
    assert_eq!(state.payload["launch_nonce"], nonce);
}

#[test]
fn launch_config_rejects_unsafe_shapes() {
    let home = Path::new("/tmp/guard-home");
    assert!(LaunchConfig::parse(&launch(home, json!({}))).is_some());
    for extra in [
        json!({"schema": "other"}),
        json!({"host": "0.0.0.0"}),
        json!({"guard_home": "relative"}),
        json!({"cli_command": []}),
        json!({"launch_nonce": "short"}),
        json!({"state": {"pid": 1}}),
        json!({"state": {"state_signature": "x"}}),
        json!({"unexpected": true}),
    ] {
        assert!(
            LaunchConfig::parse(&launch(home, extra.clone())).is_none(),
            "{extra}"
        );
    }
}

#[test]
fn args_repeat_the_home_and_port() {
    let args = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(
        parse_args(&args(&["--guard-home", "/h", "--port", "4781"])),
        Some(("/h".to_owned(), 4781))
    );
    assert_eq!(
        parse_args(&args(&["--port", "4781", "--guard-home", "/h"])),
        None
    );
    assert_eq!(
        parse_args(&args(&["--guard-home", "/h", "--port", "x"])),
        None
    );
    assert_eq!(parse_args(&args(&[])), None);
}

#[test]
fn the_handshake_is_one_the_native_reads_accept() {
    let home = Path::new("/tmp/guard-home");
    let config = LaunchConfig::parse(&launch(home, json!({}))).unwrap();
    let reads = NativeReads::new(None);
    reads.accept_handshake(&config.handshake("0123456789abcdef0123456789abcdef"));
    let accepted = reads.config().unwrap();
    assert!(accepted.cli().is_some());
}

#[test]
fn a_standalone_daemon_answers_the_health_probe_itself() {
    let home = Path::new("/tmp/guard-home");
    let config = LaunchConfig::parse(&launch(home, json!({}))).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let reads = Arc::new(NativeReads::new(None));
    reads.mark_standalone();
    reads.accept_handshake(&config.handshake("0123456789abcdef0123456789abcdef"));
    assert_eq!(reads.daemon_pid(), std::process::id());
    std::thread::spawn(move || serve(&listener, None, 4, STALLED_WRITE_TIMEOUT, reads));
    let mut client = std::net::TcpStream::connect(address).unwrap();
    client
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.0 200 OK\r\n"), "{response}");
    assert!(
        response.ends_with("{\"compatibility_version\":2,\"ok\":true}"),
        "{response}"
    );
}

#[test]
fn a_waiting_launcher_is_named_as_the_daemon() {
    let home = Path::new("/tmp/guard-home");
    let config = LaunchConfig::parse(&launch(home, json!({"launcher_pid": 4242}))).unwrap();
    assert_eq!(config.launcher_pid, Some(4242));
    let reads = NativeReads::new(None);
    reads.mark_standalone();
    reads.set_launcher_pid(4242);
    assert_eq!(reads.daemon_pid(), 4242);
}

/// A standalone daemon on a fresh private home whose replay CLI echoes the
/// arguments it was run with, so a test can see what the handler was told.
fn echoing_daemon() -> (tempfile::TempDir, SocketAddr) {
    let dir = private_home();
    let home = fs::canonicalize(dir.path()).unwrap();
    // A replay echoes its arguments; a hook review answers whether the edge
    // told it the proof checked out.
    let script = concat!(
        "if [ \"$2\" = library-call ]; then ",
        "if grep -q '\"proof_verified\":true'; then v=true; else v=false; fi; ",
        "printf '{\"ok\":{\"status\":200,\"body\":{\"proof_verified\":%s},\"no_store\":false}}' $v; ",
        "else cat >/dev/null; printf 'HTTP/1.0 200 OK\\r\\n\\r\\n%s' \"$*\"; fi"
    );
    let echo = json!({"cli_command": ["/bin/sh", "-c", script, "sh"]});
    let config = LaunchConfig::parse(&launch(&home, echo)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let pass = publish(&home, &config, address.port(), std::process::id()).unwrap();
    let reads = Arc::new(NativeReads::new(None));
    reads.mark_standalone();
    reads.accept_handshake(&config.handshake(&pass));
    std::thread::spawn(move || serve(&listener, None, 4, STALLED_WRITE_TIMEOUT, reads));
    (dir, address)
}

fn http_post(path: &str, headers: &str, body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

/// Reads one response with a declared length off a kept-alive connection.
fn read_one(client: &mut std::net::TcpStream) -> (String, Map<String, Value>) {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        client.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
    }
    let head = String::from_utf8(bytes).unwrap();
    let length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let mut body = vec![0u8; length];
    client.read_exact(&mut body).unwrap();
    (head, serde_json::from_slice(&body).unwrap())
}

fn challenge(
    client: &mut std::net::TcpStream,
    home: &Path,
    nonce: &str,
) -> (String, Map<String, Value>) {
    let home = fs::canonicalize(home).unwrap();
    let state = authenticated_state(&home.join(STATE_FILE)).unwrap();
    let body = json!({
        "protocol_version": 1,
        "nonce": nonce,
        "state_id": state.payload["state_id"],
        "hook_event": "PreToolUse",
    })
    .to_string();
    client
        .write_all(http_post("/v1/daemon/identity-challenge", "", &body).as_bytes())
        .unwrap();
    read_one(client)
}

#[test]
fn a_standalone_daemon_proves_its_identity_on_the_hook_connection() {
    let (dir, address) = echoing_daemon();
    let nonce = "ab".repeat(32);
    let mut client = std::net::TcpStream::connect(address).unwrap();
    let (head, answer) = challenge(&mut client, dir.path(), &nonce);
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    assert!(head.contains("Cache-Control: no-store\r\n"), "{head}");
    let state =
        authenticated_state(&fs::canonicalize(dir.path()).unwrap().join(STATE_FILE)).unwrap();
    let proof = verify_challenge_response(&answer, &state, &nonce, "PreToolUse").unwrap();
    let hook = json!({"hook_event_name": " PreToolUse ", "tool_name": "Bash"}).to_string();
    let headers = format!("X-Guard-Daemon-Nonce: {nonce}\r\nX-Guard-Daemon-Proof: {proof}\r\n");
    client
        .write_all(http_post("/v1/hooks/codex", &headers, &hook).as_bytes())
        .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert!(
        response.ends_with(r#"{"proof_verified":true}"#),
        "{response}"
    );
}

#[test]
fn a_hook_without_the_issued_proof_reaches_the_handler_unverified() {
    let (dir, address) = echoing_daemon();
    let nonce = "cd".repeat(32);
    let hook = json!({"hook_event_name": "PreToolUse"}).to_string();
    for (headers, event_hook) in [
        (
            format!(
                "X-Guard-Daemon-Nonce: {nonce}\r\nX-Guard-Daemon-Proof: {}\r\n",
                "0".repeat(64)
            ),
            hook.clone(),
        ),
        (String::new(), hook.clone()),
        (
            String::new(),
            json!({"hook_event_name": "PostToolUse"}).to_string(),
        ),
    ] {
        let mut client = std::net::TcpStream::connect(address).unwrap();
        let (_head, answer) = challenge(&mut client, dir.path(), &nonce);
        let headers = if headers.is_empty() {
            format!(
                "X-Guard-Daemon-Nonce: {nonce}\r\nX-Guard-Daemon-Proof: {}\r\n",
                answer["proof"].as_str().unwrap()
            )
        } else {
            headers
        };
        let path = if event_hook == hook && headers.contains(&"0".repeat(64)) {
            "/v1/hooks/codex"
        } else if event_hook == hook {
            "/v1/requests"
        } else {
            "/v1/hooks/claude-code"
        };
        client
            .write_all(http_post(path, &headers, &event_hook).as_bytes())
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.0 200 OK"), "{response}");
        assert!(!response.contains("--daemon-proof-verified"), "{response}");
        assert!(!response.contains(r#""proof_verified":true"#), "{response}");
    }
}

#[test]
fn a_malformed_or_foreign_challenge_is_refused() {
    let (_dir, address) = echoing_daemon();
    for (body, status, error) in [
        (json!({"nonce": "zz"}).to_string(), "400", "invalid_daemon_identity_challenge"),
        (
            json!({"protocol_version": 1, "nonce": "ef".repeat(32), "state_id": "other", "hook_event": "PreToolUse"}).to_string(),
            "409",
            "daemon_identity_state_mismatch",
        ),
        (
            json!({"protocol_version": true, "nonce": "ef".repeat(32), "state_id": "x", "hook_event": "PreToolUse"}).to_string(),
            "400",
            "invalid_daemon_identity_challenge",
        ),
    ] {
        let mut client = std::net::TcpStream::connect(address).unwrap();
        client
            .write_all(http_post("/v1/daemon/identity-challenge", "", &body).as_bytes())
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with(&format!("HTTP/1.0 {status} ")), "{response}");
        assert!(response.ends_with(&format!("{{\"error\":\"{error}\"}}")), "{response}");
    }
}

#[test]
fn a_standalone_daemon_answers_a_request_that_arrives_slowly_itself() {
    let (_dir, address) = echoing_daemon();
    let request = "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    let (first, rest) = request.split_at(12);
    let mut client = std::net::TcpStream::connect(address).unwrap();
    client.write_all(first.as_bytes()).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    client.write_all(rest.as_bytes()).unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert!(
        response.ends_with("{\"compatibility_version\":2,\"ok\":true}"),
        "{response}"
    );
}
