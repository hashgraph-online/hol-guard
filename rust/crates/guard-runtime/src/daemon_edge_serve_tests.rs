use std::os::unix::fs::PermissionsExt;

use serde_json::json;

use super::*;
use crate::claude_hook_bridge_auth::authenticated_state;

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
