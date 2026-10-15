//! Test fixture for the native Claude hook bridge: a private Guard home with
//! a signed `daemon-state.json`, and a scripted loopback daemon that answers
//! the identity challenge and the hook on one connection.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::daemon_policy_authority::{canonical_discovery_payload, hmac_sha256_raw};

pub(crate) const DISCOVERY_KEY: &str =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// A Guard home under the system temp directory, removed on drop.
pub(crate) struct GuardHome {
    root: PathBuf,
    pub(crate) home: PathBuf,
    pub(crate) state_path: PathBuf,
}

impl Drop for GuardHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl GuardHome {
    pub(crate) fn new(label: &str) -> Self {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("hg-claude-bridge-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let home = root.join("home");
        fs::create_dir_all(&home).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        write_private(&home.join("daemon-discovery-key"), DISCOVERY_KEY);
        let state_path = home.join("daemon-state.json");
        Self {
            root,
            home,
            state_path,
        }
    }

    pub(crate) fn scratch(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    pub(crate) fn home_text(&self) -> &str {
        self.home.to_str().unwrap()
    }

    /// The unsigned state of a daemon listening on `port`.
    pub(crate) fn state(&self, port: u16) -> Map<String, Value> {
        let key = hex::decode(DISCOVERY_KEY).unwrap();
        let Value::Object(state) = json!({
            "discovery_protocol_version": 1,
            "discovery_key_id": hex::encode(Sha256::digest(&key)),
            "host": "127.0.0.1",
            "port": port,
            "pid": 4242,
            "state_id": "state-fixture",
            "started_at": "2026-10-12T00:00:00+00:00",
            "auth_token_id": "token-fixture",
            "guard_home": self.home_text(),
        }) else {
            unreachable!()
        };
        state
    }

    pub(crate) fn write_state(&self, state: &Map<String, Value>) {
        let mut signed = state.clone();
        signed.insert("state_signature".to_owned(), Value::String(sign(state)));
        write_private(
            &self.state_path,
            &serde_json::to_string(&Value::Object(signed)).unwrap(),
        );
    }
}

pub(crate) fn write_private(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

pub(crate) fn sign(payload: &Map<String, Value>) -> String {
    let key = hex::decode(DISCOVERY_KEY).unwrap();
    hex::encode(hmac_sha256_raw(&key, &canonical_discovery_payload(payload)))
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// A signed identity-challenge answer for `nonce` and `hook_event`.
pub(crate) fn challenge_answer(
    state: &Map<String, Value>,
    nonce: &str,
    hook_event: &str,
) -> Map<String, Value> {
    let issued = now_ms();
    let mut answer = Map::new();
    answer.insert("protocol_version".to_owned(), json!(1));
    answer.insert("nonce".to_owned(), json!(nonce));
    for field in [
        "state_id",
        "host",
        "port",
        "pid",
        "started_at",
        "guard_home",
    ] {
        answer.insert(field.to_owned(), state[field].clone());
    }
    answer.insert("hook_event".to_owned(), json!(hook_event));
    answer.insert("issued_at_ms".to_owned(), json!(issued));
    answer.insert("expires_at_ms".to_owned(), json!(issued + 5_000));
    let proof = sign(&answer);
    answer.insert("proof".to_owned(), json!(proof));
    answer
}

/// One HTTP request as the daemon received it.
#[derive(Debug, Default)]
pub(crate) struct Request {
    pub(crate) target: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl Request {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

pub(crate) fn read_request(reader: &mut BufReader<TcpStream>) -> Option<Request> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let target = line.split(' ').nth(1)?.to_owned();
    let mut request = Request {
        target,
        ..Request::default()
    };
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (key, value) = line.split_once(':')?;
        request
            .headers
            .push((key.trim().to_owned(), value.trim().to_owned()));
    }
    // A bodyless GET is sent without a Content-Length.
    let length: usize = match request.header("Content-Length") {
        Some(length) => length.parse().ok()?,
        None => 0,
    };
    request.body = vec![0; length];
    reader.read_exact(&mut request.body).ok()?;
    Some(request)
}

pub(crate) fn write_response(stream: &mut TcpStream, status: u16, body: &str, close: bool) {
    let connection = if close { "close" } else { "keep-alive" };
    let head = format!(
        "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body.as_bytes()).unwrap();
    stream.flush().unwrap();
}

/// What the scripted daemon does with one connection.
#[derive(Clone, Debug)]
pub(crate) enum Exchange {
    /// Answer the identity challenge with this status and body.
    RefuseChallenge(u16, &'static str),
    /// Prove identity, then answer the hook with this status and body.
    Hook(u16, String),
    /// Answer one request without an identity challenge, as the daemon's
    /// approval endpoints do.
    Plain(u16, String),
}

/// Serve `script`, one connection per entry, recording each hook request
/// and each plain request.
pub(crate) fn spawn_daemon(
    listener: TcpListener,
    state: Map<String, Value>,
    script: Vec<Exchange>,
) -> JoinHandle<Vec<Request>> {
    std::thread::spawn(move || {
        let mut hooks = Vec::new();
        for exchange in script {
            let Ok((stream, _)) = listener.accept() else {
                break;
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            let Some(challenge) = read_request(&mut reader) else {
                continue;
            };
            if let Exchange::Plain(status, body) = &exchange {
                write_response(&mut writer, *status, body, true);
                hooks.push(challenge);
                continue;
            }
            assert_eq!(challenge.target, "/v1/daemon/identity-challenge");
            match exchange {
                Exchange::RefuseChallenge(status, body) => {
                    write_response(&mut writer, status, body, true);
                }
                Exchange::Hook(status, body) => {
                    let request: Value = serde_json::from_slice(&challenge.body).unwrap();
                    let answer = challenge_answer(
                        &state,
                        request["nonce"].as_str().unwrap(),
                        request["hook_event"].as_str().unwrap(),
                    );
                    let answer = serde_json::to_string(&Value::Object(answer)).unwrap();
                    write_response(&mut writer, 200, &answer, false);
                    if let Some(hook) = read_request(&mut reader) {
                        write_response(&mut writer, status, &body, true);
                        hooks.push(hook);
                    }
                }
                Exchange::Plain(..) => unreachable!(),
            }
        }
        hooks
    })
}

/// A Guard home whose signed state names a scripted daemon.
pub(crate) fn home_with_daemon(
    label: &str,
    script: Vec<Exchange>,
) -> (GuardHome, JoinHandle<Vec<Request>>) {
    let home = GuardHome::new(label);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let state = home.state(listener.local_addr().unwrap().port());
    home.write_state(&state);
    let daemon = spawn_daemon(listener, state, script);
    (home, daemon)
}

/// A loopback port with nothing listening on it.
pub(crate) fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}
