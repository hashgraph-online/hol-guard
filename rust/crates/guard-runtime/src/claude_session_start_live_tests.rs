use std::io::{BufRead, BufReader, Read};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::*;
use crate::claude_hook_bridge_fixture::{
    challenge_answer, sign, write_private, write_response, GuardHome,
};

pub(crate) const TOKEN: &str = "daemon-token-fixture";
pub(crate) const CURRENT_HEALTH: &str =
    r#"{"ok":true,"compatibility_version":2,"tables":["guard_connect_states"]}"#;

/// One connection the scripted daemon serves, each closed after its reply.
pub(crate) enum Reply {
    /// Answer the identity challenge with a signed proof.
    Challenge,
    /// Refuse the identity challenge with this status.
    Refuse(u16),
    /// Answer `/healthz`, then optionally rewrite the daemon state.
    Health(u16, &'static str, Option<(PathBuf, String)>),
}

/// The request target and body; unlike the bridge fixture's reader this
/// accepts a `GET` without `Content-Length`, as `/healthz` sends it.
fn read_any_request(reader: &mut BufReader<TcpStream>) -> Option<(String, Vec<u8>)> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let target = line.split(' ').nth(1)?.to_owned();
    let mut length = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case("content-length") {
            length = value.trim().parse().ok()?;
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    Some((target, body))
}

/// A live-looking state: this process's pid, a bound token, compatible.
fn live_state(home: &GuardHome, port: u16) -> Map<String, Value> {
    let mut state = home.state(port);
    state.insert("pid".to_owned(), json!(std::process::id()));
    state.insert("compatibility_version".to_owned(), json!(2));
    state.insert("package_version".to_owned(), json!(crate::PACKAGE_VERSION));
    state.insert(
        "auth_token_id".to_owned(),
        json!(hex::encode(Sha256::digest(TOKEN.as_bytes()))),
    );
    state
}

fn signed_text(state: &Map<String, Value>) -> String {
    let mut signed = state.clone();
    signed.insert("state_signature".to_owned(), json!(sign(state)));
    serde_json::to_string(&Value::Object(signed)).unwrap()
}

pub(crate) fn serve(
    listener: TcpListener,
    state: Map<String, Value>,
    script: Vec<Reply>,
) -> JoinHandle<Vec<String>> {
    std::thread::spawn(move || {
        let mut targets = Vec::new();
        for reply in script {
            let Ok((stream, _)) = listener.accept() else {
                break;
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut writer = stream.try_clone().unwrap();
            let Some((target, body)) = read_any_request(&mut BufReader::new(stream)) else {
                continue;
            };
            targets.push(target);
            match reply {
                Reply::Challenge => {
                    let body: Value = serde_json::from_slice(&body).unwrap();
                    let answer = challenge_answer(
                        &state,
                        body["nonce"].as_str().unwrap(),
                        body["hook_event"].as_str().unwrap(),
                    );
                    let answer = serde_json::to_string(&Value::Object(answer)).unwrap();
                    write_response(&mut writer, 200, &answer, true);
                }
                Reply::Refuse(status) => {
                    write_response(&mut writer, status, r#"{"error":"no"}"#, true);
                }
                Reply::Health(status, body, rewrite) => {
                    if let Some((path, text)) = rewrite {
                        write_private(&path, &text);
                    }
                    write_response(&mut writer, status, body, true);
                }
            }
        }
        targets
    })
}

/// A Guard home with a bound token and a signed live state for a daemon on
/// a fresh loopback listener; `edit` adjusts the state before signing.
pub(crate) fn live_home(
    label: &str,
    edit: impl FnOnce(&mut Map<String, Value>),
) -> (GuardHome, TcpListener, Map<String, Value>) {
    let home = GuardHome::new(label);
    write_private(&home.home.join("daemon-auth-token"), &format!("{TOKEN}\n"));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut state = live_state(&home, listener.local_addr().unwrap().port());
    edit(&mut state);
    home.write_state(&state);
    (home, listener, state)
}

fn verify(home: &GuardHome) -> Result<String, String> {
    verified_daemon_url(
        &home.state_path,
        "SessionStart",
        Instant::now() + Duration::from_secs(5),
    )
}

#[test]
fn verified_live_daemon_yields_its_loopback_url() {
    let (home, listener, state) = live_home("ss-live-ok", |_| {});
    let port = listener.local_addr().unwrap().port();
    let daemon = serve(
        listener,
        state,
        vec![Reply::Challenge, Reply::Health(200, CURRENT_HEALTH, None)],
    );

    assert_eq!(verify(&home), Ok(format!("http://127.0.0.1:{port}")));
    assert_eq!(
        daemon.join().unwrap(),
        ["/v1/daemon/identity-challenge", "/healthz"]
    );
}

#[test]
fn missing_or_unbound_token_is_refused_before_any_connection() {
    let (home, _listener, _state) = live_home("ss-live-token-missing", |_| {});
    std::fs::remove_file(home.home.join("daemon-auth-token")).unwrap();
    assert!(verify(&home).is_err());

    let (home, _listener, _state) = live_home("ss-live-token-unbound", |state| {
        state.insert("auth_token_id".to_owned(), json!("0".repeat(64)));
    });
    assert!(verify(&home).is_err());
}

#[test]
fn state_gate_failures_are_refused_before_any_connection() {
    let edits: [fn(&mut Map<String, Value>); 4] = [
        |state| {
            state.remove("compatibility_version");
        },
        |state| {
            state.insert("compatibility_version".to_owned(), json!(1));
        },
        |state| {
            state.insert("pid".to_owned(), json!(i32::MAX));
        },
        |state| {
            state.insert("pid".to_owned(), json!(0));
        },
    ];
    for (index, edit) in edits.into_iter().enumerate() {
        let (home, _listener, _state) = live_home(&format!("ss-live-gate-{index}"), edit);
        assert!(verify(&home).is_err(), "gate {index} passed");
    }
}

#[test]
fn unsigned_state_is_refused() {
    let (home, _listener, mut state) = live_home("ss-live-unsigned", |_| {});
    state.insert("state_signature".to_owned(), json!("0".repeat(64)));
    write_private(
        &home.state_path,
        &serde_json::to_string(&Value::Object(state)).unwrap(),
    );
    assert!(verify(&home).is_err());
}

#[test]
fn refused_challenge_is_refused() {
    let (home, listener, state) = live_home("ss-live-refused", |_| {});
    let daemon = serve(listener, state, vec![Reply::Refuse(403)]);
    assert!(verify(&home).is_err());
    assert_eq!(daemon.join().unwrap(), ["/v1/daemon/identity-challenge"]);
}

#[test]
fn health_that_is_not_current_is_refused() {
    let bodies: [(u16, &'static str); 4] = [
        (500, CURRENT_HEALTH),
        (200, r#"{"ok":true,"compatibility_version":1}"#),
        (
            200,
            r#"{"ok":true,"compatibility_version":2,"tables":["other"]}"#,
        ),
        (200, "not json"),
    ];
    for (index, (status, body)) in bodies.into_iter().enumerate() {
        let (home, listener, state) = live_home(&format!("ss-live-health-{index}"), |_| {});
        let daemon = serve(
            listener,
            state,
            vec![Reply::Challenge, Reply::Health(status, body, None)],
        );
        assert!(verify(&home).is_err(), "health {index} passed");
        assert_eq!(daemon.join().unwrap().len(), 2);
    }
}

#[test]
fn daemon_replaced_during_verification_is_refused() {
    let (home, listener, state) = live_home("ss-live-replaced", |_| {});
    let mut replaced = state.clone();
    replaced.insert("state_id".to_owned(), json!("state-replaced"));
    replaced.insert("started_at".to_owned(), json!("2026-10-13T00:00:00+00:00"));
    let rewrite = Some((home.state_path.clone(), signed_text(&replaced)));
    let daemon = serve(
        listener,
        state,
        vec![
            Reply::Challenge,
            Reply::Health(200, CURRENT_HEALTH, rewrite),
        ],
    );
    assert!(verify(&home).is_err());
    assert_eq!(daemon.join().unwrap().len(), 2);
}

#[test]
fn no_daemon_listening_is_refused() {
    let (home, listener, _state) = live_home("ss-live-closed", |_| {});
    drop(listener);
    assert!(verify(&home).is_err());
}

#[test]
fn daemon_of_another_version_or_host_is_refused_before_any_connection() {
    let edits: [fn(&mut Map<String, Value>); 5] = [
        |state| {
            state.insert("package_version".to_owned(), json!("0.0.0-stale"));
        },
        |state| {
            state.remove("package_version");
        },
        |state| {
            state.insert("package_version".to_owned(), json!(1));
        },
        |state| {
            state.insert("host".to_owned(), json!("localhost"));
        },
        |state| {
            state.insert("host".to_owned(), json!("::1"));
        },
    ];
    for (index, edit) in edits.into_iter().enumerate() {
        let (home, listener, _state) = live_home(&format!("ss-live-current-{index}"), edit);
        listener.set_nonblocking(true).unwrap();
        assert!(verify(&home).is_err(), "daemon {index} passed");
        // Nothing reached the listener: the gate ran before any connection.
        assert!(listener.accept().is_err(), "daemon {index} was contacted");
    }
}

#[test]
fn a_down_daemon_of_this_version_yields_its_last_url() {
    let (home, listener, _state) = live_home("ss-down-url", |state| {
        state.insert("pid".to_owned(), json!(i32::MAX));
    });
    let port = listener.local_addr().unwrap().port();

    assert_eq!(
        stopped_daemon_url(&home.state_path),
        Ok(format!("http://127.0.0.1:{port}"))
    );
    assert!(verify(&home).is_err());
}

#[test]
fn a_running_unidentified_foreign_or_unsigned_daemon_is_not_down() {
    let (home, _listener, _state) = live_home("ss-down-running", |_| {});
    assert!(stopped_daemon_url(&home.state_path).is_err(), "running pid");

    let edits: [fn(&mut Map<String, Value>); 4] = [
        |state| {
            state.insert("pid".to_owned(), json!(0));
        },
        |state| {
            state.remove("pid");
        },
        |state| {
            state.insert("pid".to_owned(), json!(i32::MAX));
            state.insert("package_version".to_owned(), json!("0.0.0"));
        },
        |state| {
            state.insert("pid".to_owned(), json!(i32::MAX));
            state.insert("host".to_owned(), json!("::1"));
        },
    ];
    for (index, edit) in edits.into_iter().enumerate() {
        let (home, _listener, _state) = live_home(&format!("ss-down-gate-{index}"), edit);
        assert!(
            stopped_daemon_url(&home.state_path).is_err(),
            "gate {index}"
        );
    }

    let (home, _listener, mut state) = live_home("ss-down-unsigned", |state| {
        state.insert("pid".to_owned(), json!(i32::MAX));
    });
    state.insert("state_signature".to_owned(), json!("0".repeat(64)));
    write_private(
        &home.state_path,
        &serde_json::to_string(&Value::Object(state)).unwrap(),
    );
    assert!(stopped_daemon_url(&home.state_path).is_err(), "unsigned");
}
