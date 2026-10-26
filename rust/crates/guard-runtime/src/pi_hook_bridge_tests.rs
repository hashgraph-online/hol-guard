//! The native Pi hook bridge: its config, and the reply it relays from a
//! scripted daemon when no resident answers.

use std::io::BufReader;
use std::net::TcpListener;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::*;
use crate::claude_hook_bridge_fixture::{
    read_request, write_private, write_response, GuardHome, Request,
};

const TOKEN: &str = "pi-token-fixture";
const PRE_TOOL: &str = r#"{"hook_event_name":"PreToolUse","tool_name":"bash"}"#;

fn config_text(changes: &[(&str, Option<Value>)]) -> String {
    let mut config = json!({
        "harness": "pi",
        "guard_home": "/tmp/guard-home",
        "query": "guard-home=%2Ftmp%2Fguard-home&workspace=%2Ftmp%2Fwork+space",
        "timeout_ms": 3100,
    });
    for (key, value) in changes {
        match value {
            Some(value) => config[*key] = value.clone(),
            None => {
                config.as_object_mut().unwrap().remove(*key);
            }
        }
    }
    config.to_string()
}

#[test]
fn configs_name_a_pi_harness_an_absolute_home_a_plain_query_and_a_bounded_timeout() {
    let parsed = parse_config(&config_text(&[])).unwrap();
    assert_eq!(parsed.harness, PI);
    assert_eq!(parsed.guard_home, PathBuf::from("/tmp/guard-home"));
    assert_eq!(parsed.timeout, Duration::from_millis(3100));
    let omp = parse_config(&config_text(&[("harness", Some(json!("omp")))])).unwrap();
    assert_eq!(omp.harness, OMP);

    for change in [
        ("harness", Some(json!("codex"))),
        ("harness", None),
        ("guard_home", Some(json!("relative/home"))),
        ("guard_home", None),
        ("query", Some(json!("guard-home=/tmp x"))),
        ("query", Some(json!("a=b\r\nX-Injected: 1"))),
        ("query", Some(json!("a=b#fragment"))),
        ("query", None),
        ("timeout_ms", Some(json!(0))),
        ("timeout_ms", Some(json!(60_001))),
        ("timeout_ms", Some(json!("3100"))),
    ] {
        assert_eq!(
            parse_config(&config_text(&[change.clone()])),
            None,
            "{change:?}"
        );
    }
    assert_eq!(parse_config("[]"), None);
    assert_eq!(parse_config("not json"), None);
}

#[test]
fn replies_are_one_line_the_extension_reads_as_an_http_response() {
    assert_eq!(envelope(None), "{\"status\":0}\n");
    let line = envelope(Some((200, "{\"decision\":\"allow\"}".to_owned())));
    assert!(line.ends_with('\n') && !line.trim_end().contains('\n'));
    let parsed: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(
        parsed,
        json!({"status": 200, "body": "{\"decision\":\"allow\"}"})
    );
}

fn home_config(home: &GuardHome, harness: &str) -> PiBridgeConfig {
    PiBridgeConfig {
        harness: if harness == "omp" { OMP } else { PI },
        guard_home: home.home.clone(),
        query: "guard-home=%2Fsomewhere&workspace=%2Ftmp".to_owned(),
        timeout: Duration::from_secs(20),
    }
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

/// Answer one hook POST with `status` and `body`, returning the request.
fn serve_once(listener: TcpListener, status: u16, body: String) -> JoinHandle<Option<Request>> {
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().ok()?;
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut writer = stream.try_clone().unwrap();
        let request = read_request(&mut BufReader::new(stream))?;
        write_response(&mut writer, status, &body, true);
        Some(request)
    })
}

fn home_with_daemon(label: &str, port: u16) -> GuardHome {
    let home = GuardHome::new(label);
    write_private(
        &home.state_path,
        &json!({"host": "127.0.0.1", "port": port}).to_string(),
    );
    write_private(&home.home.join("daemon-auth-token"), TOKEN);
    home
}

#[test]
fn no_daemon_state_is_no_reply() {
    let home = GuardHome::new("pi-bridge-no-state");
    assert_eq!(reply(&home_config(&home, "pi"), PRE_TOOL, soon()), None);
}

#[test]
fn a_hook_no_resident_answers_goes_to_the_daemon_as_the_extension_sent_it() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let answer = r#"{"decision":"deny","reason":"blocked by policy"}"#;
    let daemon = serve_once(listener, 200, answer.to_owned());
    let home = home_with_daemon("pi-bridge-daemon", port);

    let replied = reply(&home_config(&home, "omp"), PRE_TOOL, soon());

    assert_eq!(replied, Some((200, answer.to_owned())));
    let request = daemon.join().unwrap().unwrap();
    assert_eq!(
        request.target,
        "/v1/hooks/omp?guard-home=%2Fsomewhere&workspace=%2Ftmp"
    );
    assert_eq!(request.header("X-Guard-Token"), Some(TOKEN));
    assert_eq!(request.body, PRE_TOOL.as_bytes());
}

#[test]
fn a_daemon_refusal_is_relayed_with_its_status() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let refusal = r#"{"error":"forbidden"}"#;
    let daemon = serve_once(listener, 403, refusal.to_owned());
    let home = home_with_daemon("pi-bridge-refused", port);

    let replied = reply(&home_config(&home, "pi"), PRE_TOOL, soon());

    assert_eq!(replied, Some((403, refusal.to_owned())));
    assert!(daemon.join().unwrap().is_some());
}

#[test]
fn a_daemon_that_does_not_answer_in_time_is_no_reply() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let home = home_with_daemon("pi-bridge-silent", port);
    let deadline = Instant::now() + Duration::from_millis(300);

    assert_eq!(reply(&home_config(&home, "pi"), PRE_TOOL, deadline), None);
    drop(listener);
}
