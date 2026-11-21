//! The Cursor bridge's daemon start: a daemon that is down, did not answer
//! or refused the hook is started with the client's recovery command and
//! asked once more, only if it came up anew; an overloaded one never is.

use std::io::BufReader;
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::json;

use super::daemon::recovery_argv;
use super::*;
use crate::claude_hook_bridge_fixture::{read_request, write_private, write_response, GuardHome};
use crate::cursor_hook_bridge_response::{ALLOW_STDOUT, UNAVAILABLE_STDOUT};

const TOKEN: &str = "cursor-restart-token-fixture";
const SHELL: &[u8] =
    br#"{"hook_event_name":"beforeShellExecution","command":"ls","cwd":"/nonexistent-cursor-cwd"}"#;
const ALLOW: &str = r#"{"policy_action":"allow"}"#;

/// A scripted daemon that answers every hook alike until it is finished.
struct Daemon {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: JoinHandle<usize>,
}

impl Daemon {
    fn serve(status: u16, body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let mut asked = 0;
            while !stopped.load(Ordering::SeqCst) {
                let Ok((stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut writer = stream.try_clone().unwrap();
                if read_request(&mut BufReader::new(stream)).is_some() {
                    asked += 1;
                    write_response(&mut writer, status, body, true);
                }
            }
            asked
        });
        Self { port, stop, handle }
    }

    /// How many hooks the daemon was sent.
    fn finish(self) -> usize {
        self.stop.store(true, Ordering::SeqCst);
        self.handle.join().unwrap()
    }
}

fn state_text(port: u16) -> String {
    json!({"host": "127.0.0.1", "port": port}).to_string()
}

/// A Guard home with the daemon token, naming the daemon on `port` if any.
fn guard_home(label: &str, port: Option<u16>) -> GuardHome {
    let home = GuardHome::new(&format!("cursor-restart-{label}"));
    write_private(&home.home.join("daemon-auth-token"), TOKEN);
    if let Some(port) = port {
        write_private(&home.state_path, &state_text(port));
    }
    home
}

/// A start command that records the failure kind it was given in
/// `marker` and, given a port, names a daemon on it in the state.
fn start_command(home: &GuardHome, marker: &Path, next_port: Option<u16>) -> Vec<String> {
    let mut script = format!("umask 077; printf '%s' \"$0\" > '{}'", marker.display());
    if let Some(port) = next_port {
        let next = home.scratch("next-state.json");
        write_private(&next, &state_text(port));
        let staged = home.scratch("staged-state.json");
        script.push_str(&format!(
            " && /bin/cp '{}' '{}' && /bin/mv '{}' '{}'",
            next.display(),
            staged.display(),
            staged.display(),
            home.state_path.display()
        ));
    }
    vec!["/bin/sh".to_owned(), "-c".to_owned(), script]
}

fn client_for(home: &GuardHome, command: Vec<String>, budget: Duration) -> Client {
    Client {
        guard_home: home.home_text().to_owned(),
        home: Some("/h".to_owned()),
        recovery_command: command,
        event: "beforeShellExecution".to_owned(),
        deadline: Instant::now() + budget,
    }
}

fn closed() -> Reply {
    Reply::Answered(UNAVAILABLE_STDOUT.to_owned(), 2)
}

#[test]
fn the_start_command_is_the_clients_recovery_command() {
    let python: Vec<String> = ["/py", "-I", "-S", "-s", "-c", "recover()"]
        .map(String::from)
        .to_vec();
    let mut told = python.clone();
    told.push("transport-failure".to_owned());
    assert_eq!(recovery_argv(&python, "transport-failure"), told);
    // A frozen runtime reads the kind from its environment alone.
    let frozen: Vec<String> = ["/hol-guard", "--_hol-guard-codex-daemon-recover", "{}"]
        .map(String::from)
        .to_vec();
    assert_eq!(recovery_argv(&frozen, "overload"), frozen);
    assert!(recovery_argv(&[], "transport-failure").is_empty());
}

#[test]
fn a_daemon_that_is_down_is_started_and_asked_once() {
    let started = Daemon::serve(200, ALLOW);
    let home = guard_home("down", None);
    let marker = home.scratch("started");
    let command = start_command(&home, &marker, Some(started.port));
    let client = client_for(&home, command, Duration::from_secs(20));
    assert_eq!(
        reply(&client, SHELL),
        Reply::Answered(ALLOW_STDOUT.to_owned(), 0)
    );
    assert_eq!(started.finish(), 1);
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        "transport-failure"
    );
}

#[test]
fn a_refusing_daemon_is_restarted_and_only_the_new_one_is_asked() {
    let refusing = Daemon::serve(500, r#"{"error":"internal"}"#);
    let started = Daemon::serve(200, ALLOW);
    let home = guard_home("refused", Some(refusing.port));
    let marker = home.scratch("started");
    let command = start_command(&home, &marker, Some(started.port));
    let client = client_for(&home, command, Duration::from_secs(20));
    assert_eq!(
        reply(&client, SHELL),
        Reply::Answered(ALLOW_STDOUT.to_owned(), 0)
    );
    assert_eq!(refusing.finish(), 1);
    assert_eq!(started.finish(), 1);
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        "authenticated-control-plane-failure"
    );
}

#[test]
fn an_overloaded_daemon_is_never_restarted() {
    let refusals: [(&str, u16, &'static str); 3] = [
        ("too-many", 429, r#"{"error":"slow down"}"#),
        ("unavailable", 503, r#"{"error":"later"}"#),
        ("capacity", 500, r#"{"error":"Daemon at capacity"}"#),
    ];
    for (label, status, body) in refusals {
        let overloaded = Daemon::serve(status, body);
        let started = Daemon::serve(200, ALLOW);
        let home = guard_home(label, Some(overloaded.port));
        let marker = home.scratch("started");
        let command = start_command(&home, &marker, Some(started.port));
        let client = client_for(&home, command, Duration::from_secs(20));
        assert_eq!(reply(&client, SHELL), closed(), "{label}");
        assert_eq!(overloaded.finish(), 1, "{label}");
        assert_eq!(started.finish(), 0, "{label}");
        assert!(!marker.exists(), "{label}");
    }
}

#[test]
fn a_daemon_that_saw_the_hook_is_never_sent_it_again() {
    let refusing = Daemon::serve(500, r#"{"error":"internal"}"#);
    let home = guard_home("same", Some(refusing.port));
    let marker = home.scratch("started");
    // The start leaves the same daemon in place.
    let command = start_command(&home, &marker, None);
    let client = client_for(&home, command, Duration::from_secs(3));
    assert_eq!(reply(&client, SHELL), closed());
    assert!(Instant::now() < client.deadline);
    assert!(marker.exists());
    assert_eq!(refusing.finish(), 1);
}

#[test]
fn a_failed_start_fails_closed() {
    let home = guard_home("failed-start", None);
    let command = vec!["/bin/sh".to_owned(), "-c".to_owned(), "exit 3".to_owned()];
    let client = client_for(&home, command, Duration::from_secs(20));
    assert_eq!(reply(&client, SHELL), closed());
}
