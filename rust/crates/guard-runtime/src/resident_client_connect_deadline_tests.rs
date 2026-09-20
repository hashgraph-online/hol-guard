use super::*;
use std::cell::RefCell;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const CONTROL_WAIT: Duration = Duration::from_secs(4);

struct Pause {
    entered: Sender<()>,
    release: Receiver<()>,
}

thread_local! {
    static PAUSE: RefCell<Option<Pause>> = const { RefCell::new(None) };
}

pub(super) fn checkpoint() {
    PAUSE.with(|slot| {
        if let Some(pause) = slot.borrow_mut().take() {
            pause.entered.send(()).unwrap();
            pause.release.recv_timeout(CONTROL_WAIT).unwrap();
        }
    });
}

struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        // Keep the socket path below both Linux and macOS sockaddr bounds.
        let path = PathBuf::from("/tmp").join(format!(
            "hg-deadline-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn controlled_connect(expire: bool) -> (Result<(), String>, bool) {
    let home = Home::new();
    let endpoint = home.0.join("resident.sock");
    let listener = UnixListener::bind(&endpoint).unwrap();
    listener.set_nonblocking(true).unwrap();
    let marker = crate::resident_state::process_start_marker(std::process::id()).unwrap();
    let (entered, observed) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let deadline = Instant::now() + Duration::from_secs(2);
    let (result, expired_on_release) = thread::scope(|scope| {
        let worker = scope.spawn(move || {
            PAUSE.with(|slot| {
                *slot.borrow_mut() = Some(Pause {
                    entered,
                    release: released,
                });
            });
            let identity = ExpectedProcessIdentity {
                process_id: std::process::id(),
                start_marker: &marker,
                digest: None,
            };
            connect_unix_with_digest(endpoint.to_str().unwrap(), deadline, &identity).map(drop)
        });
        observed.recv_timeout(CONTROL_WAIT).unwrap();
        assert!(
            Instant::now() < deadline,
            "fixture missed socket setup boundary"
        );
        if expire {
            thread::sleep(
                deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
            );
            assert!(Instant::now() >= deadline);
        }
        let expired_on_release = Instant::now() >= deadline;
        release.send(()).unwrap();
        (worker.join().unwrap(), expired_on_release)
    });
    let connected = match listener.accept() {
        Ok((_stream, _)) => true,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => false,
        Err(error) => panic!("owned Unix listener acceptance failed: {error}"),
    };
    drop(listener);
    fs::remove_dir_all(&home.0).unwrap();
    assert!(!home.0.exists(), "owned Unix fixture was not removed");
    let case = if expire {
        "unix_socket_setup_cannot_admit_after_original_deadline"
    } else {
        "unix_socket_setup_retains_in_budget_connection"
    };
    let outcome = match &result {
        Ok(()) => "connected",
        Err(error) if error == "native_client_deadline_exceeded" => "deadline",
        _ => "unexpected",
    };
    eprintln!(
        "HOL_GUARD_DEADLINE_CONTROL {}",
        serde_json::json!({
            "case": case,
            "result": outcome,
            "connected": connected,
            "expired_on_release": expired_on_release,
            "owned_cleanup": true,
        })
    );
    (result, connected)
}

#[test]
fn unix_socket_setup_cannot_admit_after_original_deadline() {
    let (result, connected) = controlled_connect(true);
    assert!(
        !connected,
        "expired socket setup admitted a real Unix connection"
    );
    assert_eq!(result, Err("native_client_deadline_exceeded".to_owned()));
}

#[test]
fn unix_socket_setup_retains_in_budget_connection() {
    let (result, connected) = controlled_connect(false);
    assert_eq!(result, Ok(()));
    assert!(
        connected,
        "in-budget request did not reach the owned Unix listener"
    );
}
