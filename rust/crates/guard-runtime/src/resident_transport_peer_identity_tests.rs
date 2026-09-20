//! Real process boundaries for the existing Unix connector and wire protocol.

use super::*;
use crate::resident_client::{send_request_for_digest_detailed, ExpectedProcessIdentity};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const CHILD_TEST: &str = "resident_transport::peer_identity_tests::owned_peer_process";
const ROOT_ENV: &str = "HOL_GUARD_TEST_UNIX_PEER_ROOT";
const CASE_ENV: &str = "HOL_GUARD_TEST_UNIX_PEER_CASE";
const FIXTURE_WAIT: Duration = Duration::from_secs(5);
const REQUEST_BUDGET: Duration = Duration::from_secs(2);
const TOKEN: [u8; crate::AUTH_TOKEN_BYTES] = [17; crate::AUTH_TOKEN_BYTES];
const REQUEST: &[u8] = b"rsp091-private-synthetic-request";
const RESPONSE: &[u8] = b"rsp091-private-synthetic-response";

fn private_file(path: &Path) -> File {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
}

fn publish(root: &Path, name: &str, body: &[u8]) {
    let temporary = root.join(format!("{name}.pending"));
    let mut file = private_file(&temporary);
    file.write_all(body).unwrap();
    drop(file);
    fs::rename(temporary, root.join(name)).unwrap();
}

fn await_file(path: &Path) {
    let deadline = Instant::now() + FIXTURE_WAIT;
    while !path.is_file() {
        assert!(Instant::now() < deadline, "fixture_file_deadline");
        thread::sleep(Duration::from_millis(2));
    }
}

struct OwnedPeer {
    root: PathBuf,
    child: Child,
    reaped: bool,
}

impl OwnedPeer {
    fn start(negative: bool) -> Self {
        let root = PathBuf::from("/tmp").join(format!(
            "hg-peer-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                CHILD_TEST,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(ROOT_ENV, &root)
            .env(CASE_ENV, if negative { "negative" } else { "positive" })
            .stdin(Stdio::null())
            // The outer bounded test command retains original child diagnostics.
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn();
        let child = match child {
            Ok(child) => child,
            Err(error) => {
                let _ = fs::remove_dir_all(&root);
                panic!("owned_peer_spawn_failed: {error}");
            }
        };
        Self {
            root,
            child,
            reaped: false,
        }
    }

    fn poll_exit(&mut self, timeout: Duration) -> io::Result<Option<ExitStatus>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.reaped = true;
                return Ok(Some(status));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn finish(&mut self) -> Result<(), &'static str> {
        fs::write(self.root.join("release"), b"release").map_err(|_| "fixture_release_failed")?;
        match self.poll_exit(FIXTURE_WAIT) {
            Ok(Some(status)) if status.success() => {}
            Ok(Some(_)) => return Err("owned_peer_failed"),
            Ok(None) => return Err("owned_peer_exit_deadline"),
            Err(_) => return Err("owned_peer_wait_failed"),
        }
        fs::remove_dir_all(&self.root).map_err(|_| "owned_peer_directory_cleanup_failed")
    }
}

impl Drop for OwnedPeer {
    fn drop(&mut self) {
        if !self.reaped {
            // Exact owned child only; never signal a PID read from a fixture file.
            let _ = self.child.kill();
            let _ = self.poll_exit(Duration::from_secs(2));
        }
        if self.reaped {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn exercise(negative: bool) {
    let mut peer = OwnedPeer::start(negative);
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        await_file(&peer.root.join("ready"));
        let actual_peer_pid = peer.child.id();
        assert_ne!(actual_peer_pid, std::process::id());
        let selected_pid = if negative {
            std::process::id()
        } else {
            actual_peer_pid
        };
        let marker = crate::resident_state::process_start_marker(selected_pid).unwrap();
        // Both selected identities are real live instances of this package image.
        // Only the negative case's actual socket peer differs from the selection.
        crate::resident_state::validate_package_process_identity(selected_pid, &marker).unwrap();
        let identity = ExpectedProcessIdentity {
            process_id: selected_pid,
            start_marker: &marker,
            digest: None,
        };
        let endpoint = peer.root.join("resident.sock");
        let result = send_request_for_digest_detailed(
            "unix",
            endpoint.to_str().unwrap(),
            &TOKEN,
            REQUEST,
            REQUEST_BUDGET,
            &identity,
        );
        if negative {
            let error = result.unwrap_err();
            assert_eq!(error.code, "native_client_peer_identity_mismatch");
            assert!(!error.retryable_teardown);
        } else {
            assert_eq!(result.unwrap(), RESPONSE);
            fs::write(peer.root.join("response-received"), b"received").unwrap();
        }
        await_file(&peer.root.join("observed.json"));
        let body = fs::read(peer.root.join("observed.json")).unwrap();
        assert!(body.len() <= 1024);
        let observed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let expected = if negative {
            serde_json::json!({"accepted": 1, "received_bytes": 0, "authenticated": false})
        } else {
            serde_json::json!({"accepted": 1, "payload_bytes": REQUEST.len(),
                "authenticated": true, "request_digest_valid": true, "response_written": true})
        };
        assert_eq!(observed, expected);
        println!("RSP091_OBSERVATION={observed}");
    }));
    let cleanup = peer.finish();
    println!(
        "RSP091_CLEANUP={{\"negative\":{negative},\"reaped\":{},\"directory_removed\":{}}}",
        peer.reaped,
        !peer.root.exists()
    );
    if let Err(original) = outcome {
        // A cleanup error never replaces the original test failure.
        std::panic::resume_unwind(original);
    }
    cleanup.unwrap();
}

#[test]
fn unix_peer_actual_owner_completes_original_exchange() {
    exercise(false);
}

#[test]
fn unix_peer_other_process_is_rejected_before_auth() {
    exercise(true);
}

#[test]
#[ignore = "Owned subprocess fixture; invoked only by the two peer controls"]
fn owned_peer_process() {
    let root = PathBuf::from(std::env::var_os(ROOT_ENV).expect("owned_peer_root_missing"));
    let negative = match std::env::var(CASE_ENV).as_deref() {
        Ok("negative") => true,
        Ok("positive") => false,
        _ => panic!("owned_peer_case_invalid"),
    };
    let listener = UnixListener::bind(root.join("resident.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    publish(&root, "ready", b"ready");
    let deadline = Instant::now() + FIXTURE_WAIT;
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "owned_peer_accept_deadline");
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("owned_peer_accept_failed: {error}"),
        }
    };
    stream.set_nonblocking(false).unwrap();
    drop(listener);
    let observed = if negative {
        stream.set_nonblocking(true).unwrap();
        let read_deadline = Instant::now() + REQUEST_BUDGET;
        let mut first = [0u8; 1];
        let received = loop {
            assert!(Instant::now() < read_deadline, "owned_peer_read_deadline");
            match stream.read(&mut first) {
                Ok(received) => break received,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("owned_peer_read_failed: {error}"),
            }
        };
        serde_json::json!({"accepted": 1, "received_bytes": received, "authenticated": false})
    } else {
        authenticate_resident_stream(&mut stream, &TOKEN).unwrap();
        let mut pending = read_request_header(Box::new(stream)).unwrap();
        assert_eq!(pending.length, REQUEST.len());
        pending
            .stream
            .set_resident_read_timeout(Some(REQUEST_BUDGET))
            .unwrap();
        let mut request = vec![0u8; pending.length];
        pending.stream.read_exact(&mut request).unwrap();
        assert_eq!(request, REQUEST);
        let digest: [u8; crate::FRAME_DIGEST_BYTES] = Sha256::digest(&request).into();
        assert_eq!(digest, pending.request_digest);
        write_bound_response(&mut *pending.stream, &pending.request_id, RESPONSE).unwrap();
        // Keep the original stream and process live through parent response receipt.
        publish(&root, "response-written", b"written");
        await_file(&root.join("response-received"));
        serde_json::json!({"accepted": 1, "payload_bytes": request.len(),
            "authenticated": true, "request_digest_valid": true, "response_written": true})
    };
    publish(
        &root,
        "observed.json",
        &serde_json::to_vec(&observed).unwrap(),
    );
    await_file(&root.join("release"));
}
