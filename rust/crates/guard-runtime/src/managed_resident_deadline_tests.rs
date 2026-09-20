//! Real authenticated socket regressions for the original managed deadline.
use super::*;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{SystemTime, UNIX_EPOCH};

const CONTROL_WAIT: Duration = Duration::from_secs(4);
const REQUEST: &[u8] = br#"{"operation":"evaluate","request":{}}"#;
const RESPONSE: &[u8] = br#"{"deadline_fixture":"accepted"}"#;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Stage {
    Validated,
    Returned,
    LeaseCleanup,
}

struct Pause {
    stage: Stage,
    entered: Sender<()>,
    release: Receiver<()>,
}

thread_local! {
    static PAUSE: RefCell<Option<Pause>> = const { RefCell::new(None) };
}

pub(super) fn checkpoint(stage: Stage) {
    PAUSE.with(|slot| {
        let selected = slot
            .borrow()
            .as_ref()
            .is_some_and(|pause| pause.stage == stage);
        if selected {
            let pause = slot.borrow_mut().take().unwrap();
            pause.entered.send(()).unwrap();
            pause.release.recv_timeout(CONTROL_WAIT).unwrap();
        }
    });
}

struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "hol-guard-managed-deadline-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        crate::resident_state::ensure_private_directory(&path, true).unwrap();
        Self(path)
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy)]
enum Reply {
    Bound,
    WrongProof,
    CommittedEof,
}

fn reply_once(
    stream: &mut TcpStream,
    token: &[u8; crate::AUTH_TOKEN_BYTES],
    reply: Reply,
) -> io::Result<bool> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(CONTROL_WAIT))?;
    stream.set_write_timeout(Some(CONTROL_WAIT))?;
    let mut nonce = [0; crate::AUTH_NONCE_BYTES];
    stream.read_exact(&mut nonce)?;
    if matches!(reply, Reply::WrongProof) {
        stream.write_all(&[0; crate::AUTH_PROOF_BYTES])?;
        return Ok(false);
    }
    stream.write_all(&crate::hmac_sha256(
        token,
        crate::SERVER_PROOF_LABEL,
        &nonce,
    ))?;
    let mut proof = [0; crate::AUTH_PROOF_BYTES];
    stream.read_exact(&mut proof)?;
    assert_eq!(
        proof,
        crate::hmac_sha256(token, crate::CLIENT_PROOF_LABEL, &nonce)
    );
    let mut header = [0; crate::FRAME_HEADER_BYTES];
    stream.read_exact(&mut header)?;
    assert_eq!(&header[..4], crate::REQUEST_MAGIC);
    let digest_start = 4 + crate::FRAME_REQUEST_ID_BYTES;
    let length = u32::from_be_bytes(header[crate::FRAME_HEADER_BYTES - 4..].try_into().unwrap());
    assert_eq!(length as usize, REQUEST.len());
    let mut body = vec![0; REQUEST.len()];
    stream.read_exact(&mut body)?;
    assert_eq!(body, REQUEST);
    assert_eq!(
        &header[digest_start..digest_start + crate::FRAME_DIGEST_BYTES],
        &Sha256::digest(&body)[..]
    );
    if matches!(reply, Reply::CommittedEof) {
        // The complete authenticated request arrived; no reply follows.
        return Ok(true);
    }
    let mut response = Vec::new();
    response.extend_from_slice(crate::RESPONSE_MAGIC);
    response.extend_from_slice(&header[4..digest_start]);
    response.extend_from_slice(&Sha256::digest(RESPONSE));
    response.extend_from_slice(&(RESPONSE.len() as u32).to_be_bytes());
    response.extend_from_slice(RESPONSE);
    stream.write_all(&response)?;
    stream.flush()?;
    Ok(true)
}

struct Peer {
    endpoint: String,
    stopped: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<io::Result<(usize, usize)>>>,
}

impl Peer {
    fn new(token: [u8; crate::AUTH_TOKEN_BYTES], reply: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let stopped = Arc::new(AtomicBool::new(false));
        let should_stop = Arc::clone(&stopped);
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + CONTROL_WAIT * 2;
            let mut accepted = 0;
            let mut completed = 0;
            while !should_stop.load(Ordering::Acquire) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        accepted += 1;
                        completed += usize::from(reply_once(&mut stream, &token, reply)?);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => return Err(error),
                }
            }
            // The owned client has joined before finish requests shutdown.
            // Count every connection it queued before returning.
            loop {
                match listener.accept() {
                    Ok((_stream, _)) => accepted += 1,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
            Ok((accepted, completed))
        });
        Self {
            endpoint,
            stopped,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> (usize, usize) {
        self.stopped.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap().unwrap()
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[derive(Clone, Copy)]
enum Call {
    Discovered,
    Leased,
    OneShot,
}

struct Client {
    release: Option<Sender<()>>,
    worker: Option<thread::JoinHandle<Result<Vec<u8>, String>>>,
}

impl Client {
    fn finish(mut self) -> Result<Vec<u8>, String> {
        self.release.take().unwrap().send(()).unwrap();
        self.worker.take().unwrap().join().unwrap()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn controlled_call(
    call: Call,
    stage: Stage,
    expire: bool,
    reply: Reply,
) -> (Result<Vec<u8>, String>, (usize, usize)) {
    let case = match (call, stage, expire, reply) {
        (Call::Discovered, Stage::Validated, true, Reply::Bound) => {
            "validation_delay_does_not_admit_expired_request"
        }
        (Call::Discovered, Stage::Validated, false, Reply::Bound) => {
            "validated_request_completes_authenticated_bound_exchange_once"
        }
        (Call::Leased, Stage::Returned, true, Reply::Bound) => {
            "leased_request_does_not_return_late_bound_success"
        }
        (Call::OneShot, Stage::LeaseCleanup, true, Reply::Bound) => {
            "lease_cleanup_does_not_return_late_bound_success"
        }
        (Call::OneShot, Stage::LeaseCleanup, false, Reply::Bound) => {
            "lease_cleanup_returns_timely_bound_success"
        }
        (Call::OneShot, Stage::LeaseCleanup, true, Reply::WrongProof) => {
            "late_lease_cleanup_preserves_fatal_authentication_error"
        }
        (Call::OneShot, Stage::LeaseCleanup, true, Reply::CommittedEof) => {
            "late_lease_cleanup_preserves_committed_response_error"
        }
        _ => panic!("unsupported managed deadline fixture"),
    };
    let home = Home::new();
    let digest = runtime_digest().unwrap();
    let scope = state_scope(&home.0, &digest).unwrap();
    let token = [93; crate::AUTH_TOKEN_BYTES];
    let peer = Peer::new(token, reply);
    crate::resident_state::publish_state(
        &scope,
        1,
        std::process::id(),
        &digest,
        "loopback",
        peer.endpoint.clone(),
        &token,
    )
    .unwrap();
    let (entered, observed) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let base = home.0.clone();
    let deadline = Instant::now() + Duration::from_secs(2);
    let worker = thread::spawn(move || {
        PAUSE.with(|slot| {
            *slot.borrow_mut() = Some(Pause {
                stage,
                entered,
                release: released,
            });
        });
        match call {
            Call::Discovered => try_home_states(&base, REQUEST, deadline, &digest)?
                .ok_or_else(|| "fixture_resident_unavailable".to_owned()),
            Call::Leased => {
                let client_lease = lease::acquire(&base)?;
                client_request_with_lease(&base, REQUEST, deadline, &client_lease)
            }
            Call::OneShot => client_request_at_deadline(&base, REQUEST, deadline),
        }
    });
    let client = Client {
        release: Some(release),
        worker: Some(worker),
    };
    observed.recv_timeout(CONTROL_WAIT).unwrap();
    if stage == Stage::LeaseCleanup {
        // This boundary is observed after the real lease destructor has run.
        assert!(
            fs::read_dir(home.0.join("resident-client-leases.v1"))
                .unwrap()
                .all(|entry| entry.unwrap().file_name() == ".leases.lock"),
            "owned lease remained at the post-cleanup boundary"
        );
    }
    assert!(
        Instant::now() < deadline,
        "fixture missed its selected boundary"
    );
    if expire {
        thread::sleep(
            deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
        );
        assert!(Instant::now() >= deadline);
    }
    let expired_on_release = Instant::now() >= deadline;
    let result = client.finish();
    let counts = peer.finish();
    fs::remove_dir_all(&home.0).unwrap();
    assert!(!home.0.exists(), "owned deadline fixture was not removed");
    let outcome = match &result {
        Ok(bytes) if bytes.as_slice() == RESPONSE => "bound_response",
        Err(error) if error == "native_client_deadline_exceeded" => "deadline",
        Err(error) if error == "native_resident_live_request_failed" => "live_request_failed",
        _ => "unexpected",
    };
    // Emit fixed evidence only after the real call, both joins and cleanup.
    eprintln!(
        "HOL_GUARD_DEADLINE_CONTROL {}",
        serde_json::json!({
            "case": case,
            "result": outcome,
            "connections": counts.0,
            "requests": counts.1,
            "expired_on_release": expired_on_release,
            "owned_cleanup": true,
        })
    );
    (result, counts)
}

#[test]
fn validation_delay_does_not_admit_expired_request() {
    let (result, counts) = controlled_call(Call::Discovered, Stage::Validated, true, Reply::Bound);
    assert_eq!(
        counts,
        (0, 0),
        "expired validation admitted a real connection or request"
    );
    assert_eq!(
        result,
        Err("native_resident_live_request_failed".to_owned())
    );
}

#[test]
fn validated_request_completes_authenticated_bound_exchange_once() {
    let (result, counts) = controlled_call(Call::Discovered, Stage::Validated, false, Reply::Bound);
    assert_eq!(result, Ok(RESPONSE.to_vec()));
    assert_eq!(counts, (1, 1));
}

#[test]
fn leased_request_does_not_return_late_bound_success() {
    let (result, counts) = controlled_call(Call::Leased, Stage::Returned, true, Reply::Bound);
    assert_eq!(counts, (1, 1), "a committed request was replayed");
    assert_eq!(result, Err("native_client_deadline_exceeded".to_owned()));
}

#[test]
fn lease_cleanup_does_not_return_late_bound_success() {
    let (result, counts) = controlled_call(Call::OneShot, Stage::LeaseCleanup, true, Reply::Bound);
    assert_eq!(counts, (1, 1), "a committed request was replayed");
    assert_eq!(result, Err("native_client_deadline_exceeded".to_owned()));
}

#[test]
fn late_lease_cleanup_preserves_fatal_authentication_error() {
    let (result, counts) =
        controlled_call(Call::OneShot, Stage::LeaseCleanup, true, Reply::WrongProof);
    assert_eq!(counts, (1, 0), "an authentication rejection was replayed");
    assert_eq!(
        result,
        Err("native_resident_live_request_failed".to_owned())
    );
}

#[test]
fn lease_cleanup_returns_timely_bound_success() {
    let (result, counts) = controlled_call(Call::OneShot, Stage::LeaseCleanup, false, Reply::Bound);
    assert_eq!(result, Ok(RESPONSE.to_vec()));
    assert_eq!(counts, (1, 1));
}

#[test]
fn late_lease_cleanup_preserves_committed_response_error() {
    let (result, counts) = controlled_call(
        Call::OneShot,
        Stage::LeaseCleanup,
        true,
        Reply::CommittedEof,
    );
    assert_eq!(
        counts,
        (1, 1),
        "an ambiguous committed request was replayed"
    );
    assert_eq!(
        result,
        Err("native_resident_live_request_failed".to_owned())
    );
}
