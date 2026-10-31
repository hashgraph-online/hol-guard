use super::super::{handle_pending_request, ResidentStream};
use super::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Sender};

#[path = "resident_context_dispatch_reuse_tests.rs"]
mod reuse;

#[derive(Default)]
struct Gate {
    released: Mutex<bool>,
    wake: Condvar,
}
struct Release(Arc<Gate>);
impl Drop for Release {
    fn drop(&mut self) {
        *self.0.released.lock().unwrap() = true;
        self.0.wake.notify_all();
    }
}
struct Stream {
    input: Cursor<Vec<u8>>,
    output: Arc<Mutex<Vec<u8>>>,
    blocked: Option<(Sender<()>, Arc<Gate>)>,
}
impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.input.read(buf)
    }
}
impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some((entered, gate)) = self.blocked.take() {
            entered.send(()).unwrap();
            let (released, _) = gate
                .wake
                .wait_timeout_while(
                    gate.released.lock().unwrap(),
                    Duration::from_secs(5),
                    |released| !*released,
                )
                .unwrap();
            if !*released {
                return Err(io::ErrorKind::TimedOut.into());
            }
        }
        self.output.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl ResidentStream for Stream {
    fn set_resident_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
    fn set_resident_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
    fn set_resident_nonblocking(&self, _: bool) -> io::Result<()> {
        Ok(())
    }
}
type Output = Arc<Mutex<Vec<u8>>>;
fn pending(body: Vec<u8>, blocked: Option<(Sender<()>, Arc<Gate>)>) -> (PendingRequest, Output) {
    let output = Arc::new(Mutex::new(Vec::new()));
    let pending = PendingRequest {
        peer_identity: None,
        request_id: [17; crate::FRAME_REQUEST_ID_BYTES],
        request_digest: Sha256::digest(&body).into(),
        length: body.len(),
        payload_prefix: Vec::new(),
        accepted_at: Instant::now(),
        stream: Box::new(Stream {
            input: Cursor::new(body),
            output: Arc::clone(&output),
            blocked,
        }),
    };
    (pending, output)
}
fn response(output: &Output) -> Value {
    serde_json::from_slice(&output.lock().unwrap()[crate::FRAME_HEADER_BYTES..]).unwrap()
}
fn context(kind: &str) -> Vec<u8> {
    context_at(kind, Path::new("/not-opened-without-resident"))
}
fn context_at(kind: &str, home: &Path) -> Vec<u8> {
    serde_json::to_vec(&json!({"operation":"context_assistance", "request": {
        "schema":"guard-context-assistance-request.v1", "request_id":"lane",
        "query":{"kind":kind,"guard_home":home, "input":{}}}}))
    .unwrap()
}

struct Fixture {
    home: PathBuf,
    store: Arc<PolicySnapshotStore>,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "guard-cigar-lane-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        let home = crate::resident_state::ensure_private_directory(&path, true).unwrap();
        crate::resident_state::private_file(&home.join("policy-verifier.key"), true, &home)
            .unwrap()
            .write_all(&[37; 32])
            .unwrap();
        let store = Arc::new(PolicySnapshotStore::new(&home, &"a".repeat(64)).unwrap());
        Self { home, store }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.home).unwrap();
    }
}

#[test]
fn routing_keeps_metadata_outside_context_jobs_and_handles_escaped_tags() {
    for kind in [
        "installations",
        "versions",
        "workspace",
        "workspace_access",
        "workspace_grant",
    ] {
        assert!(is_request(&context(kind)));
    }
    for kind in ["status", "stop", "activate", "recheck"] {
        assert!(!is_request(&context(kind)));
    }
    for action in ["begin", "status", "compile", "explain", "close"] {
        assert!(is_request(&serde_json::to_vec(&json!({"operation":"context_agent", "request":{"query":{"kind":"agent","input":{"action":action}}}})).unwrap()));
    }
    assert!(!is_request(
        br#"{"operation":"context_agent","request":{"query":{"input":{"action":"discover"}}}}"#
    ));
    assert!(is_request(
        br#"{"operation":"context_\u0061ssistance","request":{"query":{"kind":"work\u0073pace"}}}"#
    ));
    for bytes in [
        br#"{"operation":"context_agent","operation":"health","request":{}}"#.as_slice(),
        br#"{"operation":"context_assistance","request":{"query":{"kind":"workspace","kind":"status"}}}"#,
        br#"{"operation":"health","request":{}}"#,
        br#"{"operation":"context_assistance""#,
    ] { assert!(!is_request(bytes)); }
}

#[test]
fn blocked_context_responses_cannot_occupy_hook_workers_or_grow_beyond_two_jobs() {
    blocked_optional_responses("workspace");
}
#[test]
fn blocked_version_responses_leave_health_and_stop_available_and_bound_the_queue() {
    blocked_optional_responses("versions");
}
fn blocked_optional_responses(kind: &str) {
    // The native operation runs without an SDK enrollment and refuses normally.
    // Blocking only delivery proves the lane bounds its whole request lifetime.
    let lane = Arc::new(Lane::default());
    let fixture = Fixture::new();
    let mut body = context_at(kind, &fixture.home);
    if kind == "versions" {
        let mut request: Value = serde_json::from_slice(&body).unwrap();
        request["request"]["query"]["input"] = json!({"action":"jobs"});
        body = serde_json::to_vec(&request).unwrap();
    }
    let gate = Arc::new(Gate::default());
    let release = Release(Arc::clone(&gate));
    let (entered, entered_rx) = channel();
    for _ in 0..2 {
        let (pending, _) = pending(body.clone(), Some((entered.clone(), Arc::clone(&gate))));
        handle_pending_request(pending, Some(Arc::clone(&fixture.store)), None, Some(&lane));
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("context left the caller's worker");
    }
    assert_eq!(lane.state.lock().unwrap().active, 2);
    let (third, output) = pending(body.clone(), None);
    handle_pending_request(third, Some(Arc::clone(&fixture.store)), None, Some(&lane));
    let busy = response(&output);
    assert_eq!(busy["schema"], "guard-context-assistance-result.v1");
    assert_eq!(busy["status"], "error");
    assert_eq!(busy["code"], "native_context_assistance_busy");
    let request: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(busy["request_id"], request["request"]["request_id"]);
    assert_eq!(
        busy["request_sha256"],
        crate::package_authority_op::request_digest_with_limit(&request["request"], 64 * 1024)
            .unwrap()
    );
    assert!(busy["payload"].is_null());
    let agent = json!({"operation":"context_agent","request":{"schema":"guard-context-agent-request.v1","request_id":"begin-never-retried",
        "query":{"kind":"agent","guard_home":fixture.home,"input":{"action":"begin"}}}});
    let (agent_request, output) = pending(serde_json::to_vec(&agent).unwrap(), None);
    handle_pending_request(
        agent_request,
        Some(Arc::clone(&fixture.store)),
        None,
        Some(&lane),
    );
    let agent_busy = response(&output);
    assert_eq!(agent_busy["schema"], "guard-context-agent-result.v1");
    assert_eq!(agent_busy["code"], "native_context_assistance_busy");
    assert_eq!(
        agent_busy["request_sha256"],
        crate::package_authority_op::request_digest_with_limit(&agent["request"], 64 * 1024)
            .unwrap()
    );
    assert!(!agent_busy.to_string().contains("credential"));
    let (health, output) = pending(br#"{"operation":"health","request":{}}"#.to_vec(), None);
    handle_pending_request(health, None, None, Some(&lane));
    assert_eq!(response(&output)["status"], "ready");
    let (stop, output) = pending(context_at("stop", &fixture.home), None);
    handle_pending_request(stop, Some(Arc::clone(&fixture.store)), None, Some(&lane));
    assert_eq!(response(&output)["status"], "ok");
    assert_eq!(
        response(&output)["payload"]["state"]["requested_enabled"],
        false
    );
    assert_eq!(lane.state.lock().unwrap().active, 2);
    drop(release);
    lane.drain();
    assert_eq!(lane.state.lock().unwrap().active, 0);
    lane.close();
    assert!(lane.reserve().is_none());
}

#[test]
fn tampered_frames_never_enter_the_context_lane() {
    let lane = Arc::new(Lane::default());
    let (mut request, output) = pending(context("workspace"), None);
    request.request_digest[0] ^= 1;
    handle_pending_request(request, None, None, Some(&lane));
    assert_eq!(response(&output)["error"], "native_request_digest_mismatch");
    assert_eq!(lane.state.lock().unwrap().active, 0);
}
