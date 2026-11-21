//! Real authenticated framing + workers + native owner, in a source test.
//! This is not an installed wheel or an OMP workflow qualification.
use super::*;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::Ordering;

const TOKEN: [u8; crate::AUTH_TOKEN_BYTES] = [73; crate::AUTH_TOKEN_BYTES];

fn send(
    admission: &crate::resident_transport::ResidentAdmission,
    request: &NativeBashExecuteRequestV1,
    marker: u8,
) -> UnixStream {
    let (mut client, server) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    crate::resident_transport::admit_connection(admission, Box::new(server)).unwrap();
    let nonce = [marker; crate::AUTH_NONCE_BYTES];
    client.write_all(&nonce).unwrap();
    let mut proof = [0; crate::AUTH_PROOF_BYTES];
    client.read_exact(&mut proof).unwrap();
    assert_eq!(
        proof,
        crate::resident_transport::hmac_sha256(&TOKEN, crate::SERVER_PROOF_LABEL, &nonce)
    );
    client
        .write_all(&crate::resident_transport::hmac_sha256(
            &TOKEN,
            crate::CLIENT_PROOF_LABEL,
            &nonce,
        ))
        .unwrap();
    let body =
        serde_json::to_vec(&json!({"operation":"native_bash_execute", "request":request})).unwrap();
    let mut frame = Vec::new();
    frame.extend_from_slice(crate::REQUEST_MAGIC);
    frame.extend_from_slice(&[marker; crate::FRAME_REQUEST_ID_BYTES]);
    frame.extend_from_slice(&Sha256::digest(&body));
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    client.write_all(&frame).unwrap();
    client
}

fn receive(mut client: UnixStream, marker: u8) -> NativeBashExecuteResultV1 {
    let mut header = [0; crate::FRAME_HEADER_BYTES];
    client.read_exact(&mut header).unwrap();
    let identity = crate::RESPONSE_MAGIC.len();
    let digest = identity + crate::FRAME_REQUEST_ID_BYTES;
    let length = digest + crate::FRAME_DIGEST_BYTES;
    assert_eq!(&header[..identity], crate::RESPONSE_MAGIC);
    assert_eq!(
        &header[identity..digest],
        &[marker; crate::FRAME_REQUEST_ID_BYTES]
    );
    let size = u32::from_be_bytes(header[length..].try_into().unwrap()) as usize;
    assert!(size > 0 && size <= crate::MAX_NATIVE_RESPONSE_BYTES);
    let mut body = vec![0; size];
    client.read_exact(&mut body).unwrap();
    assert_eq!(Sha256::digest(&body).as_slice(), &header[digest..length]);
    serde_json::from_slice(&body).unwrap()
}

fn wait_for(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "native launch did not reach its expected state"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn authenticated_bash_disconnect_before_launch_preserves_once_and_live_reissue_runs_once() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let claim = once(&request, &store, "2050-01-01T00:00:00+00:00");
    let execution = execution(request, envelope, claim.clone());
    seed_once_review(&execution.capture, &store, &claim, &execution.operation_id);
    let store = Arc::new(store);
    let fence = store.fence_for_launch(&execution.envelope).unwrap();
    let admission = crate::resident_transport::start_resident_workers(
        Arc::new(TOKEN),
        Some(Arc::clone(&store)),
    );
    let client = send(&admission, &execution, 1);
    let mut flag = None;
    wait_for(|| {
        flag = store
            .bash_launches()
            .active_cancellation(&execution.operation_id);
        flag.is_some()
    });
    let flag = flag.unwrap();
    assert!(!flag.load(Ordering::Acquire));
    drop(client);
    wait_for(|| flag.load(Ordering::Acquire));
    drop(fence);
    wait_for(|| {
        store
            .bash_launches()
            .active_cancellation(&execution.operation_id)
            .is_none()
    });
    let report = Path::new(&execution.capture.home_dir).join("maintenance-report.tsv");
    assert!(!report.exists());
    let connection = Connection::open(&claim.store_path).unwrap();
    let spent: Option<String> = connection
        .query_row(
            "SELECT claimed_at FROM guard_local_once_approvals WHERE approval_id=?1",
            [claim.decisions[0]["approval_id"].as_str().unwrap()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(spent.is_none());
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM guard_bash_operations", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        0
    );
    // Keeping the authenticated connection live must preserve response bytes
    // and normal completion when the disconnect reader is stopped.
    let first = receive(send(&admission, &execution, 2), 2);
    assert_eq!(first.status, "ok", "{}", first.code);
    assert!(first.grant_claimed && first.dispatch_acknowledged && !first.replayed);
    assert_eq!(first.payload.unwrap().exit_code, Some(0));
    std::fs::write(&report, "preserve completed operation").unwrap();
    let replay = receive(send(&admission, &execution, 3), 3);
    assert_eq!(replay.status, "recorded");
    assert!(replay.replayed && replay.grant_claimed && replay.dispatch_acknowledged);
    assert!(replay.payload.is_none());
    assert_eq!(
        std::fs::read_to_string(report).unwrap(),
        "preserve completed operation"
    );
    crate::resident_transport::drain_resident_workers(admission);
}
