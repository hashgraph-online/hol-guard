use super::*;
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

struct TestHome(PathBuf);

impl TestHome {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "hol-guard-managed-retry-{}-{}",
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

impl Drop for TestHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct TestOwner(Child);

impl TestOwner {
    fn spawn() -> Self {
        Self(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "managed_resident::retry_tests::managed_retry_owner_child",
                ])
                .env("HOL_GUARD_RETRY_OWNER_CHILD", "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }

    fn stop(&mut self) {
        let _ = self.0.kill();
        self.0.wait().unwrap();
    }
}

impl Drop for TestOwner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn managed_retry_owner_child() {
    if std::env::var_os("HOL_GUARD_RETRY_OWNER_CHILD").is_some() {
        let mut byte = [0];
        let _ = std::io::stdin().read_exact(&mut byte);
    }
}

fn accept_bounded(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // BSD sockets inherit the listener's nonblocking mode. The
                // exchange below uses blocking I/O with bounded timeouts.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                return stream;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("managed retry fixture did not receive a connection: {error}"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum FailurePhase {
    Authentication,
    CommittedResponse,
}

#[test]
fn managed_restart_preserves_fatal_exchange_failures_after_owner_exit() {
    for phase in [
        FailurePhase::Authentication,
        FailurePhase::CommittedResponse,
    ] {
        for owner_exits in [false, true] {
            let home = TestHome::new();
            let digest = runtime_digest().unwrap();
            let scope = state_scope(&home.0, &digest).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let token = [71u8; crate::AUTH_TOKEN_BYTES];
            let payload = br#"{"operation":"evaluate","request":{}}"#;
            let mut owner = owner_exits.then(TestOwner::spawn);
            let owner_id = owner
                .as_ref()
                .map_or_else(std::process::id, |owner| owner.0.id());
            crate::resident_state::publish_state(
                &scope,
                1,
                owner_id,
                &digest,
                "loopback",
                listener.local_addr().unwrap().to_string(),
                &token,
            )
            .unwrap();
            let peer = thread::spawn(move || {
                let mut stream = accept_bounded(&listener);
                let mut nonce = [0; crate::AUTH_NONCE_BYTES];
                stream.read_exact(&mut nonce).unwrap();
                let received_request = match phase {
                    FailurePhase::Authentication => false,
                    FailurePhase::CommittedResponse => {
                        stream
                            .write_all(&crate::hmac_sha256(
                                &token,
                                crate::SERVER_PROOF_LABEL,
                                &nonce,
                            ))
                            .unwrap();
                        let mut proof = [0; crate::AUTH_PROOF_BYTES];
                        stream.read_exact(&mut proof).unwrap();
                        assert_eq!(
                            proof,
                            crate::hmac_sha256(&token, crate::CLIENT_PROOF_LABEL, &nonce)
                        );
                        let mut header = [0; crate::FRAME_HEADER_BYTES];
                        stream.read_exact(&mut header).unwrap();
                        assert_eq!(&header[..4], crate::REQUEST_MAGIC);
                        let mut body = vec![0; payload.len()];
                        stream.read_exact(&mut body).unwrap();
                        assert_eq!(body, payload);
                        true
                    }
                };
                if let Some(owner) = owner.as_mut() {
                    owner.stop();
                }
                match phase {
                    FailurePhase::Authentication => {
                        stream.write_all(&[0; crate::AUTH_PROOF_BYTES]).unwrap();
                    }
                    FailurePhase::CommittedResponse => {
                        // The peer received the complete authenticated request.
                        // Closing without a response leaves its commit ambiguous.
                        stream.shutdown(Shutdown::Both).unwrap();
                    }
                }
                received_request
            });
            let result = containment::try_live_or_restart(
                &home.0,
                payload,
                Instant::now() + Duration::from_secs(2),
                &digest,
            );
            let received_request = peer.join().unwrap();
            assert_eq!(
                received_request,
                matches!(phase, FailurePhase::CommittedResponse)
            );
            assert_eq!(
                result,
                Err("native_resident_live_request_failed".to_owned()),
                "fatal exchange was made restartable: {phase:?}, owner_exits={owner_exits}"
            );
        }
    }
}

#[test]
fn managed_restart_still_allows_connection_unavailable_before_exchange() {
    let home = TestHome::new();
    let digest = runtime_digest().unwrap();
    let scope = state_scope(&home.0, &digest).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    drop(listener);
    crate::resident_state::publish_state(
        &scope,
        1,
        std::process::id(),
        &digest,
        "loopback",
        endpoint,
        &[72u8; crate::AUTH_TOKEN_BYTES],
    )
    .unwrap();
    assert_eq!(
        containment::try_live_or_restart(
            &home.0,
            b"{}",
            Instant::now() + Duration::from_secs(1),
            &digest,
        ),
        Ok(None)
    );
}
