use super::*;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::thread;

const TOKEN: [u8; crate::AUTH_TOKEN_BYTES] = [0x5a; crate::AUTH_TOKEN_BYTES];

fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    for stream in [&client, &server] {
        stream.set_nodelay(true).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
    (client, server)
}

fn accept_authentication(stream: &mut TcpStream, slow_proof: bool) -> io::Result<()> {
    let mut nonce = [0u8; AUTH_NONCE_BYTES];
    stream.read_exact(&mut nonce)?;
    let proof = hmac_sha256(&TOKEN, SERVER_PROOF_LABEL, &nonce);
    if slow_proof {
        // Every fragment arrives within the old socket inactivity timeout;
        // their aggregate duration exceeds the authentication phase budget.
        for chunk in proof.chunks(4) {
            thread::sleep(Duration::from_millis(40));
            stream.write_all(chunk)?;
        }
    } else {
        stream.write_all(&proof)?;
    }
    let mut client_proof = [0u8; AUTH_PROOF_BYTES];
    stream.read_exact(&mut client_proof)?;
    assert_eq!(
        client_proof,
        hmac_sha256(&TOKEN, CLIENT_PROOF_LABEL, &nonce)
    );
    Ok(())
}

fn accept_request(stream: &mut TcpStream) -> io::Result<[u8; FRAME_REQUEST_ID_BYTES]> {
    let mut header = [0u8; FRAME_HEADER_BYTES];
    stream.read_exact(&mut header)?;
    assert_eq!(&header[..4], REQUEST_MAGIC);
    let request_id = header[4..4 + FRAME_REQUEST_ID_BYTES].try_into().unwrap();
    let length = u32::from_be_bytes(header[FRAME_HEADER_BYTES - 4..].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload)?;
    assert_eq!(payload, b"{}");
    assert_eq!(
        &header[4 + FRAME_REQUEST_ID_BYTES..FRAME_HEADER_BYTES - 4],
        Sha256::digest(&payload).as_slice(),
    );
    Ok(request_id)
}

fn response_header(request_id: &[u8; FRAME_REQUEST_ID_BYTES], response: &[u8]) -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(RESPONSE_MAGIC);
    header.extend_from_slice(request_id);
    header.extend_from_slice(&Sha256::digest(response));
    header.extend_from_slice(&(response.len() as u32).to_be_bytes());
    header
}

#[test]
fn timely_authenticated_socket_response_is_unchanged() {
    let (mut client, mut server) = socket_pair();
    let peer = thread::spawn(move || -> io::Result<()> {
        accept_authentication(&mut server, false)?;
        let request_id = accept_request(&mut server)?;
        server.write_all(&response_header(&request_id, b"{}"))?;
        server.write_all(b"{}")
    });
    let result = exchange_request(
        &mut client,
        &TOKEN,
        b"{}",
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    assert_eq!(result, b"{}");
    peer.join().unwrap().unwrap();
}

#[test]
fn fragmented_server_proof_cannot_renew_authentication_budget() {
    let (mut client, mut server) = socket_pair();
    let peer = thread::spawn(move || -> io::Result<()> {
        accept_authentication(&mut server, true)?;
        let request_id = accept_request(&mut server)?;
        server.write_all(&response_header(&request_id, b"{}"))?;
        server.write_all(b"{}")
    });
    let started = Instant::now();
    let result = exchange_request(&mut client, &TOKEN, b"{}", started + Duration::from_secs(2));
    let elapsed = started.elapsed();
    let _ = client.shutdown(Shutdown::Both);
    let _ = peer.join().unwrap();
    let error = result.unwrap_err();
    assert_eq!(error.code, "native_client_frame_read_failed");
    assert!(!error.retryable_teardown);
    assert!(elapsed < Duration::from_millis(800));
}

#[test]
fn fragmented_response_header_cannot_renew_request_budget() {
    let (mut client, mut server) = socket_pair();
    let peer = thread::spawn(move || -> io::Result<()> {
        accept_authentication(&mut server, false)?;
        let request_id = accept_request(&mut server)?;
        for chunk in response_header(&request_id, b"{}").chunks(8) {
            thread::sleep(Duration::from_millis(40));
            server.write_all(chunk)?;
        }
        server.write_all(b"{}")
    });
    let started = Instant::now();
    let result = exchange_request(
        &mut client,
        &TOKEN,
        b"{}",
        started + Duration::from_millis(180),
    );
    let elapsed = started.elapsed();
    let _ = client.shutdown(Shutdown::Both);
    let _ = peer.join().unwrap();
    let error = result.unwrap_err();
    assert_eq!(error.code, "native_client_deadline_exceeded");
    assert!(!error.retryable_teardown);
    assert!(elapsed < Duration::from_millis(800));
}

#[test]
fn response_body_uses_time_left_after_header_and_partial_reads() {
    let (mut client, mut server) = socket_pair();
    let peer = thread::spawn(move || -> io::Result<()> {
        accept_authentication(&mut server, false)?;
        let request_id = accept_request(&mut server)?;
        thread::sleep(Duration::from_millis(70));
        server.write_all(&response_header(&request_id, b"{}"))?;
        for byte in b"{}" {
            thread::sleep(Duration::from_millis(70));
            server.write_all(&[*byte])?;
        }
        Ok(())
    });
    let started = Instant::now();
    let result = exchange_request(
        &mut client,
        &TOKEN,
        b"{}",
        started + Duration::from_millis(180),
    );
    let elapsed = started.elapsed();
    let _ = client.shutdown(Shutdown::Both);
    let _ = peer.join().unwrap();
    let error = result.unwrap_err();
    assert_eq!(error.code, "native_client_deadline_exceeded");
    assert!(!error.retryable_teardown);
    assert!(elapsed < Duration::from_millis(800));
}

#[cfg(unix)]
#[test]
fn progressing_backpressured_request_write_remains_bounded_and_nonretryable() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let (mut client, mut server) = socket_pair();
    nix::sys::socket::setsockopt(&client, nix::sys::socket::sockopt::SndBuf, &4096).unwrap();
    let stopped = Arc::new(AtomicBool::new(false));
    let peer_stopped = Arc::clone(&stopped);
    let peer = thread::spawn(move || -> io::Result<()> {
        accept_authentication(&mut server, false)?;
        let mut buffer = [0u8; 1024];
        while !peer_stopped.load(Ordering::Acquire) {
            if server.read(&mut buffer)? == 0 {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    });
    let payload = vec![b'x'; 2 * 1024 * 1024];
    let started = Instant::now();
    let result = exchange_request(
        &mut client,
        &TOKEN,
        &payload,
        started + Duration::from_millis(180),
    );
    let elapsed = started.elapsed();
    stopped.store(true, Ordering::Release);
    let _ = client.shutdown(Shutdown::Both);
    let _ = peer.join().unwrap();
    let error = result.unwrap_err();
    assert_eq!(error.code, "native_client_deadline_exceeded");
    assert!(!error.retryable_teardown);
    assert!(elapsed < Duration::from_millis(800));
}

#[test]
fn timely_authentication_rejection_keeps_its_fatal_error() {
    let (mut client, mut server) = socket_pair();
    let peer = thread::spawn(move || -> io::Result<()> {
        let mut nonce = [0u8; AUTH_NONCE_BYTES];
        server.read_exact(&mut nonce)?;
        server.write_all(&[0u8; AUTH_PROOF_BYTES])
    });
    let error = exchange_request(
        &mut client,
        &TOKEN,
        b"{}",
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap_err();
    assert_eq!(error.code, "native_client_auth_rejected");
    assert!(!error.retryable_teardown);
    peer.join().unwrap().unwrap();
}

#[test]
fn zero_budget_is_rejected_before_endpoint_or_process_access() {
    let error = send_request_for_digest_detailed(
        "loopback",
        "invalid",
        &TOKEN,
        b"{}",
        Duration::ZERO,
        &ExpectedProcessIdentity {
            process_id: 0,
            start_marker: "",
            digest: None,
        },
    )
    .unwrap_err();
    assert_eq!(error.code, "native_client_deadline_exceeded");
    assert!(!error.retryable_teardown);
}

struct TimeoutFallbackProbe {
    complete_after_deadline: bool,
    fallback_reads: usize,
}

impl Read for TimeoutFallbackProbe {
    fn read(&mut self, _output: &mut [u8]) -> io::Result<usize> {
        panic!("a failed timeout setter cannot enter the blocking read")
    }
}

impl Write for TimeoutFallbackProbe {
    fn write(&mut self, _input: &[u8]) -> io::Result<usize> {
        unreachable!()
    }

    fn flush(&mut self) -> io::Result<()> {
        unreachable!()
    }
}

impl ResidentStream for TimeoutFallbackProbe {
    fn set_resident_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(22))
    }

    fn set_resident_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        unreachable!()
    }

    fn set_resident_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        panic!("the deadline reader must not toggle socket mode")
    }

    fn read_buffered_after_timeout_error(
        &mut self,
        output: &mut [u8],
        _error: &io::Error,
        deadline: Instant,
    ) -> Option<io::Result<usize>> {
        if !self.complete_after_deadline {
            return None;
        }
        self.fallback_reads += 1;
        thread::sleep(
            deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
        );
        output[0] = b'x';
        Some(Ok(1))
    }
}

#[test]
fn unsupported_timeout_error_is_preserved_without_reading() {
    let mut stream = TimeoutFallbackProbe {
        complete_after_deadline: false,
        fallback_reads: 0,
    };
    let error = DeadlineStream::new(&mut stream, Instant::now() + Duration::from_secs(1))
        .read(&mut [0u8; 1])
        .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(22));
    assert_eq!(stream.fallback_reads, 0);
}

#[test]
fn buffered_fallback_cannot_bypass_absolute_deadline_after_read() {
    let mut stream = TimeoutFallbackProbe {
        complete_after_deadline: true,
        fallback_reads: 0,
    };
    let error = DeadlineStream::new(&mut stream, Instant::now() + Duration::from_millis(200))
        .read(&mut [0u8; 1])
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(stream.fallback_reads, 1);
}

#[cfg(target_os = "macos")]
mod macos_closed_peer {
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    const REQUEST_ID: [u8; FRAME_REQUEST_ID_BYTES] = [0x51; FRAME_REQUEST_ID_BYTES];

    fn closed_response(header: &[u8], body: &[u8]) -> UnixStream {
        let (client, mut server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        server.write_all(header).unwrap();
        server.write_all(body).unwrap();
        drop(server);
        let error = client
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(nix::errno::Errno::EINVAL as i32));
        let mut descriptors = [nix::poll::PollFd::new(
            client.as_fd(),
            nix::poll::PollFlags::POLLIN,
        )];
        assert_eq!(
            nix::poll::poll(&mut descriptors, nix::poll::PollTimeout::ZERO).unwrap(),
            1
        );
        assert!(descriptors[0]
            .revents()
            .unwrap()
            .contains(nix::poll::PollFlags::POLLHUP));
        client
    }

    fn assert_blocking(stream: &UnixStream) {
        let flags = nix::fcntl::fcntl(stream, nix::fcntl::FcntlArg::F_GETFL).unwrap();
        assert_eq!(flags & nix::fcntl::OFlag::O_NONBLOCK.bits(), 0);
    }

    #[test]
    fn complete_bound_response_survives_peer_close_without_changing_socket_mode() {
        let mut client = closed_response(&response_header(&REQUEST_ID, b"{}"), b"{}");
        assert_blocking(&client);
        let mut stream =
            DeadlineStream::new(&mut client, Instant::now() + Duration::from_millis(250));
        assert_eq!(
            read_committed_response(&mut stream, &REQUEST_ID).unwrap(),
            b"{}"
        );
        assert_eq!(stream.read(&mut [0u8; 1]).unwrap(), 0);
        assert_blocking(&client);
    }

    #[test]
    fn completed_write_can_flush_after_peer_close_without_replaying_request() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        DeadlineStream::new(&mut client, deadline)
            .write_all(b"{}")
            .unwrap();
        let mut request = [0u8; 2];
        server.read_exact(&mut request).unwrap();
        assert_eq!(request, *b"{}");
        server
            .write_all(&response_header(&REQUEST_ID, b"{}"))
            .unwrap();
        server.write_all(b"{}").unwrap();
        drop(server);
        let error = client
            .set_write_timeout(Some(Duration::from_millis(250)))
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(nix::errno::Errno::EINVAL as i32));
        assert_blocking(&client);
        let error = DeadlineStream::new(&mut client, Instant::now())
            .flush()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let mut stream = DeadlineStream::new(&mut client, deadline);
        stream.flush().unwrap();
        assert_eq!(
            read_committed_response(&mut stream, &REQUEST_ID).unwrap(),
            b"{}"
        );
        assert_eq!(stream.read(&mut [0u8; 1]).unwrap(), 0);
        assert_blocking(&client);
    }

    #[test]
    fn malformed_or_partial_buffered_responses_remain_fatal() {
        for (header, body, code) in [
            (
                response_header(&[0x52; FRAME_REQUEST_ID_BYTES], b"{}"),
                b"{}".as_slice(),
                "native_client_response_binding_failed",
            ),
            (
                response_header(&REQUEST_ID, b"{}"),
                b"[]".as_slice(),
                "native_client_response_digest_mismatch",
            ),
            (
                response_header(&REQUEST_ID, b"{}"),
                b"{".as_slice(),
                "native_client_frame_read_failed",
            ),
        ] {
            let mut client = closed_response(&header, body);
            let mut stream =
                DeadlineStream::new(&mut client, Instant::now() + Duration::from_millis(250));
            let error = read_committed_response(&mut stream, &REQUEST_ID).unwrap_err();
            assert_eq!(error.code, code);
            assert!(!error.retryable_teardown);
        }
    }

    #[test]
    fn expired_deadline_leaves_buffered_response_unread() {
        let mut client = closed_response(&response_header(&REQUEST_ID, b"{}"), b"{}");
        let error = DeadlineStream::new(&mut client, Instant::now())
            .read(&mut [0u8; 1])
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let mut stream =
            DeadlineStream::new(&mut client, Instant::now() + Duration::from_millis(250));
        assert_eq!(
            read_committed_response(&mut stream, &REQUEST_ID).unwrap(),
            b"{}"
        );
    }

    #[test]
    fn fallback_requires_exact_setter_error_and_actual_peer_hangup() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        server.write_all(b"x").unwrap();
        let mut output = [0u8; 1];
        let deadline = Instant::now() + Duration::from_millis(250);
        assert!(client
            .read_buffered_after_timeout_error(
                &mut output,
                &io::Error::from_raw_os_error(22),
                deadline
            )
            .is_none());
        assert!(client
            .flush_after_timeout_error(&io::Error::from_raw_os_error(22), deadline)
            .is_none());
        assert_eq!(output, [0]);
        drop(server);
        assert!(client
            .read_buffered_after_timeout_error(
                &mut output,
                &io::Error::from_raw_os_error(13),
                deadline
            )
            .is_none());
        assert!(client
            .flush_after_timeout_error(&io::Error::from_raw_os_error(13), deadline)
            .is_none());
        assert_eq!(output, [0]);
        assert_eq!(client.read(&mut output).unwrap(), 1);
        assert_eq!(output, [b'x']);
        assert_blocking(&client);
    }
}
