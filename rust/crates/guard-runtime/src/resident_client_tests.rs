use super::*;
use std::io::{self, Read, Write};

#[derive(Default)]
struct TestStream {
    eof: bool,
    read_error: Option<io::ErrorKind>,
    write_error: Option<io::ErrorKind>,
    flush_error: Option<io::ErrorKind>,
    partial_write: bool,
}

impl TestStream {
    fn eof() -> Self {
        Self {
            eof: true,
            ..Self::default()
        }
    }

    fn read_error(kind: io::ErrorKind) -> Self {
        Self {
            read_error: Some(kind),
            ..Self::default()
        }
    }

    fn write_error(kind: io::ErrorKind) -> Self {
        Self {
            write_error: Some(kind),
            ..Self::default()
        }
    }

    fn partial_write_error(kind: io::ErrorKind) -> Self {
        Self {
            partial_write: true,
            ..Self::write_error(kind)
        }
    }

    fn flush_error(kind: io::ErrorKind) -> Self {
        Self {
            flush_error: Some(kind),
            ..Self::default()
        }
    }
}

impl Read for TestStream {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        if self.eof {
            return Ok(0);
        }
        self.read_error
            .map_or(Ok(0), |kind| Err(io::Error::from(kind)))
    }
}

impl Write for TestStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.partial_write {
            self.partial_write = false;
            return Ok(1.min(buffer.len()));
        }
        self.write_error
            .map_or(Ok(buffer.len()), |kind| Err(io::Error::from(kind)))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_error
            .map_or(Ok(()), |kind| Err(io::Error::from(kind)))
    }
}

impl crate::ResidentStream for TestStream {
    fn set_resident_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_resident_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn try_read_available(&mut self, _output: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

#[test]
fn rejects_non_loopback_tcp_endpoint() {
    let error = match connect_loopback_with_digest(
        "192.0.2.1:80",
        Duration::from_millis(1),
        &ExpectedProcessIdentity {
            process_id: 1,
            start_marker: "",
            digest: None,
        },
    ) {
        Ok(_) => panic!("non-loopback endpoint was accepted"),
        Err(error) => error,
    };
    assert_eq!(error, "native_client_endpoint_invalid");
}

#[cfg(unix)]
#[test]
fn rejects_response_bound_to_another_request() {
    use std::os::unix::net::UnixStream;
    use std::thread;

    let (mut client, mut server) = UnixStream::pair().unwrap();
    let expected_request_id = [1u8; FRAME_REQUEST_ID_BYTES];
    thread::spawn(move || {
        let response = b"{}";
        let mut header = Vec::new();
        header.extend_from_slice(RESPONSE_MAGIC);
        header.extend_from_slice(&[2u8; FRAME_REQUEST_ID_BYTES]);
        header.extend_from_slice(&Sha256::digest(response));
        header.extend_from_slice(&(response.len() as u32).to_be_bytes());
        server.write_all(&header).unwrap();
        server.write_all(response).unwrap();
    });
    let error = read_response(&mut client, &expected_request_id).unwrap_err();
    assert_eq!(error.code, "native_client_response_binding_failed");
    assert!(!error.retryable_teardown);
}
#[cfg(unix)]
#[test]
fn rejects_response_digest_mismatch() {
    use std::io::Write as _;
    use std::os::unix::net::UnixStream;
    use std::thread;

    let (mut client, mut server) = UnixStream::pair().unwrap();
    let request_id = [3u8; FRAME_REQUEST_ID_BYTES];
    thread::spawn(move || {
        let response = b"{}";
        let mut header = Vec::new();
        header.extend_from_slice(RESPONSE_MAGIC);
        header.extend_from_slice(&request_id);
        header.extend_from_slice(&[0u8; FRAME_DIGEST_BYTES]);
        header.extend_from_slice(&(response.len() as u32).to_be_bytes());
        server.write_all(&header).unwrap();
        server.write_all(response).unwrap();
    });
    let error = read_response(&mut client, &request_id).unwrap_err();
    assert_eq!(error.code, "native_client_response_digest_mismatch");
    assert!(!error.retryable_teardown);
}

#[test]
fn response_teardown_after_flushed_request_is_never_retryable() {
    use std::io::{self, Read, Write};

    struct ResponseTeardownSocket {
        wrote_request: bool,
        flushed_request: bool,
    }

    impl Read for ResponseTeardownSocket {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            assert!(self.wrote_request);
            assert!(self.flushed_request);
            Err(io::Error::from(io::ErrorKind::ConnectionReset))
        }
    }

    impl Write for ResponseTeardownSocket {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.wrote_request = true;
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushed_request = true;
            Ok(())
        }
    }

    impl crate::ResidentStream for ResponseTeardownSocket {
        fn set_resident_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn set_resident_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn try_read_available(&mut self, _output: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    let mut client = ResponseTeardownSocket {
        wrote_request: false,
        flushed_request: false,
    };
    let request_id = write_request(
        &mut client,
        &[0u8; crate::AUTH_TOKEN_BYTES],
        &[0u8; AUTH_NONCE_BYTES],
        b"{}",
    )
    .unwrap();
    let error = read_committed_response(&mut client, &request_id).unwrap_err();
    assert_eq!(error.code, "native_client_frame_read_failed");
    assert!(!error.retryable_teardown);
}

#[cfg(unix)]
#[test]
fn closed_socket_during_auth_nonce_write_carries_teardown_evidence() {
    use std::io::{self, Read, Write};

    struct ClosedSocket;

    impl Read for ClosedSocket {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            unreachable!("the nonce write must fail before reading");
        }
    }

    impl Write for ClosedSocket {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl crate::ResidentStream for ClosedSocket {
        fn set_resident_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn set_resident_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn try_read_available(&mut self, _output: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    let mut client = ClosedSocket;
    let error = authenticate(
        &mut client,
        &[0u8; crate::AUTH_TOKEN_BYTES],
        Duration::from_millis(100),
    )
    .unwrap_err();
    assert_eq!(error.code, "native_client_auth_nonce_failed");
    assert!(error.retryable_teardown);
}

#[cfg(unix)]
#[test]
fn truncated_server_proof_is_never_retryable() {
    use std::io::{self, Read, Write};

    struct TruncatedProofSocket;

    impl Read for TruncatedProofSocket {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for TruncatedProofSocket {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl crate::ResidentStream for TruncatedProofSocket {
        fn set_resident_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn set_resident_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn try_read_available(&mut self, _output: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    let mut client = TruncatedProofSocket;
    let error = authenticate(
        &mut client,
        &[0u8; crate::AUTH_TOKEN_BYTES],
        Duration::from_millis(100),
    )
    .unwrap_err();
    assert_eq!(error.code, "native_client_frame_read_failed");
    assert!(!error.retryable_teardown);
}

#[test]
fn response_eof_and_reset_are_never_retryable() {
    for mut client in [
        TestStream::eof(),
        TestStream::read_error(io::ErrorKind::ConnectionReset),
    ] {
        let error = read_response(&mut client, &[0u8; FRAME_REQUEST_ID_BYTES]).unwrap_err();
        assert_eq!(error.code, "native_client_frame_read_failed");
        assert!(!error.retryable_teardown);
    }
}

#[test]
fn partial_or_flush_request_write_is_never_retryable() {
    for mut client in [
        TestStream::partial_write_error(io::ErrorKind::BrokenPipe),
        TestStream::flush_error(io::ErrorKind::ConnectionReset),
    ] {
        let error = write_request(
            &mut client,
            &[0u8; crate::AUTH_TOKEN_BYTES],
            &[0u8; AUTH_NONCE_BYTES],
            b"{}",
        )
        .unwrap_err();
        assert_eq!(error.code, "native_client_frame_write_failed");
        assert!(!error.retryable_teardown);
    }
}
