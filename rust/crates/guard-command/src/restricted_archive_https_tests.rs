//! Synthetic HTTPS proof using the production peer and TLS transport.
//! The loopback routing seam exists only in this test module; production
//! acquisition still rejects every non-public destination before connecting.

use super::*;
use crate::restricted_archive::{
    download_restricted_archive, DnsResolver, RestrictedArchiveDownloadResult,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

fn server(
    host: &str,
    replies: Vec<Vec<u8>>,
) -> (u16, Vec<u8>, std::thread::JoinHandle<Vec<Vec<u8>>>) {
    delayed_server(host, replies, Duration::ZERO, false)
}

fn delayed_server(
    host: &str,
    replies: Vec<Vec<u8>>,
    delay: Duration,
    body_delay: bool,
) -> (u16, Vec<u8>, std::thread::JoinHandle<Vec<Vec<u8>>>) {
    let certified = rcgen::generate_simple_self_signed(vec![host.to_owned()]).unwrap();
    let der = certified.cert.der().to_vec();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certified.cert.der().clone()], key.into())
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for reply in replies {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let connection = rustls::ServerConnection::new(Arc::new(config.clone())).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, socket);
            let mut request = Vec::new();
            let mut byte = [0; 1];
            while request.len() < 32 * 1024 && !request.ends_with(b"\r\n\r\n") {
                match stream.read(&mut byte) {
                    Ok(1) => request.push(byte[0]),
                    _ => break,
                }
            }
            if request.ends_with(b"\r\n\r\n") {
                requests.push(request);
                if body_delay {
                    let split = reply
                        .windows(4)
                        .position(|bytes| bytes == b"\r\n\r\n")
                        .unwrap()
                        + 4;
                    let _ = stream.write_all(&reply[..split]);
                    let _ = stream.flush();
                    std::thread::sleep(delay);
                    let _ = stream.write_all(&reply[split..]);
                    let _ = stream.flush();
                    continue;
                }
                std::thread::sleep(delay);
                // Body-limit failures may close before the synthetic server flushes.
                let _ = stream.write_all(&reply);
                let _ = stream.flush();
            }
        }
        requests
    });
    (port, der, handle)
}

struct PublicDns;
impl DnsResolver for PublicDns {
    fn getaddrinfo(&self, _: &str) -> Result<Option<Vec<String>>, String> {
        Ok(Some(vec!["8.8.8.8".into()]))
    }
}

struct TestRouting(ManagedUreqPinnedTransport);
impl PinnedHttpsTransport for TestRouting {
    fn validate_destination(
        &self,
        destination: &CanonicalDestination,
    ) -> Result<(), RestrictedDownloadError> {
        self.0.validate_destination(destination)
    }
    fn open_pinned_https_response(
        &self,
        destination: &CanonicalDestination,
        address: &str,
        deadline: Instant,
    ) -> Result<Box<dyn ReadableResponse>, RestrictedDownloadError> {
        assert_eq!(address, "8.8.8.8");
        self.0
            .open_pinned_https_response(destination, "127.0.0.1", deadline)
    }
}

#[test]
fn managed_https_redirects_preserve_signed_query_and_request_headers() {
    let _test_lock = crate::restricted_archive::ARCHIVE_TEST_LOCK.lock().unwrap();
    let (port, root, server) = server("packages.example.com", vec![
        b"HTTP/1.1 302 Found\r\nLocation: ../next.tgz?signature=a%2Fb&expires=1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n".to_vec(),
    ]);
    let url = format!("https://packages.example.com:{port}/dir/archive.tgz?token=a%2Fb");
    let result = download_restricted_archive(
        &url,
        16,
        4,
        1.0,
        None,
        &PublicDns,
        &TestRouting(ManagedUreqPinnedTransport {
            roots: vec![root],
            allow_public_registries: true,
        }),
    );
    let requests = server.join().unwrap();
    let download = match result {
        RestrictedArchiveDownloadResult::Success(value) => value,
        RestrictedArchiveDownloadResult::Failure(error) => panic!("{error:?}"),
    };
    assert_eq!(download.size, 7);
    assert_eq!(std::fs::read(&download.path).unwrap(), b"abcdefg");
    assert_eq!(
        download.final_url,
        format!("https://packages.example.com:{port}/next.tgz?signature=a%2Fb&expires=1")
    );
    download.cleanup();
    assert_eq!(requests.len(), 2);
    for request in requests {
        let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
        assert!(request.contains("accept-encoding: identity\r\n"));
        assert!(request.contains("accept: application/octet-stream\r\n"));
        assert!(request.contains("user-agent: hol-guard-restricted-archive/1\r\n"));
        assert!(!request.contains("authorization:"));
        assert!(!request.contains("cookie:"));
    }
}

#[test]
fn trusted_certificate_for_another_hostname_is_refused_before_http() {
    let _test_lock = crate::restricted_archive::ARCHIVE_TEST_LOCK.lock().unwrap();
    let (port, root, server) = server(
        "other.example.com",
        vec![b"HTTP/1.1 200 OK\r\n\r\n".to_vec()],
    );
    let destination = crate::restricted_archive::canonical_destination(&format!(
        "https://packages.example.com:{port}/archive.tgz"
    ))
    .unwrap();
    let result = ManagedUreqPinnedTransport {
        roots: vec![root],
        allow_public_registries: true,
    }
    .open_pinned_https_response(
        &destination,
        "127.0.0.1",
        Instant::now() + Duration::from_secs(1),
    );
    assert!(server.join().unwrap().is_empty());
    let error = match result {
        Ok(_) => panic!("wrong hostname accepted"),
        Err(error) => error,
    };
    assert_eq!(error.code, "external_archive_tls_error");
}

#[test]
fn untrusted_certificate_is_refused_before_http() {
    let _test_lock = crate::restricted_archive::ARCHIVE_TEST_LOCK.lock().unwrap();
    let (port, _, server) = server(
        "packages.example.com",
        vec![b"HTTP/1.1 200 OK\r\n\r\n".to_vec()],
    );
    let other = rcgen::generate_simple_self_signed(vec!["packages.example.com".into()]).unwrap();
    let destination = crate::restricted_archive::canonical_destination(&format!(
        "https://packages.example.com:{port}/archive.tgz"
    ))
    .unwrap();
    let result = ManagedUreqPinnedTransport {
        allow_public_registries: true,
        roots: vec![other.cert.der().to_vec()],
    }
    .open_pinned_https_response(
        &destination,
        "127.0.0.1",
        Instant::now() + Duration::from_secs(1),
    );
    assert!(server.join().unwrap().is_empty());
    let error = match result {
        Ok(_) => panic!("untrusted certificate accepted"),
        Err(error) => error,
    };
    assert_eq!(error.code, "external_archive_tls_error");
}

#[test]
fn real_https_unknown_length_body_is_bounded() {
    let _test_lock = crate::restricted_archive::ARCHIVE_TEST_LOCK.lock().unwrap();
    let (port, root, server) = server(
        "packages.example.com",
        vec![b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n1234".to_vec()],
    );
    let url = format!("https://packages.example.com:{port}/archive.tgz");
    let result = download_restricted_archive(
        &url,
        3,
        4,
        1.0,
        None,
        &PublicDns,
        &TestRouting(ManagedUreqPinnedTransport {
            roots: vec![root],
            allow_public_registries: true,
        }),
    );
    server.join().unwrap();
    let error = match result {
        RestrictedArchiveDownloadResult::Success(value) => {
            value.cleanup();
            panic!("overflow accepted")
        }
        RestrictedArchiveDownloadResult::Failure(error) => error,
    };
    assert_eq!(error.code, "external_archive_download_size_limit");
}

#[test]
fn real_https_headers_and_body_share_one_absolute_deadline() {
    let _test_lock = crate::restricted_archive::ARCHIVE_TEST_LOCK.lock().unwrap();
    for body_delay in [false, true] {
        let (port, root, server) = delayed_server(
            "packages.example.com",
            vec![b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\na".to_vec()],
            Duration::from_millis(200),
            body_delay,
        );
        let url = format!("https://packages.example.com:{port}/archive.tgz");
        let start = Instant::now();
        let result = download_restricted_archive(
            &url,
            3,
            4,
            0.075,
            None,
            &PublicDns,
            &TestRouting(ManagedUreqPinnedTransport {
                roots: vec![root],
                allow_public_registries: true,
            }),
        );
        assert!(start.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
        let error = match result {
            RestrictedArchiveDownloadResult::Success(value) => {
                value.cleanup();
                panic!("late body accepted")
            }
            RestrictedArchiveDownloadResult::Failure(error) => error,
        };
        assert_eq!(
            error.code, "external_archive_download_timeout",
            "body_delay={body_delay}"
        );
    }
}

#[test]
fn managed_registry_redirect_is_refused_before_second_dns_or_tls() {
    let _test_lock = crate::restricted_archive::ARCHIVE_TEST_LOCK.lock().unwrap();
    struct CountingDns(std::sync::atomic::AtomicUsize);
    impl DnsResolver for CountingDns {
        fn getaddrinfo(&self, _: &str) -> Result<Option<Vec<String>>, String> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Some(vec!["8.8.8.8".into()]))
        }
    }
    let dns = CountingDns(std::sync::atomic::AtomicUsize::new(0));
    let (port, root, server) = server("packages.example.com", vec![
        b"HTTP/1.1 302 Found\r\nLocation: https://files.pythonhosted.org/a.tgz\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
    ]);
    let result = download_restricted_archive(
        &format!("https://packages.example.com:{port}/a.tgz"),
        16,
        4,
        1.0,
        None,
        &dns,
        &TestRouting(ManagedUreqPinnedTransport {
            roots: vec![root],
            allow_public_registries: false,
        }),
    );
    assert!(
        matches!(result, RestrictedArchiveDownloadResult::Failure(error)
        if error.code == "managed_public_registry_disabled")
    );
    assert_eq!(server.join().unwrap().len(), 1);
    assert_eq!(dns.0.load(std::sync::atomic::Ordering::SeqCst), 1);
}
