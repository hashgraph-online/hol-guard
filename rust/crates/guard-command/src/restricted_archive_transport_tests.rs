//! Real socket/deadline regressions for the production acquisition transport.

use super::*;
use std::io::Write;
use std::net::TcpListener;
use std::sync::mpsc;

#[test]
fn stalled_dns_retains_admission_until_workers_exit() {
    let _test_lock = crate::restricted_archive::ARCHIVE_TEST_LOCK.lock().unwrap();
    let (release_a, wait_a) = mpsc::channel();
    let (release_b, wait_b) = mpsc::channel();
    let (completed, completion) = mpsc::channel();
    let completed_a = completed.clone();
    let error = resolve_system_with(Instant::now() + Duration::from_millis(20), move || {
        wait_a.recv().unwrap();
        completed_a.send(()).unwrap();
        Ok(Some(vec!["8.8.8.8".into()]))
    })
    .unwrap_err();
    assert_eq!(error.code, "external_archive_dns_timeout");
    let error = resolve_system_with(Instant::now() + Duration::from_millis(20), move || {
        wait_b.recv().unwrap();
        completed.send(()).unwrap();
        Ok(Some(vec!["8.8.8.8".into()]))
    })
    .unwrap_err();
    assert_eq!(error.code, "external_archive_dns_timeout");
    let third = resolve_system_with(Instant::now() + Duration::from_secs(1), || {
        panic!("capacity refusal must not start DNS")
    })
    .unwrap_err();
    assert_eq!(
        third.message,
        "External archive DNS resolver capacity is unavailable."
    );
    release_a.send(()).unwrap();
    release_b.send(()).unwrap();
    completion.recv_timeout(Duration::from_secs(1)).unwrap();
    completion.recv_timeout(Duration::from_secs(1)).unwrap();
    // Completion occurs just before slot Drop; wait for the workers to retire.
    let until = Instant::now() + Duration::from_secs(1);
    loop {
        if resolve_system_with(until, || Ok(Some(vec!["8.8.8.8".into()]))).is_ok() {
            break;
        }
        assert!(Instant::now() < until);
        std::thread::yield_now();
    }
}

#[test]
fn stalled_tls_uses_one_absolute_deadline() {
    let _test_lock = crate::restricted_archive::ARCHIVE_TEST_LOCK.lock().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (release, wait) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        wait.recv().unwrap();
        drop(stream);
    });
    let destination = crate::restricted_archive::canonical_destination(&format!(
        "https://packages.example.com:{port}/archive.tgz"
    ))
    .unwrap();
    let start = Instant::now();
    let result = UreqPinnedTransport.open_pinned_https_response(
        &destination,
        "127.0.0.1",
        start + Duration::from_millis(75),
    );
    release.send(()).unwrap();
    server.join().unwrap();
    let error = match result {
        Ok(_) => panic!("stalled TLS accepted"),
        Err(error) => error,
    };
    assert_eq!(error.code, "external_archive_download_timeout");
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn cleartext_peer_cannot_satisfy_https() {
    let _test_lock = crate::restricted_archive::ARCHIVE_TEST_LOCK.lock().unwrap();
    use std::io::Read;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (release, wait) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut client_hello = [0; 4096];
        assert!(stream.read(&mut client_hello).unwrap() > 0);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na")
            .unwrap();
        wait.recv().unwrap();
    });
    let destination = crate::restricted_archive::canonical_destination(&format!(
        "https://packages.example.com:{port}/archive.tgz"
    ))
    .unwrap();
    let result = UreqPinnedTransport.open_pinned_https_response(
        &destination,
        "127.0.0.1",
        Instant::now() + Duration::from_secs(1),
    );
    release.send(()).unwrap();
    server.join().unwrap();
    let error = match result {
        Ok(_) => panic!("cleartext accepted"),
        Err(error) => error,
    };
    assert_eq!(error.code, "external_archive_tls_error");
}

#[test]
fn empty_managed_trust_fails_before_connection() {
    let _test_lock = crate::restricted_archive::ARCHIVE_TEST_LOCK.lock().unwrap();
    let transport = ManagedUreqPinnedTransport {
        roots: Vec::new(),
        allow_public_registries: true,
    };
    let destination = crate::restricted_archive::canonical_destination(
        "https://packages.example.com/archive.tgz",
    )
    .unwrap();
    let result = transport.open_pinned_https_response(
        &destination,
        "127.0.0.1",
        Instant::now() + Duration::from_secs(1),
    );
    let error = match result {
        Ok(_) => panic!("empty trust accepted"),
        Err(error) => error,
    };
    assert_eq!(error.code, "external_archive_tls_error");
}
