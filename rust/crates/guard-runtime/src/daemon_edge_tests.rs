use super::*;
use std::io::{Read, Write};

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn daemon_edge_parses_its_two_flags_in_either_order() {
    let expected = Some(EdgeArgs {
        upstream_port: 41234,
        parent_pid: 4321,
    });
    assert_eq!(
        parse_args(&args(&["--upstream-port", "41234", "--parent-pid", "4321"])),
        expected
    );
    assert_eq!(
        parse_args(&args(&["--parent-pid", "4321", "--upstream-port", "41234"])),
        expected
    );
}

#[test]
fn daemon_edge_refuses_malformed_flags() {
    for bad in [
        &["--upstream-port", "0", "--parent-pid", "4321"][..],
        &["--upstream-port", "41234", "--parent-pid", "1"],
        &["--upstream-port", "41234"],
        &["--upstream-port", "41234", "--parent-pid"],
        &[
            "--upstream-port",
            "1",
            "--upstream-port",
            "2",
            "--parent-pid",
            "9",
        ],
        &["--upstream-port", "1", "--parent-pid", "9", "--extra", "x"],
    ] {
        assert_eq!(parse_args(&args(bad)), None, "{bad:?}");
    }
}

#[test]
fn daemon_edge_only_relays_to_another_port_on_the_loopback_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let other = port.wrapping_add(1).max(1);
    assert_eq!(
        upstream_address(&listener, other),
        Some(SocketAddr::from(([127, 0, 0, 1], other)))
    );
    assert_eq!(upstream_address(&listener, port), None);
}

fn spawn_edge(upstream: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || serve(&listener, upstream, 4));
    address
}

#[test]
fn daemon_edge_relays_a_request_and_its_response() {
    let daemon = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = daemon.local_addr().unwrap();
    thread::spawn(move || {
        let (mut stream, _) = daemon.accept().unwrap();
        let mut request = Vec::new();
        (&stream).read_to_end(&mut request).unwrap();
        stream.write_all(b"answer:").unwrap();
        stream.write_all(&request).unwrap();
    });
    let edge = spawn_edge(upstream);
    let mut client = TcpStream::connect(edge).unwrap();
    client.write_all(b"GET /v1/health").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    assert_eq!(response, b"answer:GET /v1/health");
}

#[test]
fn daemon_edge_closes_the_client_when_the_daemon_finishes_first() {
    let daemon = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = daemon.local_addr().unwrap();
    thread::spawn(move || {
        let (mut stream, _) = daemon.accept().unwrap();
        let mut first = [0u8; 4];
        stream.read_exact(&mut first).unwrap();
        stream.write_all(b"done").unwrap();
    });
    let edge = spawn_edge(upstream);
    let mut client = TcpStream::connect(edge).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client.write_all(b"ping").unwrap();
    // The client never half-closes; the daemon closing must still end the
    // connection instead of leaving the relay waiting on the client.
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    assert_eq!(response, b"done");
}

#[test]
fn daemon_edge_closes_the_client_when_the_daemon_is_unreachable() {
    let unused = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = unused.local_addr().unwrap();
    drop(unused);
    let edge = spawn_edge(upstream);
    let mut client = TcpStream::connect(edge).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut response = Vec::new();
    let read = client.read_to_end(&mut response);
    assert!(read.is_err() || response.is_empty());
}

#[test]
fn daemon_edge_keeps_serving_more_connections_than_its_slot_limit() {
    let daemon = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = daemon.local_addr().unwrap();
    thread::spawn(move || {
        for stream in daemon.incoming() {
            let mut stream = stream.unwrap();
            thread::spawn(move || {
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).unwrap();
                stream.write_all(&byte).unwrap();
            });
        }
    });
    let edge = spawn_edge(upstream);
    for round in 0..12u8 {
        let mut client = TcpStream::connect(edge).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        client.write_all(&[round]).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, [round]);
    }
}
