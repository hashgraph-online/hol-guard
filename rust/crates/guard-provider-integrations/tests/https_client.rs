//! The HTTPS client against a real TLS endpoint (BP-T111).
//!
//! The provider host is a synthetic DNS name, so the exchange reaches the test server the way a
//! managed machine reaches a provider through its policy proxy: the policy names a proxy on this
//! machine, the client sends `CONNECT host:443`, and the server answers the tunnel with TLS under a
//! certificate the policy's trust roots pin. Nothing leaves the machine.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use guard_command::egress_caller::{EgressPolicy, EgressProxy, EgressTrust};
use guard_provider_integrations::client::{
    HttpProviderTransport, ProviderLimits, ProviderMethod, ProviderRequest, ProviderTransport,
};
use guard_provider_integrations::ProviderClientError;
use zeroize::Zeroizing;

const HOST: &str = "api.provider.exampleshield.test";
const KEY: &str = "example-provider-key";
const LIMITS: ProviderLimits = ProviderLimits {
    timeout_ms: 2000,
    max_response_bytes: 4096,
};

/// One scripted answer: the bytes to write and how long to stall between head and body.
struct Reply {
    bytes: Vec<u8>,
    stall: Duration,
}

fn reply(status: &str, headers: &str, body: &str) -> Reply {
    Reply {
        bytes: format!(
            "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n{headers}\r\n{body}",
            body.len()
        )
        .into_bytes(),
        stall: Duration::ZERO,
    }
}

struct Server {
    port: u16,
    certificate: Vec<u8>,
    exchanges: JoinHandle<Vec<String>>,
}

fn read_head(stream: &mut impl Read) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while head.len() < 32 * 1024 && !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return None,
        }
    }
    String::from_utf8(head).ok()
}

fn content_length(head: &str) -> usize {
    head.lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse().ok())
        .unwrap_or(0)
}

/// A proxy that tunnels every `CONNECT` into a TLS server for `certificate_host`. It answers one
/// reply per connection and returns, per exchange, the `CONNECT` head and the request head.
fn server(certificate_host: &str, replies: Vec<Reply>) -> Server {
    let certified = rcgen::generate_simple_self_signed(vec![certificate_host.to_owned()]).unwrap();
    let certificate = certified.cert.der().to_vec();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key.into())
        .unwrap(),
    );
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let exchanges = std::thread::spawn(move || {
        let mut exchanges = Vec::new();
        for reply in replies {
            let Ok((mut socket, _)) = listener.accept() else {
                break;
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(8)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(8)))
                .unwrap();
            let Some(connect) = read_head(&mut socket) else {
                continue;
            };
            let _ = socket.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
            let connection = rustls::ServerConnection::new(config.clone()).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, socket);
            let Some(request) = read_head(&mut stream) else {
                exchanges.push(connect);
                continue;
            };
            let mut body = vec![0; content_length(&request)];
            let _ = stream.read_exact(&mut body);
            exchanges.push(format!(
                "{connect}{request}{}",
                String::from_utf8_lossy(&body)
            ));
            let split = reply
                .bytes
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
                .map_or(reply.bytes.len(), |index| index + 4);
            let _ = stream.write_all(&reply.bytes[..split]);
            let _ = stream.flush();
            std::thread::sleep(reply.stall);
            let _ = stream.write_all(&reply.bytes[split..]);
            let _ = stream.flush();
            stream.conn.send_close_notify();
            let _ = stream.flush();
        }
        exchanges
    });
    Server {
        port,
        certificate,
        exchanges,
    }
}

/// A managed policy that sends every exchange through the test proxy and trusts only `roots`.
struct TestPolicy {
    proxy_port: u16,
    roots: Vec<Vec<u8>>,
    refuse: bool,
}

impl EgressPolicy for TestPolicy {
    fn validate(&self, _url: &str) -> Result<(), String> {
        if self.refuse {
            Err("destination_refused".to_owned())
        } else {
            Ok(())
        }
    }

    fn proxy(&self, _url: &str) -> EgressProxy {
        EgressProxy::Url {
            url: format!("http://127.0.0.1:{}", self.proxy_port),
            credentials: None,
        }
    }

    fn trust(&self) -> EgressTrust {
        EgressTrust::Roots(Arc::new(
            self.roots
                .iter()
                .map(|der| ureq::tls::Certificate::from_der(der).to_owned())
                .collect(),
        ))
    }
}

fn policy(server: &Server) -> TestPolicy {
    TestPolicy {
        proxy_port: server.port,
        roots: vec![server.certificate.clone()],
        refuse: false,
    }
}

fn request(host: &str) -> ProviderRequest {
    ProviderRequest {
        method: ProviderMethod::Post,
        host: host.to_owned(),
        path: "/v1/check".to_owned(),
        header: "x-api-key".to_owned(),
        key: Zeroizing::new(KEY.to_owned()),
        body: Some(r#"{"target":"https://shop.example.test/basket"}"#.to_owned()),
    }
}

fn send(policy: &TestPolicy, request: &ProviderRequest) -> Result<Vec<u8>, ProviderClientError> {
    HttpProviderTransport::new(vec![HOST.to_owned()], policy)
        .send(request, LIMITS)
        .map(|response| {
            assert_eq!(response.status, 200);
            response.body
        })
}

#[test]
fn a_pinned_host_is_reached_over_tls_with_the_declared_request() {
    let server = server(HOST, vec![reply("200 OK", "", r#"{"verdict":"clean"}"#)]);
    let body = send(&policy(&server), &request(HOST)).unwrap();
    assert_eq!(body, br#"{"verdict":"clean"}"#);
    let exchanges = server.exchanges.join().unwrap();
    assert_eq!(exchanges.len(), 1);
    let exchange = exchanges[0].to_ascii_lowercase();
    assert!(
        exchange.starts_with(&format!("connect {HOST}:443 ")),
        "{exchange}"
    );
    assert!(exchange.contains("post /v1/check http/1.1"), "{exchange}");
    assert!(exchange.contains("content-type: application/json"));
    assert!(exchange.contains("accept: application/json"));
    assert!(exchange.contains(&format!("x-api-key: {KEY}")));
    assert!(exchange.ends_with(r#"{"target":"https://shop.example.test/basket"}"#));
}

#[test]
fn a_redirect_is_refused_and_never_followed() {
    let server = server(
        HOST,
        vec![
            reply(
                "302 Found",
                &format!("location: https://{HOST}/v1/elsewhere\r\n"),
                "",
            ),
            reply("200 OK", "", "{}"),
        ],
    );
    let answer = send(&policy(&server), &request(HOST));
    assert_eq!(answer, Err(ProviderClientError::Transport));
    // Release the second scripted connection so the server thread ends.
    let _ = std::net::TcpStream::connect(("127.0.0.1", server.port));
    let exchanges = server.exchanges.join().unwrap();
    assert!(exchanges[0].contains("/v1/check"));
    assert!(exchanges
        .iter()
        .all(|exchange| !exchange.contains("/v1/elsewhere")));
}

#[test]
fn a_host_off_the_pin_list_and_a_refused_destination_never_connect() {
    let server = server(HOST, Vec::new());
    assert_eq!(
        send(&policy(&server), &request("other.exampleshield.test")),
        Err(ProviderClientError::HostNotPinned)
    );
    let mut refusing = policy(&server);
    refusing.refuse = true;
    assert_eq!(
        send(&refusing, &request(HOST)),
        Err(ProviderClientError::Blocked)
    );
    assert!(server.exchanges.join().unwrap().is_empty());
}

#[test]
fn an_oversize_body_is_refused() {
    let big = "x".repeat(LIMITS.max_response_bytes as usize + 1);
    let server = server(HOST, vec![reply("200 OK", "", &big)]);
    assert_eq!(
        send(&policy(&server), &request(HOST)),
        Err(ProviderClientError::ResponseTooLarge)
    );
    server.exchanges.join().unwrap();
}

#[test]
fn a_slow_body_runs_into_the_deadline() {
    let mut slow = reply("200 OK", "", r#"{"verdict":"clean"}"#);
    slow.stall = Duration::from_millis(6000);
    let server = server(HOST, vec![slow]);
    let started = Instant::now();
    assert_eq!(
        send(&policy(&server), &request(HOST)),
        Err(ProviderClientError::Timeout)
    );
    assert!(started.elapsed() < Duration::from_millis(5000));
    server.exchanges.join().unwrap();
}

#[test]
fn a_certificate_for_another_host_or_an_untrusted_one_fails_tls() {
    let server = server("other.exampleshield.test", vec![reply("200 OK", "", "{}")]);
    assert_eq!(
        send(&policy(&server), &request(HOST)),
        Err(ProviderClientError::Transport)
    );
    server.exchanges.join().unwrap();

    let server = self::server(HOST, vec![reply("200 OK", "", "{}")]);
    let stranger = rcgen::generate_simple_self_signed(vec![HOST.to_owned()]).unwrap();
    let mut untrusted = policy(&server);
    untrusted.roots = vec![stranger.cert.der().to_vec()];
    assert_eq!(
        send(&untrusted, &request(HOST)),
        Err(ProviderClientError::Transport)
    );
    server.exchanges.join().unwrap();
}
