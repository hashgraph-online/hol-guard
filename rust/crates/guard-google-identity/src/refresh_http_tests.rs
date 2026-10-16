use super::*;
use crate::oauth::worker_input_tests::credential;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, LazyBuffers, NextTimeout, Transport,
};

// In-memory HTTP framing tests: no sockets, DNS, TLS handshake, or provider calls.
#[derive(Debug, Default)]
pub(crate) struct Wire {
    replies: VecDeque<Vec<u8>>,
    pub(crate) requests: Vec<Vec<u8>>,
    pub(crate) urls: Vec<String>,
}
#[derive(Debug)]
struct MemoryConnector(Arc<Mutex<Wire>>);
#[derive(Debug)]
struct MemoryResolver;
impl Resolver for MemoryResolver {
    fn resolve(
        &self,
        _: &oauth2::http::Uri,
        _: &ureq::config::Config,
        _: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let mut addresses = self.empty();
        addresses.push("192.0.2.1:443".parse().unwrap());
        Ok(addresses)
    }
}
impl Connector for MemoryConnector {
    type Out = MemoryTransport;
    fn connect(
        &self,
        details: &ConnectionDetails,
        _: Option<()>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        let mut wire = self.0.lock().unwrap();
        wire.urls.push(details.uri.to_string());
        wire.requests.push(Vec::new());
        let index = wire.requests.len() - 1;
        let reply = wire.replies.pop_front().expect("unexpected HTTP request");
        Ok(Some(MemoryTransport {
            wire: self.0.clone(),
            index,
            reply,
            offset: 0,
            buffers: LazyBuffers::new(
                details.config.input_buffer_size(),
                details.config.output_buffer_size(),
            ),
        }))
    }
}
#[derive(Debug)]
struct MemoryTransport {
    wire: Arc<Mutex<Wire>>,
    index: usize,
    reply: Vec<u8>,
    offset: usize,
    buffers: LazyBuffers,
}
impl Transport for MemoryTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }
    fn transmit_output(&mut self, amount: usize, _: NextTimeout) -> Result<(), ureq::Error> {
        self.wire.lock().unwrap().requests[self.index]
            .extend_from_slice(&self.buffers.output()[..amount]);
        Ok(())
    }
    fn await_input(&mut self, _: NextTimeout) -> Result<bool, ureq::Error> {
        let target = self.buffers.input_append_buf();
        let count = target.len().min(self.reply.len() - self.offset);
        target[..count].copy_from_slice(&self.reply[self.offset..self.offset + count]);
        self.offset += count;
        self.buffers.input_appended(count);
        Ok(count > 0)
    }
    fn is_open(&mut self) -> bool {
        self.offset < self.reply.len()
    }
    fn is_tls(&self) -> bool {
        true
    }
}
pub(crate) fn response(status: u16, media: &str, body: &str) -> Vec<u8> {
    format!("HTTP/1.1 {status} Test\r\nContent-Type: {media}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).into_bytes()
}
fn token() -> String {
    serde_json::json!({"access_token":"synthetic-renewed-access", "token_type":"Bearer", "expires_in":3600}).to_string()
}
fn redirect() -> Vec<u8> {
    b"HTTP/1.1 302 Found\r\nLocation: https://untrusted.example/token\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
}
fn userinfo() -> String {
    serde_json::json!({"sub":"subject-one", "hd":"work.example", "email":"sender@work.example", "email_verified":true}).to_string()
}
pub(crate) fn agent(replies: Vec<Vec<u8>>) -> (ureq::Agent, Arc<Mutex<Wire>>) {
    let wire = Arc::new(Mutex::new(Wire {
        replies: replies.into(),
        ..Wire::default()
    }));
    let agent = ureq::Agent::with_parts(
        token_agent().config().clone(),
        MemoryConnector(wire.clone()),
        MemoryResolver,
    );
    (agent, wire)
}

#[test]
fn registered_refresh_uses_fixed_endpoints_form_and_fresh_bearer() {
    let original = credential("subject-one");
    let registration = original.refresh_registration.as_ref().unwrap();
    let (agent, wire) = agent(vec![
        response(200, "application/json", &token()),
        response(200, "application/json", &userinfo()),
    ]);
    let renewed = original.refresh_registered_with_agent(&agent).unwrap();
    assert!(renewed.is_current());
    let wire = wire.lock().unwrap();
    assert_eq!(wire.urls, [TOKEN_URL, USERINFO_URL]);
    assert_eq!(wire.requests.len(), 2);
    let post = std::str::from_utf8(&wire.requests[0]).unwrap();
    let (headers, body) = post.split_once("\r\n\r\n").unwrap();
    assert!(headers.starts_with("POST /token HTTP/1.1\r\n"));
    let headers = headers.to_ascii_lowercase();
    assert!(headers.contains("host: oauth2.googleapis.com\r\n"));
    assert!(headers.contains("content-type: application/x-www-form-urlencoded\r\n"));
    let fields: std::collections::BTreeMap<_, _> =
        oauth2::url::form_urlencoded::parse(body.as_bytes()).collect();
    assert_eq!(fields.len(), 4);
    assert_eq!(fields["grant_type"], "refresh_token");
    assert_eq!(fields["client_id"], registration.client_id);
    assert_eq!(fields["client_secret"], registration.client_secret.as_str());
    assert_eq!(
        fields["refresh_token"],
        original.refresh_token.as_ref().unwrap().as_str()
    );
    let get = std::str::from_utf8(&wire.requests[1])
        .unwrap()
        .to_ascii_lowercase();
    assert!(get.starts_with(
        "GET /v1/userinfo HTTP/1.1\r\n"
            .to_ascii_lowercase()
            .as_str()
    ));
    assert!(get.contains("host: openidconnect.googleapis.com\r\n"));
    assert!(get.contains("authorization: bearer synthetic-renewed-access\r\n"));
    assert!(get.contains("accept: application/json\r\n"));
    assert!(!get.contains(registration.client_secret.as_str()));
    let config = agent.config();
    assert!(config.https_only() && config.proxy().is_none());
    assert_eq!(config.max_redirects(), 0);
    assert_eq!(config.timeouts().global, Some(Duration::from_secs(5)));
}

#[test]
fn valid_json_at_each_response_limit_is_accepted() {
    let token = token();
    let info = userinfo();
    let token_at_limit = format!("{token}{}", " ".repeat(64 * 1024 - token.len()));
    let info_at_limit = format!("{info}{}", " ".repeat(16 * 1024 - info.len()));
    let (agent, wire) = agent(vec![
        response(200, "application/json", &token_at_limit),
        response(200, "application/json", &info_at_limit),
    ]);
    assert!(credential("subject-one")
        .refresh_registered_with_agent(&agent)
        .unwrap()
        .is_current());
    assert_eq!(wire.lock().unwrap().requests.len(), 2);
}

#[test]
fn token_transport_errors_media_and_size_limits_stop_before_userinfo() {
    for reply in [
        response(401, "application/json", "{}"),
        response(503, "application/json", "{}"),
        redirect(),
        response(200, "text/plain", &token()),
        response(
            200,
            "application/json",
            &format!("{}{}", token(), " ".repeat(64 * 1024)),
        ),
        b"invalid HTTP framing\r\n\r\n".to_vec(),
    ] {
        let (agent, wire) = agent(vec![reply]);
        assert!(credential("subject-one")
            .refresh_registered_with_agent(&agent)
            .is_err());
        assert_eq!(wire.lock().unwrap().requests.len(), 1);
    }
}

#[test]
fn userinfo_transport_errors_media_and_size_limits_never_authorize() {
    for reply in [
        response(401, "application/json", "{}"),
        response(503, "application/json", "{}"),
        redirect(),
        response(200, "text/plain", &userinfo()),
        response(
            200,
            "application/json",
            &format!("{}{}", userinfo(), " ".repeat(16 * 1024)),
        ),
        b"invalid HTTP framing\r\n\r\n".to_vec(),
    ] {
        let (agent, wire) = agent(vec![response(200, "application/json", &token()), reply]);
        assert!(credential("subject-one")
            .refresh_registered_with_agent(&agent)
            .is_err());
        assert_eq!(wire.lock().unwrap().requests.len(), 2);
    }
}
