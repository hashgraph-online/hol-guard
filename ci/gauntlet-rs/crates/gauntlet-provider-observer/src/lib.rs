//! Read-only HTTP metadata from the two fixed local-model endpoints.
//!
//! This crate can open sockets, unlike `gauntlet-evidence`. A successful read
//! is an operational observation, not a provider attestation or permission to
//! make an inference request.

use gauntlet_contracts::canonicalize;
use gauntlet_evidence::{
    model_endpoint, verify_advertised_model, verify_provider_status, ModelEndpoint,
};
use serde_json::{json, Value};
use std::fmt;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};

const MAX_BODY: usize = 65_536;
const MAX_HEADERS: usize = 8_192;
const MAX_CHUNKS: usize = 2_048;
const FIXED_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 5, 2);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_DEADLINE: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum ObserverError {
    InvalidPins,
    Unavailable(String),
    InvalidHttp(&'static str),
    InvalidJson,
    InvalidProvider(String),
}

impl fmt::Display for ObserverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPins => {
                f.write_str("exact outside provider route and model pins required")
            }
            Self::Unavailable(error) => write!(f, "local provider metadata unavailable: {error}"),
            Self::InvalidHttp(error) => write!(f, "invalid local provider HTTP response: {error}"),
            Self::InvalidJson => f.write_str("invalid bounded local provider JSON"),
            Self::InvalidProvider(error) => write!(f, "local provider metadata refused: {error}"),
        }
    }
}

impl std::error::Error for ObserverError {}

type Result<T> = std::result::Result<T, ObserverError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetadataPath {
    Models,
    Quota,
}

impl MetadataPath {
    fn as_str(self) -> &'static str {
        match self {
            Self::Models => "/v1/models",
            Self::Quota => "/v1/benchmark-quota",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderObservation {
    pub route: ModelEndpoint,
    pub models: Value,
    pub status: Value,
    pub quota: Value,
}

impl ProviderObservation {
    /// The snapshot is diagnostic. It never represents authenticated usage or
    /// a qualifying benchmark result.
    pub fn to_json(&self) -> Value {
        json!({
            "route": self.route.to_json(),
            "models": self.models,
            "status": self.status,
            "qualification_eligible": false,
        })
    }
}

struct DeadlineStream {
    stream: TcpStream,
    deadline: Instant,
}

impl DeadlineStream {
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "provider deadline"))
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.remaining()?;
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(buffer)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let remaining = self.remaining()?;
        self.stream.set_write_timeout(Some(remaining))?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

fn read_line<R: Read>(reader: &mut R, remaining: &mut usize) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        if *remaining == 0 {
            return Err(ObserverError::InvalidHttp("header bound exceeded"));
        }
        let mut byte = [0u8; 1];
        reader
            .read_exact(&mut byte)
            .map_err(|error| ObserverError::Unavailable(error.to_string()))?;
        *remaining -= 1;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return Ok(line);
        }
        if byte[0] == b'\n' {
            return Err(ObserverError::InvalidHttp("bare newline"));
        }
    }
}

fn parse_headers<R: Read>(reader: &mut R) -> Result<(Option<usize>, bool)> {
    let mut remaining = MAX_HEADERS;
    let status = read_line(reader, &mut remaining)?;
    let status =
        std::str::from_utf8(&status).map_err(|_| ObserverError::InvalidHttp("non-ASCII status"))?;
    let mut words = status.split_whitespace();
    if !matches!(words.next(), Some("HTTP/1.0" | "HTTP/1.1")) || words.next() != Some("200") {
        return Err(ObserverError::InvalidHttp("status is not HTTP 200"));
    }
    let mut length = None;
    let mut chunked = false;
    loop {
        let line = read_line(reader, &mut remaining)?;
        if line.is_empty() {
            break;
        }
        let line = std::str::from_utf8(&line)
            .map_err(|_| ObserverError::InvalidHttp("non-ASCII header"))?;
        let (name, value) = line
            .split_once(':')
            .ok_or(ObserverError::InvalidHttp("malformed header"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || value.bytes().any(|byte| byte < 0x20 && byte != b'\t')
        {
            return Err(ObserverError::InvalidHttp("malformed header"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() || !value.trim().bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(ObserverError::InvalidHttp("invalid content length"));
            }
            let parsed = value
                .trim()
                .parse::<usize>()
                .map_err(|_| ObserverError::InvalidHttp("invalid content length"))?;
            if parsed > MAX_BODY {
                return Err(ObserverError::InvalidHttp("body bound exceeded"));
            }
            length = Some(parsed);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.trim().eq_ignore_ascii_case("chunked") {
                return Err(ObserverError::InvalidHttp("unsupported transfer encoding"));
            }
            chunked = true;
        }
    }
    if length.is_some() && chunked {
        return Err(ObserverError::InvalidHttp("ambiguous body framing"));
    }
    Ok((length, chunked))
}

fn read_chunked<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut framing_remaining = MAX_HEADERS;
    for _ in 0..MAX_CHUNKS {
        let line = read_line(reader, &mut framing_remaining)?;
        let line = std::str::from_utf8(&line)
            .map_err(|_| ObserverError::InvalidHttp("invalid chunk size"))?;
        let size = line.split(';').next().unwrap_or("");
        if size.is_empty() || !size.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ObserverError::InvalidHttp("invalid chunk size"));
        }
        let size = usize::from_str_radix(size, 16)
            .map_err(|_| ObserverError::InvalidHttp("invalid chunk size"))?;
        if size == 0 {
            loop {
                let trailer = read_line(reader, &mut framing_remaining)?;
                if trailer.is_empty() {
                    return Ok(body);
                }
                if !trailer.contains(&b':') {
                    return Err(ObserverError::InvalidHttp("malformed trailer"));
                }
            }
        }
        if size > MAX_BODY - body.len() {
            return Err(ObserverError::InvalidHttp("body bound exceeded"));
        }
        let start = body.len();
        body.resize(start + size, 0);
        reader
            .read_exact(&mut body[start..])
            .map_err(|error| ObserverError::Unavailable(error.to_string()))?;
        let mut ending = [0u8; 2];
        reader
            .read_exact(&mut ending)
            .map_err(|error| ObserverError::Unavailable(error.to_string()))?;
        if ending != *b"\r\n" {
            return Err(ObserverError::InvalidHttp("chunk lacks CRLF"));
        }
    }
    Err(ObserverError::InvalidHttp("chunk count exceeded"))
}

fn read_bounded_response<R: Read>(reader: &mut R) -> Result<Value> {
    let (length, chunked) = parse_headers(reader)?;
    let body = if chunked {
        read_chunked(reader)?
    } else if let Some(length) = length {
        let mut body = vec![0u8; length];
        reader
            .read_exact(&mut body)
            .map_err(|error| ObserverError::Unavailable(error.to_string()))?;
        body
    } else {
        let mut body = Vec::new();
        reader
            .take((MAX_BODY + 1) as u64)
            .read_to_end(&mut body)
            .map_err(|error| ObserverError::Unavailable(error.to_string()))?;
        if body.len() > MAX_BODY {
            return Err(ObserverError::InvalidHttp("body bound exceeded"));
        }
        body
    };
    let canonical = canonicalize(&body).map_err(|_| ObserverError::InvalidJson)?;
    serde_json::from_slice(&canonical).map_err(|_| ObserverError::InvalidJson)
}

fn exchange<S: Read + Write>(stream: &mut S, port: u16, path: MetadataPath) -> Result<Value> {
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: 192.168.5.2:{port}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        path.as_str()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| ObserverError::Unavailable(error.to_string()))?;
    read_bounded_response(stream)
}

fn fetch(endpoint: &ModelEndpoint, path: MetadataPath) -> Result<Value> {
    let address = SocketAddr::V4(SocketAddrV4::new(FIXED_IP, endpoint.port));
    let stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)
        .map_err(|error| ObserverError::Unavailable(error.to_string()))?;
    let mut stream = DeadlineStream {
        stream,
        deadline: Instant::now() + IO_DEADLINE,
    };
    exchange(&mut stream, endpoint.port, path)
}

fn validate_observation(
    route: ModelEndpoint,
    models: Value,
    status: Value,
    model_id: &str,
    provider_pins: &Value,
) -> Result<ProviderObservation> {
    verify_advertised_model(&models, model_id)
        .map_err(|error| ObserverError::InvalidProvider(error.to_string()))?;
    let quota = verify_provider_status(&status, provider_pins)
        .map_err(|error| ObserverError::InvalidProvider(error.to_string()))?;
    Ok(ProviderObservation {
        route,
        models,
        status,
        quota,
    })
}

/// Query only `/v1/models` and `/v1/benchmark-quota` at the pinned Lima host.
/// The caller must supply the expected model ID and provider pins from outside
/// the HTTP response. Neither the response nor this function grants inference.
pub fn observe_provider_metadata(
    base_url: &str,
    model_id: &str,
    provider_pins: &Value,
) -> Result<ProviderObservation> {
    let route = model_endpoint(base_url).map_err(|_| ObserverError::InvalidPins)?;
    if model_id.is_empty() || model_id.len() > 256 {
        return Err(ObserverError::InvalidPins);
    }
    let models = fetch(&route, MetadataPath::Models)?;
    let status = fetch(&route, MetadataPath::Quota)?;
    validate_observation(route, models, status, model_id, provider_pins)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct Stub {
        response: Cursor<Vec<u8>>,
        request: Vec<u8>,
    }

    impl Stub {
        fn new(response: &[u8]) -> Self {
            Self {
                response: Cursor::new(response.to_vec()),
                request: Vec::new(),
            }
        }
    }

    impl Read for Stub {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.response.read(buf)
        }
    }

    impl Write for Stub {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.request.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn fixed_gets_accept_length_chunked_and_close_framing() {
        let cases: &[(&[u8], MetadataPath)] = &[
            (b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"data\":[]}", MetadataPath::Models),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nb\r\n{\"data\":[]}\r\n0\r\n\r\n", MetadataPath::Models),
            (b"HTTP/1.0 200 OK\r\n\r\n{\"data\":[]}", MetadataPath::Quota),
        ];
        for (response, path) in cases {
            let mut stub = Stub::new(response);
            assert_eq!(
                exchange(&mut stub, 8001, *path).unwrap(),
                json!({"data":[]})
            );
            assert_eq!(
                std::str::from_utf8(&stub.request).unwrap(),
                format!(
                    "GET {} HTTP/1.1\r\nHost: 192.168.5.2:8001\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
                    path.as_str()
                )
            );
        }
    }

    #[test]
    fn redirects_ambiguity_oversize_and_duplicate_json_refuse() {
        let cases: &[&[u8]] = &[
            b"HTTP/1.1 302 Found\r\nLocation: http://example.com/\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{\"a\":1,\"a\":2}",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n{}",
        ];
        for response in cases {
            let mut stub = Stub::new(response);
            assert!(exchange(&mut stub, 8002, MetadataPath::Quota).is_err());
        }
    }

    #[test]
    fn fixed_route_rejects_arbitrary_destination_before_network() {
        let pins = json!({});
        for route in [
            "https://192.168.5.2:8001/v1",
            "http://example.com:8001/v1",
            "http://127.0.0.1:8003/v1",
        ] {
            assert!(matches!(
                observe_provider_metadata(route, "model", &pins),
                Err(ObserverError::InvalidPins)
            ));
        }
        assert!(matches!(
            observe_provider_metadata("http://host.lima.internal:8001/v1", "", &pins),
            Err(ObserverError::InvalidPins)
        ));
    }

    #[test]
    fn frozen_python_provider_snapshot_requires_matching_model_and_outside_pins() {
        let frozen: Value = serde_json::from_str(include_str!(
            "../../gauntlet-evidence/tests/fixtures/python_provider_status_v1.json"
        ))
        .unwrap();
        let idle = frozen["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "idle")
            .unwrap();
        let route = model_endpoint("http://host.lima.internal:8001/v1").unwrap();
        let models = json!({"data":[{"id":"outside-model"}]});
        let accepted = validate_observation(
            route.clone(),
            models.clone(),
            idle["status"].clone(),
            "outside-model",
            &idle["pins"],
        )
        .unwrap();
        assert_eq!(accepted.quota, idle["quota"]);
        assert_eq!(accepted.to_json()["qualification_eligible"], false);
        assert!(validate_observation(
            route.clone(),
            models.clone(),
            idle["status"].clone(),
            "different-model",
            &idle["pins"],
        )
        .is_err());
        let mut wrong_pins = idle["pins"].clone();
        wrong_pins["binding_sha256"] = json!("0".repeat(64));
        assert!(validate_observation(
            route,
            models,
            idle["status"].clone(),
            "outside-model",
            &wrong_pins,
        )
        .is_err());
    }
}
