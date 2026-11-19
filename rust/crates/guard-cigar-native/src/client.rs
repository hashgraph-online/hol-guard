//! `__guard-cigar-client`: one agent's restricted broker client.
//!
//! Replaces the Python `broker_client.py`. Guard hands it one grant over the
//! pipe; every operation opens a fresh loopback connection, proves the grant
//! with the broker's mutual handshake, sends one command and reads one reply.
//! Once any command byte may have reached the broker, a failure is reported
//! as `BrokerOutcomeUnknown`, since the broker may have applied it.

use crate::broker_host::{is_hex64, outcome, Outcome};
use crate::frames::{member, serve, REQUEST_FAILED};
use cigar_context::broker::authentication::{ClientHello, ServerProof, MAX_HANDSHAKE_FRAME};
use cigar_context::broker::protocol::{
    read_frame, write_frame, MAX_AGENT_FRAME, MAX_AGENT_RESPONSE,
};
use cigar_context::broker::BrokerCredential;
use serde_json::{json, Value};
use std::io::{self, stdin, stdout, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(3);
const QUEUE_WAIT_MS: u64 = 500;
const UNKNOWN: &str = "BrokerOutcomeUnknown";

/// Serve the client bridge on stdin and stdout until the supervisor closes it.
pub(crate) fn run() -> i32 {
    let mut client: Option<Client> = None;
    serve(&mut stdin().lock(), &mut stdout().lock(), |request| {
        (dispatch(&mut client, request), false)
    });
    0
}

fn dispatch(client: &mut Option<Client>, request: &Value) -> Result<Value, &'static str> {
    let op = request
        .get("op")
        .and_then(Value::as_str)
        .ok_or(REQUEST_FAILED)?;
    if op == "prepare" && client.is_none() {
        return Ok(json!({"ready": true}));
    }
    if op == "initialize" {
        if client.is_some() {
            return Err(REQUEST_FAILED);
        }
        *client = Some(Client::from_config(&member(request, "connection")?)?);
        return Ok(json!({"initialized": true}));
    }
    let client = client.as_ref().ok_or(REQUEST_FAILED)?;
    let field = |name: &str| member(request, name);
    match op {
        "compile" => client.call(json!({"op": "compile", "request": field("request")?})),
        "revalidate" => {
            client.call(json!({"op": "revalidate", "ticket": field("ticket")?}))?;
            Ok(json!({"current": true}))
        }
        "explain" => client.call(json!({"op": "explain", "ticket": field("ticket")?})),
        "forget_ticket" => {
            client.call(json!({"op": "forget_ticket", "ticket": field("ticket")?}))?;
            Ok(json!({"forgotten": true}))
        }
        "submit_answer" => {
            let ticket = field("ticket")?;
            let draft = field("draft")?;
            let result =
                client.call(json!({"op": "submit_answer", "ticket": ticket, "draft": draft}))?;
            result.get("submission_id").cloned().ok_or(REQUEST_FAILED)
        }
        "propose" => client.call(json!({
            "op": "propose_source",
            "request_key": field("request_key")?,
            "source": field("source")?,
            "expected": field("expected")?,
            "documents": field("documents")?,
        })),
        "proposal_status" => {
            client.call(json!({"op": "proposal_status", "request_key": field("request_key")?}))
        }
        "forget_proposal" => {
            client.call(json!({"op": "forget_proposal", "request_key": field("request_key")?}))?;
            Ok(json!({"forgotten": true}))
        }
        _ => Err(REQUEST_FAILED),
    }
}

struct Client {
    port: u16,
    credential: BrokerCredential,
}

impl Client {
    /// Accept exactly the `cigar.broker-client.v1` config a grant exports.
    fn from_config(config: &Value) -> Result<Self, &'static str> {
        let object = config.as_object().filter(|object| {
            object.len() == 5
                && ["schema", "host", "port", "epoch", "secret"]
                    .iter()
                    .all(|key| object.contains_key(*key))
        });
        let object = object.ok_or("InvalidInput")?;
        let port = object["port"]
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port > 0);
        match (port, object["epoch"].as_str(), object["secret"].as_str()) {
            (Some(port), Some(epoch), Some(secret))
                if object["schema"] == "cigar.broker-client.v1"
                    && object["host"] == "127.0.0.1"
                    && is_hex64(&object["epoch"])
                    && is_hex64(&object["secret"]) =>
            {
                Ok(Self {
                    port,
                    credential: BrokerCredential {
                        epoch: epoch.to_owned(),
                        secret: secret.to_owned(),
                    },
                })
            }
            _ => Err("InvalidInput"),
        }
    }

    fn call(&self, command: Value) -> Result<Value, &'static str> {
        let request = json!({
            "protocol": crate::BROKER_PROTOCOL,
            "id": 1,
            "wait_ms": QUEUE_WAIT_MS,
            "command": command,
        });
        let body = serde_json::to_vec(&request).map_err(|_| "InvalidInput")?;
        if body.len() > MAX_AGENT_FRAME {
            return Err("LimitExceeded");
        }
        let mut stream = Deadline::connect(self.port)?;
        self.authenticate(&mut stream)?;
        // From here on the broker may have received part of the command.
        let length = u32::try_from(body.len()).map_err(|_| "LimitExceeded")?;
        let sent = stream
            .write_all(&length.to_be_bytes())
            .and_then(|()| stream.write_all(&body))
            .and_then(|()| stream.flush());
        if sent.is_err() {
            return Err(UNKNOWN);
        }
        let reply = read_frame(&mut stream, MAX_AGENT_RESPONSE).map_err(|_| UNKNOWN)?;
        let reply = serde_json::from_slice::<Value>(&reply).map_err(|_| UNKNOWN)?;
        match outcome(&reply, 1) {
            Some(Outcome::Done(result)) => Ok(result),
            Some(Outcome::Failed(code)) => Err(code),
            None => Err(UNKNOWN),
        }
    }

    /// Prove the grant and check the broker's proof before any command byte.
    fn authenticate(&self, stream: &mut Deadline) -> Result<(), &'static str> {
        let hello = ClientHello::new(&self.credential).map_err(|_| "Authentication")?;
        write_frame(stream, &hello, MAX_HANDSHAKE_FRAME).map_err(|_| stream.failure())?;
        let server = read_frame(stream, MAX_HANDSHAKE_FRAME).map_err(|_| stream.failure())?;
        let server: ServerProof = serde_json::from_slice(&server).map_err(|_| "Authentication")?;
        let proof = hello
            .verify_server(&self.credential, &server)
            .map_err(|_| "Authentication")?;
        write_frame(stream, &proof, MAX_HANDSHAKE_FRAME).map_err(|_| stream.failure())
    }
}

/// A loopback stream that holds every read and write to one total deadline.
struct Deadline {
    stream: TcpStream,
    deadline: Instant,
    timed_out: bool,
}

impl Deadline {
    fn connect(port: u16) -> Result<Self, &'static str> {
        let deadline = Instant::now() + TIMEOUT;
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let stream = TcpStream::connect_timeout(&address, TIMEOUT).map_err(|error| {
            if error.kind() == io::ErrorKind::TimedOut {
                "Timeout"
            } else {
                "Transport"
            }
        })?;
        let _ = stream.set_nodelay(true);
        Ok(Self {
            stream,
            deadline,
            timed_out: false,
        })
    }

    fn remaining(&mut self) -> io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            self.timed_out = true;
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(left)
    }

    fn note<T>(&mut self, result: io::Result<T>) -> io::Result<T> {
        if let Err(error) = &result {
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) {
                self.timed_out = true;
            }
        }
        result
    }

    /// The code for a failure before any command byte was sent.
    fn failure(&self) -> &'static str {
        if self.timed_out {
            "Timeout"
        } else {
            "Transport"
        }
    }
}

impl Read for Deadline {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let left = self.remaining()?;
        self.stream.set_read_timeout(Some(left))?;
        let result = self.stream.read(buffer);
        self.note(result)
    }
}

impl Write for Deadline {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let left = self.remaining()?;
        self.stream.set_write_timeout(Some(left))?;
        let result = self.stream.write(buffer);
        self.note(result)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
