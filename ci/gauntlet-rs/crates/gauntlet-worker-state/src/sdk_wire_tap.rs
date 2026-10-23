//! Ineligible Rust-owned MCP data plane for the future SDK socket tap.
//!
//! The caller must establish the peer/cgroup identities and retain the
//! returned events under a one-use outside pin. This module only forwards
//! byte-identical bounded JSON-RPC lines between two already held sockets.

use gauntlet_contracts::canonicalize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(crate) const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_TOTAL_BYTES: usize = 12 * 1024 * 1024;
pub(crate) const MAX_FRAMES: usize = 1_000;
const READ_TIMEOUT: Duration = Duration::from_millis(250);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_LIFETIME: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdkWireEvent {
    pub sequence: usize,
    pub family: String,
    pub direction: &'static str,
    pub frame_sha256: String,
    pub canonical_message_sha256: String,
    pub frame_bytes: usize,
    pub method: Option<String>,
    /// Canonical JSON scalar: quoted for string IDs, unquoted for integer IDs.
    pub id_json: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdkWireObservation {
    pub events: Vec<SdkWireEvent>,
    pub completed_tool_calls: usize,
    pub total_bytes: usize,
}

impl SdkWireObservation {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-sdk-wire-tap.v1",
            "events":self.events.iter().map(|event| json!({
                "sequence":event.sequence,
                "family":event.family,
                "direction":event.direction,
                "frame_sha256":event.frame_sha256,
                "canonical_message_sha256":event.canonical_message_sha256,
                "frame_bytes":event.frame_bytes,
                "method":event.method,
                "id_json":event.id_json,
            })).collect::<Vec<_>>(),
            "completed_tool_calls":self.completed_tool_calls,
            "total_bytes":self.total_bytes,
            "peer_identity_verified":false,
            "journal_durable":false,
            "execution_eligible":false,
        })
    }
}

struct Ledger {
    family: String,
    events: Vec<SdkWireEvent>,
    total_bytes: usize,
    pending_client: BTreeMap<String, String>,
    pending_service: BTreeMap<String, String>,
    completed_tool_calls: usize,
    poisoned: bool,
}

/// Root-side replay validator for raw frames delivered over a future private
/// child pipe. It does not infer that the child actually forwarded a frame.
pub struct SdkWireFrameObserver {
    ledger: Ledger,
}

impl SdkWireFrameObserver {
    pub fn new(family: &str) -> Result<Self, String> {
        Ok(Self {
            ledger: Ledger::new(family)?,
        })
    }

    pub fn observe(
        &mut self,
        direction: &'static str,
        frame: &[u8],
    ) -> Result<SdkWireEvent, String> {
        self.ledger.ingest(direction, frame, None)
    }

    pub fn finish(self) -> Result<SdkWireObservation, String> {
        self.ledger.finish()
    }
}

impl Ledger {
    fn new(family: &str) -> Result<Self, String> {
        if !matches!(family, "docs" | "mail") {
            return Err("fixed MCP tap family required".to_owned());
        }
        Ok(Self {
            family: family.to_owned(),
            events: Vec::new(),
            total_bytes: 0,
            pending_client: BTreeMap::new(),
            pending_service: BTreeMap::new(),
            completed_tool_calls: 0,
            poisoned: false,
        })
    }

    fn forward(
        &mut self,
        direction: &'static str,
        frame: &[u8],
        destination: &mut UnixStream,
    ) -> Result<(), String> {
        self.ingest(direction, frame, Some(destination)).map(|_| ())
    }

    fn ingest(
        &mut self,
        direction: &'static str,
        frame: &[u8],
        destination: Option<&mut UnixStream>,
    ) -> Result<SdkWireEvent, String> {
        if self.poisoned
            || frame.len() < 2
            || frame.len() > MAX_FRAME_BYTES + 1
            || frame.last() != Some(&b'\n')
            || frame[..frame.len() - 1].contains(&b'\n')
            || self.events.len() >= MAX_FRAMES
            || self
                .total_bytes
                .checked_add(frame.len())
                .is_none_or(|value| value > MAX_TOTAL_BYTES)
        {
            self.poisoned = true;
            return Err("MCP tap frame or aggregate bound exceeded".to_owned());
        }
        let canonical = match canonicalize(&frame[..frame.len() - 1]) {
            Ok(value) => value,
            Err(_) => {
                self.poisoned = true;
                return Err("invalid strict MCP JSON-RPC frame".to_owned());
            }
        };
        let value: Value = match serde_json::from_slice(&canonical) {
            Ok(value) => value,
            Err(_) => {
                self.poisoned = true;
                return Err("invalid strict MCP JSON-RPC frame".to_owned());
            }
        };
        if !value.is_object() || value["jsonrpc"] != "2.0" {
            self.poisoned = true;
            return Err("invalid MCP JSON-RPC version or body".to_owned());
        }
        let object = value.as_object().ok_or("invalid MCP object")?;
        let id = match object.get("id") {
            None => None,
            Some(Value::String(id)) if !id.is_empty() && id.len() <= 128 => {
                Some(serde_json::to_string(id).map_err(|error| error.to_string())?)
            }
            Some(Value::Number(id)) if id.is_i64() || id.is_u64() => Some(id.to_string()),
            _ => {
                self.poisoned = true;
                return Err("invalid MCP request ID".to_owned());
            }
        };
        if id.as_ref().is_some_and(|id| id.len() > 128) {
            self.poisoned = true;
            return Err("invalid MCP request ID".to_owned());
        }
        if !matches!(direction, "client-to-service" | "service-to-client") {
            self.poisoned = true;
            return Err("invalid MCP tap direction".to_owned());
        }
        let method = object.get("method").and_then(Value::as_str);
        let has_result = object.contains_key("result");
        let has_error = object.contains_key("error");
        let is_request = object.contains_key("method");
        let valid_shape = if is_request {
            method.is_some_and(|method| !method.is_empty()) && !has_result && !has_error
        } else {
            id.is_some() && (has_result != has_error) && (!has_error || object["error"].is_object())
        };
        if !valid_shape {
            self.poisoned = true;
            return Err("invalid MCP request or response shape".to_owned());
        }
        let sender_is_client = direction == "client-to-service";
        if is_request {
            if let Some(id) = id.as_ref() {
                let sender_pending = if sender_is_client {
                    &self.pending_client
                } else {
                    &self.pending_service
                };
                if sender_pending.contains_key(id) {
                    self.poisoned = true;
                    return Err("duplicate outstanding MCP request ID".to_owned());
                }
            }
        } else if let Some(id) = id.as_ref() {
            let recipient_pending = if sender_is_client {
                &self.pending_service
            } else {
                &self.pending_client
            };
            if !recipient_pending.contains_key(id) {
                self.poisoned = true;
                return Err("orphan MCP response ID".to_owned());
            }
        }
        if let Some(destination) = destination {
            if let Err(error) = destination.write_all(frame) {
                self.poisoned = true;
                return Err(format!("MCP tap forwarding failed: {error}"));
            }
        }
        if is_request {
            if let Some(id) = id.as_ref() {
                let sender_pending = if sender_is_client {
                    &mut self.pending_client
                } else {
                    &mut self.pending_service
                };
                sender_pending.insert(id.to_owned(), method.unwrap_or_default().to_owned());
            }
        } else if let Some(id) = id.as_ref() {
            let recipient_pending = if sender_is_client {
                &mut self.pending_service
            } else {
                &mut self.pending_client
            };
            let matched_method = recipient_pending.remove(id);
            if !sender_is_client && matched_method.as_deref() == Some("tools/call") {
                self.completed_tool_calls += 1;
            }
        }
        let event = SdkWireEvent {
            sequence: self.events.len() + 1,
            family: self.family.clone(),
            direction,
            frame_sha256: format!("{:x}", Sha256::digest(frame)),
            canonical_message_sha256: format!("{:x}", Sha256::digest(&canonical)),
            frame_bytes: frame.len(),
            method: method.map(str::to_owned),
            id_json: id,
        };
        self.events.push(event.clone());
        self.total_bytes += frame.len();
        Ok(event)
    }

    fn finish(self) -> Result<SdkWireObservation, String> {
        if self.poisoned
            || !self.pending_client.is_empty()
            || !self.pending_service.is_empty()
            || self.events.is_empty()
        {
            return Err("MCP tap did not close a complete exchange".to_owned());
        }
        Ok(SdkWireObservation {
            events: self.events,
            completed_tool_calls: self.completed_tool_calls,
            total_bytes: self.total_bytes,
        })
    }
}

struct RelayControl<'a> {
    stop: &'a AtomicBool,
    cancelled: &'a AtomicBool,
    until: Instant,
}

fn pump<F, C>(
    mut source: UnixStream,
    mut destination: UnixStream,
    direction: &'static str,
    ledger: &Mutex<Ledger>,
    frame_sink: &Mutex<F>,
    pre_forward: &Mutex<C>,
    control: &RelayControl<'_>,
) -> Result<(), String>
where
    F: FnMut(&'static str, &[u8]) -> Result<(), String> + Send,
    C: FnMut(&'static str, &[u8]) -> Result<(), String> + Send,
{
    source
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(|error| error.to_string())?;
    destination
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .map_err(|error| error.to_string())?;
    let mut chunk = [0_u8; 8192];
    let mut frame = Vec::new();
    loop {
        if control.stop.load(Ordering::Acquire)
            || control.cancelled.load(Ordering::Acquire)
            || Instant::now() >= control.until
        {
            return Err("MCP tap was cancelled or timed out".to_owned());
        }
        let count = match source.read(&mut chunk) {
            Ok(0) => {
                if !frame.is_empty() {
                    return Err("partial MCP frame at EOF".to_owned());
                }
                destination
                    .shutdown(Shutdown::Write)
                    .map_err(|error| error.to_string())?;
                return Ok(());
            }
            Ok(count) => count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(error) => return Err(format!("MCP tap read failed: {error}")),
        };
        let mut remaining = &chunk[..count];
        while !remaining.is_empty() {
            if let Some(index) = remaining.iter().position(|byte| *byte == b'\n') {
                frame.extend_from_slice(&remaining[..=index]);
                if frame.len() > MAX_FRAME_BYTES + 1 {
                    return Err("MCP tap frame exceeds byte bound".to_owned());
                }
                let mut ledger = ledger
                    .lock()
                    .map_err(|_| "MCP tap ledger lock poisoned".to_owned())?;
                let mut check = pre_forward
                    .lock()
                    .map_err(|_| "MCP tap pre-forward lock poisoned".to_owned())?;
                if let Err(error) = (*check)(direction, &frame) {
                    ledger.poisoned = true;
                    return Err(format!("MCP tap pre-forward check failed: {error}"));
                }
                drop(check);
                ledger.forward(direction, &frame, &mut destination)?;
                let mut sink = frame_sink
                    .lock()
                    .map_err(|_| "MCP tap frame sink lock poisoned".to_owned())?;
                if let Err(error) = (*sink)(direction, &frame) {
                    ledger.poisoned = true;
                    return Err(format!("MCP tap frame report failed: {error}"));
                }
                frame.clear();
                remaining = &remaining[index + 1..];
            } else {
                frame.extend_from_slice(remaining);
                if frame.len() > MAX_FRAME_BYTES + 1 {
                    return Err("MCP tap frame exceeds byte bound".to_owned());
                }
                break;
            }
        }
    }
}

/// Relay one already authenticated client/frontdoor pair. The returned value
/// is a private diagnostic, never a conformance verdict or public snapshot.
pub fn relay_bounded_sdk_mcp_pair_ineligible(
    client: UnixStream,
    frontdoor: UnixStream,
    family: &str,
    cancelled: &AtomicBool,
) -> Result<SdkWireObservation, String> {
    let sink = Mutex::new(|_direction: &'static str, _frame: &[u8]| Ok(()));
    relay_bounded_sdk_mcp_pair_with_frame_sink_ineligible(
        client, frontdoor, family, cancelled, &sink,
    )
}

/// The sink is called in the same order as successfully forwarded frames.
/// Its intended use is the bounded raw-frame child pipe; a failed sink poisons
/// this exchange even when bytes reached the other socket.
pub fn relay_bounded_sdk_mcp_pair_with_frame_sink_ineligible<F>(
    client: UnixStream,
    frontdoor: UnixStream,
    family: &str,
    cancelled: &AtomicBool,
    frame_sink: &Mutex<F>,
) -> Result<SdkWireObservation, String>
where
    F: FnMut(&'static str, &[u8]) -> Result<(), String> + Send,
{
    let no_check = Mutex::new(|_direction: &'static str, _frame: &[u8]| Ok(()));
    relay_bounded_sdk_mcp_pair_with_checks_ineligible(
        client,
        frontdoor,
        family,
        cancelled,
        MAX_LIFETIME,
        &no_check,
        frame_sink,
    )
}

/// Root-owned forwarding can authenticate both held peers immediately
/// before each write. A failed precheck prevents that frame from reaching
/// the destination and poisons the whole exchange.
pub(crate) fn relay_bounded_sdk_mcp_pair_with_checks_ineligible<F, C>(
    client: UnixStream,
    frontdoor: UnixStream,
    family: &str,
    cancelled: &AtomicBool,
    lifetime: Duration,
    pre_forward: &Mutex<C>,
    frame_sink: &Mutex<F>,
) -> Result<SdkWireObservation, String>
where
    F: FnMut(&'static str, &[u8]) -> Result<(), String> + Send,
    C: FnMut(&'static str, &[u8]) -> Result<(), String> + Send,
{
    if lifetime == Duration::ZERO {
        return Err("MCP tap lifetime already expired".to_owned());
    }
    let ledger = Mutex::new(Ledger::new(family)?);
    let stop = AtomicBool::new(false);
    let until = Instant::now() + lifetime.min(MAX_LIFETIME);
    let control = RelayControl {
        stop: &stop,
        cancelled,
        until,
    };
    let client_read = client.try_clone().map_err(|error| error.to_string())?;
    let frontdoor_read = frontdoor.try_clone().map_err(|error| error.to_string())?;
    let result = std::thread::scope(|scope| {
        let outgoing = scope.spawn(|| {
            let outcome = pump(
                client_read,
                frontdoor,
                "client-to-service",
                &ledger,
                frame_sink,
                pre_forward,
                &control,
            );
            if outcome.is_err() {
                stop.store(true, Ordering::Release);
            }
            outcome
        });
        let incoming = scope.spawn(|| {
            let outcome = pump(
                frontdoor_read,
                client,
                "service-to-client",
                &ledger,
                frame_sink,
                pre_forward,
                &control,
            );
            if outcome.is_err() {
                stop.store(true, Ordering::Release);
            }
            outcome
        });
        let first = outgoing
            .join()
            .map_err(|_| "outgoing MCP tap thread panicked".to_owned())?;
        let second = incoming
            .join()
            .map_err(|_| "incoming MCP tap thread panicked".to_owned())?;
        match (first, second) {
            (Err(first), Err(second)) if first == "MCP tap was cancelled or timed out" => {
                Err(second)
            }
            (Err(first), _) => Err(first),
            (_, Err(second)) => Err(second),
            (Ok(()), Ok(())) => Ok(()),
        }
    });
    if cancelled.load(Ordering::Acquire) {
        return Err("MCP tap was cancelled".to_owned());
    }
    result?;
    ledger
        .into_inner()
        .map_err(|_| "MCP tap ledger lock poisoned".to_owned())?
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_unix_sockets_preserve_bytes_and_match_response() {
        let (mut sdk, tap_client) = UnixStream::pair().unwrap();
        let (mut native, tap_frontdoor) = UnixStream::pair().unwrap();
        let request = b"{ \"jsonrpc\":\"2.0\",\"id\":\"r1\",\"method\":\"tools/call\",\"params\":{\"name\":\"docs.read\"}}\n";
        let response = b"{\"jsonrpc\":\"2.0\",\"id\":\"r1\",\"result\":{\"isError\":false}}\n";
        std::thread::scope(|scope| {
            let relay = scope.spawn(|| {
                relay_bounded_sdk_mcp_pair_ineligible(
                    tap_client,
                    tap_frontdoor,
                    "docs",
                    &AtomicBool::new(false),
                )
                .unwrap()
            });
            let server = scope.spawn(|| {
                let mut observed = vec![0; request.len()];
                native.read_exact(&mut observed).unwrap();
                assert_eq!(observed, request);
                native.write_all(response).unwrap();
                native.shutdown(Shutdown::Write).unwrap();
            });
            sdk.write_all(request).unwrap();
            sdk.shutdown(Shutdown::Write).unwrap();
            let mut received = vec![0; response.len()];
            sdk.read_exact(&mut received).unwrap();
            assert_eq!(received, response);
            server.join().unwrap();
            let proof = relay.join().unwrap();
            assert_eq!(proof.events.len(), 2);
            assert_eq!(proof.completed_tool_calls, 1);
            assert_eq!(
                proof.events[0].frame_sha256,
                format!("{:x}", Sha256::digest(request))
            );
            assert_eq!(
                proof.events[1].frame_sha256,
                format!("{:x}", Sha256::digest(response))
            );
            assert_eq!(proof.to_json()["execution_eligible"], false);
        });
    }

    #[test]
    fn failed_root_pre_forward_check_never_delivers_request() {
        let (mut sdk, tap_client) = UnixStream::pair().unwrap();
        let (mut native, tap_frontdoor) = UnixStream::pair().unwrap();
        let request = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}\n";
        let check = Mutex::new(|_direction: &'static str, _frame: &[u8]| {
            Err("peer ancestry changed".to_owned())
        });
        let sink = Mutex::new(|_direction: &'static str, _frame: &[u8]| Ok(()));
        let relay = std::thread::spawn(move || {
            relay_bounded_sdk_mcp_pair_with_checks_ineligible(
                tap_client,
                tap_frontdoor,
                "docs",
                &AtomicBool::new(false),
                Duration::from_secs(5),
                &check,
                &sink,
            )
        });
        sdk.write_all(request).unwrap();
        sdk.shutdown(Shutdown::Write).unwrap();
        assert!(relay.join().unwrap().is_err());
        let mut byte = [0_u8; 1];
        assert_eq!(native.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn idle_root_relay_stops_at_caller_lifetime() {
        let (_sdk, tap_client) = UnixStream::pair().unwrap();
        let (_native, tap_frontdoor) = UnixStream::pair().unwrap();
        let check = Mutex::new(|_direction: &'static str, _frame: &[u8]| Ok(()));
        let sink = Mutex::new(|_direction: &'static str, _frame: &[u8]| Ok(()));
        let began = Instant::now();
        let result = relay_bounded_sdk_mcp_pair_with_checks_ineligible(
            tap_client,
            tap_frontdoor,
            "docs",
            &AtomicBool::new(false),
            Duration::from_millis(100),
            &check,
            &sink,
        );
        assert!(result.is_err());
        assert!(began.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn duplicate_or_partial_frames_refuse() {
        let mut ledger = Ledger::new("docs").unwrap();
        let (mut peer, mut writer) = UnixStream::pair().unwrap();
        let request = b"{\"jsonrpc\":\"2.0\",\"id\":\"r1\",\"method\":\"tools/call\"}\n";
        ledger
            .forward("client-to-service", request, &mut writer)
            .unwrap();
        let mut received = vec![0; request.len()];
        peer.read_exact(&mut received).unwrap();
        assert!(ledger
            .forward("client-to-service", request, &mut writer)
            .is_err());
        assert!(ledger.finish().is_err());
        let (mut sdk, tap_client) = UnixStream::pair().unwrap();
        let (native, tap_frontdoor) = UnixStream::pair().unwrap();
        let probe = std::thread::spawn(move || {
            relay_bounded_sdk_mcp_pair_ineligible(
                tap_client,
                tap_frontdoor,
                "docs",
                &AtomicBool::new(false),
            )
        });
        sdk.write_all(b"{\"jsonrpc\":\"2.0\"").unwrap();
        sdk.shutdown(Shutdown::Write).unwrap();
        drop(native);
        assert!(probe.join().unwrap().is_err());
    }

    #[test]
    fn malformed_json_and_orphan_response_never_forward() {
        let mut ledger = Ledger::new("docs").unwrap();
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        reader.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        assert!(ledger
            .forward(
                "client-to-service",
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"id\":2}\n",
                &mut writer
            )
            .is_err());
        let mut byte = [0_u8; 1];
        assert!(reader.read(&mut byte).is_err());
        let mut ledger = Ledger::new("docs").unwrap();
        assert!(ledger
            .forward(
                "service-to-client",
                b"{\"jsonrpc\":\"2.0\",\"id\":\"unknown\",\"result\":{}}\n",
                &mut writer
            )
            .is_err());
        assert!(Ledger::new("other").is_err());
    }

    #[test]
    fn numeric_ids_notifications_and_reverse_requests_keep_distinct_ledgers() {
        let mut ledger = Ledger::new("mail").unwrap();
        let (mut receiver, mut writer) = UnixStream::pair().unwrap();
        let frames: &[(&str, &[u8])] = &[
            (
                "client-to-service",
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}\n",
            ),
            (
                "client-to-service",
                b"{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"tools/call\"}\n",
            ),
            (
                "service-to-client",
                b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n",
            ),
            (
                "service-to-client",
                b"{\"jsonrpc\":\"2.0\",\"id\":\"s1\",\"method\":\"ping\"}\n",
            ),
            (
                "client-to-service",
                b"{\"jsonrpc\":\"2.0\",\"id\":\"s1\",\"result\":null}\n",
            ),
            (
                "service-to-client",
                b"{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":[]}\n",
            ),
            (
                "service-to-client",
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n",
            ),
        ];
        for (direction, frame) in frames {
            ledger.forward(direction, frame, &mut writer).unwrap();
            let mut observed = vec![0; frame.len()];
            receiver.read_exact(&mut observed).unwrap();
            assert_eq!(&observed, frame);
        }
        let proof = ledger.finish().unwrap();
        assert_eq!(proof.completed_tool_calls, 2);
        assert_eq!(proof.events[0].id_json.as_deref(), Some("1"));
        assert_eq!(proof.events[1].id_json.as_deref(), Some("\"1\""));
    }

    #[test]
    fn cancellation_and_frame_budget_refuse() {
        let mut ledger = Ledger::new("docs").unwrap();
        let (_reader, mut writer) = UnixStream::pair().unwrap();
        let mut huge_frame = vec![b' '; MAX_FRAME_BYTES + 1];
        huge_frame.push(b'\n');
        assert!(ledger
            .forward("client-to-service", &huge_frame, &mut writer)
            .is_err());
        assert!(ledger.finish().is_err());
        let (_sdk, tap_client) = UnixStream::pair().unwrap();
        let (_native, tap_frontdoor) = UnixStream::pair().unwrap();
        let cancelled = AtomicBool::new(true);
        let began = Instant::now();
        assert!(relay_bounded_sdk_mcp_pair_ineligible(
            tap_client,
            tap_frontdoor,
            "docs",
            &cancelled
        )
        .is_err());
        assert!(began.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn root_side_raw_frame_observer_recomputes_digest_and_refuses_missing_result() {
        let request = b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\"}\n";
        let response = b"{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n";
        let mut observer = SdkWireFrameObserver::new("docs").unwrap();
        let first = observer.observe("client-to-service", request).unwrap();
        assert_eq!(first.frame_sha256, format!("{:x}", Sha256::digest(request)));
        assert_eq!(
            first.canonical_message_sha256,
            format!(
                "{:x}",
                Sha256::digest(canonicalize(&request[..request.len() - 1]).unwrap())
            )
        );
        assert_eq!(first.id_json.as_deref(), Some("2"));
        let second = observer.observe("service-to-client", response).unwrap();
        assert_eq!(second.sequence, 2);
        assert_eq!(observer.finish().unwrap().completed_tool_calls, 1);
        let mut missing = SdkWireFrameObserver::new("docs").unwrap();
        missing.observe("client-to-service", request).unwrap();
        assert!(missing.finish().is_err());
        let mut forged = SdkWireFrameObserver::new("docs").unwrap();
        assert!(forged.observe("service-to-client", response).is_err());
    }
}
