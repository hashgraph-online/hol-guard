//! Single-flight RPC over an authenticated bridge channel. Operation handlers
//! are supplied by trusted caller code, never chosen as an executable or path.

use crate::{BridgeChannel, BridgeIoError, Result};
use gauntlet_evidence::{
    parse_bridge_rpc_request, parse_bridge_rpc_response, BridgeRpcReply, BridgeRpcRequest,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};
use uuid::Uuid;

const MAX_TIMEOUT: Duration = Duration::from_secs(4_000);
const LOCK_POLL: Duration = Duration::from_millis(10);

fn operation_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && name.len() <= 32
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn error_kind(kind: &str) -> bool {
    let mut bytes = kind.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_'))
        && kind.len() <= 64
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn request_id() -> Result<String> {
    let mut bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| BridgeIoError::Invalid("secure RPC request ID unavailable"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(bytes).to_string())
}

pub struct BridgeClient {
    channel: Mutex<BridgeChannel>,
}

impl BridgeClient {
    pub fn new(channel: BridgeChannel) -> Self {
        Self {
            channel: Mutex::new(channel),
        }
    }

    fn lock(
        &self,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<MutexGuard<'_, BridgeChannel>> {
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Err(BridgeIoError::Cancelled);
            }
            match self.channel.try_lock() {
                Ok(guard) => return Ok(guard),
                Err(TryLockError::Poisoned(_)) => {
                    return Err(BridgeIoError::Invalid("bridge single-flight lock poisoned"));
                }
                Err(TryLockError::WouldBlock) => {}
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(BridgeIoError::Deadline);
            }
            std::thread::sleep(remaining.min(LOCK_POLL));
        }
    }

    pub fn call(
        &self,
        operation: &str,
        payload: &Value,
        timeout: Duration,
        cancelled: &AtomicBool,
    ) -> Result<Value> {
        let id = request_id()?;
        self.call_with_id(&id, operation, payload, timeout, cancelled)
    }

    /// The explicit-ID form supports deterministic interoperability tests.
    /// A production caller should use `call` for a fresh random UUID.
    pub fn call_with_id(
        &self,
        id: &str,
        operation: &str,
        payload: &Value,
        timeout: Duration,
        cancelled: &AtomicBool,
    ) -> Result<Value> {
        if timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(BridgeIoError::Invalid(
                "bounded finite RPC timeout required",
            ));
        }
        let body = json!({"request_id":id,"operation":operation,"payload":payload});
        let request = parse_bridge_rpc_request(&body)
            .map_err(|error| BridgeIoError::Frame(error.to_string()))?;
        let deadline = Instant::now() + timeout;
        let mut channel = self.lock(deadline, cancelled)?;
        channel.send("request", &body, deadline, cancelled)?;
        let response = channel.receive("response", deadline, cancelled)?;
        match parse_bridge_rpc_response(&response, &request) {
            Ok(BridgeRpcReply::Success(value)) => Ok(value),
            Ok(BridgeRpcReply::RemoteFailure { code, .. }) => {
                Err(BridgeIoError::RemoteFailure(code))
            }
            Err(error) => {
                channel.invalidate();
                Err(BridgeIoError::Frame(error.to_string()))
            }
        }
    }
}

pub type OperationResult = std::result::Result<Value, &'static str>;

pub struct BridgeOperation<'a> {
    pub name: &'static str,
    pub handler: &'a mut dyn FnMut(&Value) -> OperationResult,
}

fn valid_registry(operations: &[BridgeOperation<'_>]) -> bool {
    (1..=32).contains(&operations.len())
        && operations.iter().enumerate().all(|(index, current)| {
            operation_name(current.name)
                && operations[..index]
                    .iter()
                    .all(|earlier| earlier.name != current.name)
        })
}

fn response(request: &BridgeRpcRequest, result: Value, error: Value) -> Value {
    json!({
        "request_id":request.request_id(),
        "operation":request.operation(),
        "result":result,
        "error":error,
    })
}

pub fn serve_one(
    channel: &mut BridgeChannel,
    operations: &mut [BridgeOperation<'_>],
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<String> {
    if !valid_registry(operations) {
        return Err(BridgeIoError::Invalid(
            "fixed trusted operation registry required",
        ));
    }
    let body = channel.receive("request", deadline, cancelled)?;
    let request = match parse_bridge_rpc_request(&body) {
        Ok(request) => request,
        Err(error) => {
            channel.invalidate();
            return Err(BridgeIoError::Frame(error.to_string()));
        }
    };
    let mut reply = response(&request, Value::Null, Value::Null);
    if let Some(operation) = operations
        .iter_mut()
        .find(|operation| operation.name == request.operation())
    {
        match (operation.handler)(request.payload()) {
            Ok(value) if value.is_object() => reply["result"] = value,
            Ok(_) => {
                reply["error"] = json!({"code":"operation-failed","kind":"BridgeProtocolError"});
            }
            Err(kind) if error_kind(kind) => {
                reply["error"] = json!({"code":"operation-failed","kind":kind});
            }
            Err(_) => {
                channel.invalidate();
                return Err(BridgeIoError::Invalid(
                    "invalid trusted operation error kind",
                ));
            }
        }
    } else {
        reply["error"] = json!({"code":"unknown-operation"});
    }
    channel.send("response", &reply, deadline, cancelled)?;
    Ok(request.operation().to_owned())
}
