//! Data-only request/response contract above the authenticated VM bridge.
//!
//! Callers must first decode a frame with `FrameCodec`, which enforces strict
//! JSON, MAC, direction, session and sequence. An operation name is never an
//! executable, module or path selector. A live client must invalidate its
//! codec on a protocol error or uncertain transport write.

use crate::bridge_frames::canonical_uuid;
use crate::payload::exact_keys;
use crate::{EvidenceError, Result};
use serde_json::Value;

const INVALID_REQUEST: EvidenceError = EvidenceError::Invalid("invalid bridge operation request");
const WRONG_RESPONSE: EvidenceError =
    EvidenceError::Invalid("bridge response does not bind exact request");
const INVALID_ERROR: EvidenceError = EvidenceError::Invalid("invalid bridge operation error");
const INVALID_ERROR_FIELDS: EvidenceError =
    EvidenceError::Invalid("invalid bridge operation error fields");
const INVALID_RESULT: EvidenceError = EvidenceError::Invalid("invalid bridge operation result");

#[derive(Debug, Clone, PartialEq)]
pub struct BridgeRpcRequest {
    request_id: String,
    operation: String,
    payload: Value,
}

impl BridgeRpcRequest {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn operation(&self) -> &str {
        &self.operation
    }

    pub fn payload(&self) -> &Value {
        &self.payload
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum BridgeRpcReply {
    Success(Value),
    RemoteFailure {
        code: &'static str,
        kind: Option<String>,
    },
}

fn operation_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= 32
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn error_kind(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_'))
        && value.len() <= 64
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub fn parse_bridge_rpc_request(body: &Value) -> Result<BridgeRpcRequest> {
    if !exact_keys(body, &["request_id", "operation", "payload"]) {
        return Err(INVALID_REQUEST);
    }
    let request_id = body["request_id"]
        .as_str()
        .filter(|value| canonical_uuid(value))
        .ok_or(INVALID_REQUEST)?;
    let operation = body["operation"]
        .as_str()
        .filter(|value| operation_name(value))
        .ok_or(INVALID_REQUEST)?;
    if !body["payload"].is_object() {
        return Err(INVALID_REQUEST);
    }
    Ok(BridgeRpcRequest {
        request_id: request_id.to_owned(),
        operation: operation.to_owned(),
        payload: body["payload"].clone(),
    })
}

pub fn parse_bridge_rpc_response(
    body: &Value,
    request: &BridgeRpcRequest,
) -> Result<BridgeRpcReply> {
    if !exact_keys(body, &["request_id", "operation", "result", "error"])
        || body["request_id"] != request.request_id
        || body["operation"] != request.operation
    {
        return Err(WRONG_RESPONSE);
    }
    let error = &body["error"];
    if !error.is_null() {
        if !body["result"].is_null()
            || !error.is_object()
            || !(exact_keys(error, &["code"]) || exact_keys(error, &["code", "kind"]))
        {
            return Err(INVALID_ERROR);
        }
        return match error["code"].as_str() {
            Some("unknown-operation") if exact_keys(error, &["code"]) => {
                Ok(BridgeRpcReply::RemoteFailure {
                    code: "unknown-operation",
                    kind: None,
                })
            }
            Some("operation-failed")
                if exact_keys(error, &["code", "kind"])
                    && error["kind"].as_str().is_some_and(error_kind) =>
            {
                Ok(BridgeRpcReply::RemoteFailure {
                    code: "operation-failed",
                    kind: error["kind"].as_str().map(str::to_owned),
                })
            }
            Some("unknown-operation" | "operation-failed") => Err(INVALID_ERROR_FIELDS),
            _ => Err(INVALID_ERROR),
        };
    }
    if !body["result"].is_object() {
        return Err(INVALID_RESULT);
    }
    Ok(BridgeRpcReply::Success(body["result"].clone()))
}
