//! `content-decode --stdin`: contained HTTP content-coding decode.
//!
//! Reads one `ContentDecodeRequestV1`, refuses anything the decoder does not
//! fully understand (unknown codings, coding parameters, stacks deeper than
//! the caps, bodies over the input cap) before a decoder is constructed, and
//! only then applies the same containment the archive inspector uses:
//! resource limits, the platform capability deny, and probes proving network,
//! write and spawn are gone. The decode runs inside that containment with
//! byte, ratio, depth, time and halt bounds. The worker never sees a
//! credential or a destination; its caller passes the raw body and headers
//! and nothing else. Every decode outcome is a typed result with exit code 0;
//! transport failures exit nonzero so the caller fails closed.

#[cfg(unix)]
use std::sync::atomic::Ordering;
#[cfg(unix)]
use std::time::Duration;
use std::time::Instant;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use guard_archive::content_coding::{
    parse_content_codings, ContentCoding, ContentCodingCaps, ContentDecodeCounters,
    ContentDecodeError, ContentDecodeStatus,
};
use guard_contracts::{
    ContentDecodeCountersV1, ContentDecodeRequestV1, ContentDecodeResultV1,
    CONTENT_CAP_HEADER_VALUES, CONTENT_CAP_INPUT_BYTES, CONTENT_CAP_LAYERS,
    CONTENT_CAP_MEMORY_BYTES, CONTENT_CAP_OUTPUT_BYTES, CONTENT_CAP_RATIO, CONTENT_CAP_TIMEOUT_MS,
    CONTENT_DECODE_REQUEST_SCHEMA, CONTENT_DECODE_RESULT_SCHEMA,
};
use sha2::{Digest, Sha256};

#[cfg(target_os = "macos")]
use crate::archive_inspect_containment::warm_allocator_regions;
#[cfg(unix)]
use crate::archive_inspect_containment::{
    acquire_archive_lease, apply_capability_deny, apply_child_limits, network_capability_denied,
    spawn_capability_denied, write_capability_denied,
};

const MAX_STATE_DIR_BYTES: usize = 16 * 1024;

fn incomplete(code: &'static str, message: &'static str) -> ContentDecodeError {
    ContentDecodeError {
        status: ContentDecodeStatus::Incomplete,
        code,
        message,
    }
}

fn containment_unavailable() -> ContentDecodeError {
    incomplete(
        "content_containment_unavailable",
        "Contained content decoding is unavailable on this platform.",
    )
}

pub(crate) fn evaluate_content_decode_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let started = Instant::now();
    #[cfg(unix)]
    let original_parent = crate::archive_inspect::arm_parent_death_guard();
    #[cfg(not(unix))]
    let original_parent = 0i32;
    let value = crate::strict_json_value(bytes)?;
    let request: ContentDecodeRequestV1 =
        serde_json::from_value(value).map_err(|_| "content_decode_request_invalid".to_owned())?;
    let request_sha256 = hex::encode(Sha256::digest(bytes));
    let runtime_sha256 = crate::resident_state::runtime_digest()?;
    let mut counters = ContentDecodeCounters::default();
    let outcome = decode_request(&request, original_parent, started, &mut counters);
    let (status, code, message, body) = match outcome {
        Ok(body) => (
            "decoded",
            "content_decoded",
            "The response body was decoded.",
            Some(body),
        ),
        Err(error) => (
            match error.status {
                ContentDecodeStatus::Rejected => "rejected",
                ContentDecodeStatus::Incomplete | ContentDecodeStatus::Halted => "incomplete",
            },
            error.code,
            error.message,
            None,
        ),
    };
    let result = ContentDecodeResultV1 {
        schema: CONTENT_DECODE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        message: message.to_owned(),
        body_sha256: body.as_ref().map(|body| hex::encode(Sha256::digest(body))),
        body_base64: body.map(|body| STANDARD.encode(body)),
        runtime_sha256,
        counters: ContentDecodeCountersV1 {
            decoder_calls: counters.decoder_calls,
            input_bytes: counters.input_bytes,
            output_bytes: counters.output_bytes,
            layers: counters.layers,
            elapsed_ms: started.elapsed().as_millis() as u64,
        },
    };
    serde_json::to_vec(&result).map_err(|_| "content_decode_encode_failed".to_owned())
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validated_caps(request: &ContentDecodeRequestV1) -> Option<ContentCodingCaps> {
    let caps = &request.caps;
    let valid = request.schema == CONTENT_DECODE_REQUEST_SCHEMA
        && is_lower_hex(&request.request_id, 32)
        && request.content_encoding.len() <= CONTENT_CAP_HEADER_VALUES
        && !request.state_dir.is_empty()
        && request.state_dir.len() <= MAX_STATE_DIR_BYTES
        && request.timeout_ms > 0
        && request.timeout_ms <= CONTENT_CAP_TIMEOUT_MS
        && caps.max_input_bytes > 0
        && caps.max_input_bytes <= CONTENT_CAP_INPUT_BYTES
        && caps.max_output_bytes > 0
        && caps.max_output_bytes <= CONTENT_CAP_OUTPUT_BYTES
        && caps.max_ratio > 0
        && caps.max_ratio <= CONTENT_CAP_RATIO
        && caps.max_layers > 0
        && caps.max_layers <= CONTENT_CAP_LAYERS
        && caps.max_memory_bytes > 0
        && caps.max_memory_bytes <= CONTENT_CAP_MEMORY_BYTES;
    valid.then_some(ContentCodingCaps {
        max_input_bytes: caps.max_input_bytes,
        max_output_bytes: caps.max_output_bytes,
        max_ratio: caps.max_ratio,
        max_layers: caps.max_layers as usize,
    })
}

/// Everything that can refuse the response without decoding it runs first,
/// outside containment, so a refusal never constructs a decoder.
fn decode_request(
    request: &ContentDecodeRequestV1,
    original_parent: i32,
    started: Instant,
    counters: &mut ContentDecodeCounters,
) -> Result<Vec<u8>, ContentDecodeError> {
    let caps = validated_caps(request).ok_or_else(|| {
        incomplete(
            "content_decode_policy_invalid",
            "Content decode policy is invalid.",
        )
    })?;
    // Bound the encoded form before decoding it, so an oversized body is
    // refused without allocating its decoded copy.
    let encoded_ceiling = caps.max_input_bytes.div_ceil(3).saturating_mul(4);
    if request.body_base64.len() as u64 > encoded_ceiling {
        return Err(ContentDecodeError {
            status: ContentDecodeStatus::Rejected,
            code: "content_input_too_large",
            message: "The response body exceeds Guard's raw size limit.",
        });
    }
    let raw = STANDARD.decode(&request.body_base64).map_err(|_| {
        incomplete(
            "content_decode_request_invalid",
            "Content decode request body is not valid base64.",
        )
    })?;
    counters.input_bytes = raw.len() as u64;
    if counters.input_bytes > caps.max_input_bytes {
        return Err(ContentDecodeError {
            status: ContentDecodeStatus::Rejected,
            code: "content_input_too_large",
            message: "The response body exceeds Guard's raw size limit.",
        });
    }
    let values: Vec<&str> = request
        .content_encoding
        .iter()
        .map(String::as_str)
        .collect();
    let codings = parse_content_codings(&values, caps.max_layers)?;
    if codings.is_empty() {
        // Identity: nothing to decode, so no decoder and no containment.
        counters.output_bytes = counters.input_bytes;
        return Ok(raw);
    }
    contained_decode(
        request,
        &raw,
        &codings,
        &caps,
        original_parent,
        started,
        counters,
    )
}

#[cfg(not(unix))]
fn contained_decode(
    _request: &ContentDecodeRequestV1,
    _raw: &[u8],
    _codings: &[ContentCoding],
    _caps: &ContentCodingCaps,
    _original_parent: i32,
    _started: Instant,
    _counters: &mut ContentDecodeCounters,
) -> Result<Vec<u8>, ContentDecodeError> {
    Err(containment_unavailable())
}

#[cfg(unix)]
fn contained_decode(
    request: &ContentDecodeRequestV1,
    raw: &[u8],
    codings: &[ContentCoding],
    caps: &ContentCodingCaps,
    original_parent: i32,
    started: Instant,
    counters: &mut ContentDecodeCounters,
) -> Result<Vec<u8>, ContentDecodeError> {
    let orphaned = || {
        incomplete(
            "content_decode_orphaned",
            "Content decoding lost its supervising process.",
        )
    };
    #[cfg(target_os = "macos")]
    warm_allocator_regions();
    let parent_alive =
        crate::resident_transport_service::resident_parent_liveness().map_err(|_| orphaned())?;
    let has_liveness_channel = std::env::var_os(crate::PARENT_LIVENESS_FD_ENV).is_some();
    let (_lease_file, lease_path) = match acquire_archive_lease(&request.state_dir) {
        Ok(Some(lease)) => lease,
        Ok(None) => {
            return Err(incomplete(
                "content_decode_overloaded",
                "Contained decoding capacity is currently saturated.",
            ));
        }
        Err(_) => {
            return Err(incomplete(
                "content_decode_lease_failed",
                "The contained decode lease could not be established.",
            ));
        }
    };
    if !apply_child_limits(request.timeout_ms, request.caps.max_memory_bytes)
        || !apply_capability_deny()
    {
        return Err(containment_unavailable());
    }
    // Containment is proven before the first untrusted byte is decoded.
    if !network_capability_denied()
        || !write_capability_denied(&lease_path)
        || !spawn_capability_denied()
    {
        return Err(containment_unavailable());
    }
    if !parent_alive.load(Ordering::Acquire)
        || nix::unistd::getppid().as_raw() != original_parent
        || (!has_liveness_channel && original_parent <= 1)
    {
        return Err(orphaned());
    }
    let deadline = started + Duration::from_millis(request.timeout_ms);
    let halt = move || {
        !parent_alive.load(Ordering::Acquire) || nix::unistd::getppid().as_raw() != original_parent
    };
    guard_archive::content_coding::decode_content(raw, codings, caps, deadline, &halt, counters)
}

#[cfg(test)]
#[path = "content_decode_tests.rs"]
mod tests;
