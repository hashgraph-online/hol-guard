#![forbid(unsafe_code)]

mod approval;
mod approval_gate_consumers;
mod approval_gate_enrollment;
mod approval_gate_grants;
mod approval_gate_op;
mod approval_gate_settings;
mod approval_gate_state;
mod approval_gate_verify;
mod approval_proof_op;
mod approval_reuse;
mod archive_inspect;
mod archive_inspect_containment;
mod business_document_compile;
mod business_source_codec;
mod claim_approval_reuse_op;
mod claim_reuse;
mod command_effect;
#[cfg(unix)]
mod contained_op;
mod context_digest;
mod context_digest_json;
mod context_digest_local_cli;
mod daemon_policy_authority;
mod data_flow_analyze_op;
mod edge;
mod encrypted_secret_store;
mod git_execution_safety_binary;
mod git_execution_safety_checks;
mod git_execution_safety_config;
mod git_execution_safety_op;
mod git_execution_safety_probe;
#[cfg(all(test, unix))]
mod git_execution_safety_repo_tests;
#[cfg(test)]
mod git_execution_safety_tests;
mod github_cli_classify_op;
mod github_workflow_runtime_authorization;
mod hardening;
mod hook_process_spawn;
mod local_cli_grant_op;
mod local_mcp_grant_identity;
mod local_mcp_grant_launcher;
mod local_mcp_grant_op;
mod local_once_store;
mod local_store_read;
mod managed_resident;
mod mcp_probe_op;
mod mcp_runtime_evidence_op;
mod mcp_stdio_session_op;
mod mcp_tool_evidence_op;
mod native_hook_receipt;
mod native_runtime_admission;
mod native_runtime_resilience;
mod oauth_refresh;
mod oauth_secret_authority;
mod oneshot;
mod package_authority_op;
mod package_evaluation_compose_op;
mod policy_decision_lookup_op;
mod policy_enforcement;
mod policy_integrity_resolver;
mod policy_snapshot_build;
mod policy_store;
mod prompt_analyze_op;
mod resident_client;
mod resident_diagnostics;
mod resident_endpoint;
mod resident_ops;
#[allow(dead_code)] // Worker enrollment is not enabled by this OS identity input.
mod resident_peer_identity;
mod resident_process_identity;
mod resident_protocol;
mod resident_state;
mod resident_state_encoding;
mod resident_transport;
mod resident_transport_service;
mod resident_update_lock;
mod runtime_cli;
mod shim_op;
#[cfg(unix)]
mod skill_directory_identity_op;
#[cfg(unix)]
mod skill_identity_canon;
#[cfg(unix)]
mod skill_identity_discovery;
#[cfg(unix)]
mod skill_identity_inspect;
#[cfg(unix)]
mod skill_identity_walk;
#[cfg(unix)]
mod state_directory_lock;
mod strict_json;
mod totp;
mod workflow_capability_store;

pub(crate) use resident_protocol::{capabilities, encode_response, strict_json_value};
pub(crate) use resident_transport::{
    constant_time_eq, hmac_sha256, BoxedResidentStream, ResidentStream,
};
pub(crate) use resident_transport_service::{
    read_resident_auth_token, resident_stdin_liveness, serve, serve_loopback,
};

pub(crate) use guard_contracts::{MAX_NATIVE_REQUEST_BYTES, MAX_NATIVE_RESPONSE_BYTES};
use std::env;
use std::io::{self, Read, Write};
use std::time::Duration;

const BUILD_SHA: &str = match option_env!("HOL_GUARD_BUILD_SHA") {
    Some(value) => value,
    None => "unknown",
};
const PACKAGE_VERSION: &str = match option_env!("HOL_GUARD_PACKAGE_VERSION") {
    Some(value) => value,
    None => env!("CARGO_PKG_VERSION"),
};
const RESIDENT_PROTOCOL_VERSION: u8 = 2;
const REQUEST_MAGIC: &[u8; 4] = b"HGR2";
const RESPONSE_MAGIC: &[u8; 4] = b"HGS2";
const FRAME_REQUEST_ID_BYTES: usize = 32;
const FRAME_DIGEST_BYTES: usize = 32;
const FRAME_HEADER_BYTES: usize = 4 + FRAME_REQUEST_ID_BYTES + FRAME_DIGEST_BYTES + 4;
const AUTH_TOKEN_BYTES: usize = 32;
const AUTH_NONCE_BYTES: usize = 32;
const AUTH_PROOF_BYTES: usize = 32;
const AUTH_WORKERS: usize = 4;
const AUTH_QUEUE_CAPACITY: usize = 32;
const AUTH_QUEUE_CAPACITY_MAX: usize = 64;
const EVALUATION_WORKERS: usize = 16;
const EVALUATION_QUEUE_CAPACITY: usize = 32;
const AUTHENTICATED_PREFETCH_BYTES: usize = 64 * 1024;
const AUTH_TIMEOUT: Duration = Duration::from_millis(250);
const HEADER_TIMEOUT: Duration = Duration::from_millis(250);
const PAYLOAD_TIMEOUT: Duration = Duration::from_secs(2);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);
const SERVER_PROOF_LABEL: &[u8] = b"hol-guard-resident-server-v1\0";
const CLIENT_PROOF_LABEL: &[u8] = b"hol-guard-resident-client-v1\0";
#[cfg(unix)]
const PARENT_LIVENESS_FD_ENV: &str = "HOL_GUARD_PARENT_LIVENESS_FD";

pub(crate) fn evaluation_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().clamp(EVALUATION_WORKERS, 32))
        .unwrap_or(EVALUATION_WORKERS)
}

pub(crate) fn auth_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| (n.get() / 4).clamp(AUTH_WORKERS, 8))
        .unwrap_or(AUTH_WORKERS)
}

pub(crate) fn evaluation_queue_capacity() -> usize {
    evaluation_workers()
        .saturating_mul(2)
        .clamp(EVALUATION_QUEUE_CAPACITY, 64)
}

pub(crate) fn auth_queue_capacity() -> usize {
    auth_workers()
        .saturating_mul(8)
        .clamp(AUTH_QUEUE_CAPACITY, AUTH_QUEUE_CAPACITY_MAX)
}

fn read_stdin_bounded() -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX_NATIVE_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| hardening::read_error(&error, "native_request_read_failed"))?;
    if bytes.len() > MAX_NATIVE_REQUEST_BYTES {
        return Err("native_request_too_large".into());
    }
    Ok(bytes)
}

fn write_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    serde_json::to_writer(io::stdout().lock(), value)
        .map_err(|_| "native_response_encode_failed".to_owned())?;
    println!();
    Ok(())
}

fn write_bytes_response(response: &[u8]) -> Result<(), String> {
    io::stdout()
        .write_all(response)
        .map_err(|error| hardening::write_error(&error, "native_response_write_failed"))?;
    io::stdout()
        .write_all(b"\n")
        .map_err(|error| hardening::write_error(&error, "native_response_write_failed"))?;
    Ok(())
}

fn run() -> Result<(), String> {
    runtime_cli::run()
}

fn main() {
    std::panic::set_hook(Box::new(|_| eprintln!("native_runtime_panicked")));
    if let Err(code) = run() {
        eprintln!("{code}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resident_hmac_matches_cross_language_vectors() {
        let token = [7u8; AUTH_TOKEN_BYTES];
        let nonce = [9u8; AUTH_NONCE_BYTES];
        let server = hmac_sha256(&token, SERVER_PROOF_LABEL, &nonce);
        let client = hmac_sha256(&token, CLIENT_PROOF_LABEL, &nonce);
        assert_eq!(
            server,
            [
                0xb8, 0x19, 0x89, 0x8f, 0x11, 0x87, 0x8c, 0x1c, 0x14, 0x84, 0x23, 0xd0, 0x36, 0x1a,
                0x9d, 0xe2, 0x0d, 0x9e, 0xca, 0x3b, 0xb8, 0x6c, 0xe1, 0x21, 0x4c, 0xee, 0x95, 0x7f,
                0x95, 0xbb, 0x06, 0xc4,
            ]
        );
        assert_eq!(
            client,
            [
                0xfe, 0xf8, 0x3d, 0x9f, 0xf5, 0x98, 0x89, 0x22, 0xef, 0x5c, 0x4c, 0x7b, 0x54, 0xd9,
                0xc6, 0x66, 0xab, 0xf4, 0x2f, 0xdf, 0xa8, 0x39, 0x44, 0x8b, 0x57, 0x9f, 0x65, 0x07,
                0x41, 0xd0, 0x6d, 0x97,
            ]
        );
        assert_ne!(server, client);
        assert!(constant_time_eq(&server, &server));
        assert!(!constant_time_eq(&server, &client));
    }

    #[test]
    fn strict_json_rejects_duplicate_keys_and_trailing_values() {
        assert!(strict_json_value(br#"{"a":1,"a":2}"#).is_err());
        assert!(strict_json_value(br#"{"a":1} {}"#).is_err());
    }

    #[test]
    fn strict_json_preserves_numeric_fields_and_literal_serde_marker_objects() {
        let parsed = strict_json_value(
            br#"{"timeout_seconds":6.0,"fraction":0.125,"maximum":1208925819614629174706177,"literal":{"$serde_json::private::Number":"123"}}"#,
        )
        .unwrap();
        assert_eq!(parsed["timeout_seconds"].as_f64(), Some(6.0));
        assert_eq!(parsed["fraction"].as_f64(), Some(0.125));
        assert_eq!(
            parsed["maximum"].as_number().unwrap().as_str(),
            "1208925819614629174706177"
        );
        assert_eq!(parsed["literal"]["$serde_json::private::Number"], "123");
        assert!(strict_json_value(br#"{"value":1e999}"#).is_err());
        assert!(strict_json_value(br#"{"name":1,"name":2}"#).is_err());
    }

    #[test]
    fn strict_json_rejects_deep_and_wide_values() {
        let deep = format!(
            "{}0{}",
            "[".repeat(strict_json::TEST_MAX_JSON_DEPTH + 2),
            "]".repeat(strict_json::TEST_MAX_JSON_DEPTH + 2)
        );
        assert!(strict_json_value(deep.as_bytes()).is_err());
        let wide = format!(
            "[{}]",
            std::iter::repeat_n("0", strict_json::TEST_MAX_JSON_COLLECTION_ITEMS + 1)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(strict_json_value(wide.as_bytes()).is_err());
    }

    #[test]
    fn overload_response_is_constant_and_retryable() {
        assert_eq!(
            resident_protocol::error_response("native_overloaded", true),
            b"{\"error\":\"native_overloaded\",\"retryable\":true}".to_vec()
        );
    }

    #[test]
    fn resident_hmac_changes_with_nonce() {
        let token = [3u8; AUTH_TOKEN_BYTES];
        let mut first_nonce = [1u8; AUTH_NONCE_BYTES];
        let second_nonce = [2u8; AUTH_NONCE_BYTES];
        let first = hmac_sha256(&token, SERVER_PROOF_LABEL, &first_nonce);
        let second = hmac_sha256(&token, SERVER_PROOF_LABEL, &second_nonce);
        assert_ne!(first, second);
        first_nonce[0] ^= 1;
        assert_ne!(first, hmac_sha256(&token, SERVER_PROOF_LABEL, &first_nonce));
    }

    #[test]
    fn resident_worker_pools_scale_within_bounds() {
        let evaluation = super::evaluation_workers();
        let auth = super::auth_workers();
        assert!((EVALUATION_WORKERS..=32).contains(&evaluation));
        assert!((AUTH_WORKERS..=8).contains(&auth));
        assert!((EVALUATION_QUEUE_CAPACITY..=64).contains(&super::evaluation_queue_capacity()));
        assert!(
            (AUTH_QUEUE_CAPACITY..=AUTH_QUEUE_CAPACITY_MAX).contains(&super::auth_queue_capacity())
        );
    }
}
