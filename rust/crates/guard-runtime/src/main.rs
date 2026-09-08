#![forbid(unsafe_code)]

mod approval;
mod edge;
mod hardening;
mod managed_resident;
mod native_hook_receipt;
mod oneshot;
mod policy_enforcement;
mod policy_store;
mod resident_client;
mod resident_process_identity;
mod resident_protocol;
mod resident_state;
mod resident_state_encoding;
mod resident_transport;
mod resident_transport_service;
mod strict_json;

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
const AUTH_QUEUE_CAPACITY: usize = 16;
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
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [command] if command == "capabilities" => write_json(&capabilities()),
        [command, flag] if command == "capabilities" && flag == "--json" => {
            write_json(&capabilities())
        }
        [command] if command == "rule-contract" => write_json(&guard_rule_contract::rule_contract()),
        [command, flag] if command == "rule-contract" && flag == "--json" => {
            write_json(&guard_rule_contract::rule_contract())
        }
        [command] if command == "self-test" => {
            write_json(&serde_json::json!({"ok": true, "capabilities": capabilities()}))
        }
        [command, flag] if command == "self-test" && flag == "--json" => {
            write_json(&serde_json::json!({"ok": true, "capabilities": capabilities()}))
        }
        [command, flag] if command == "hook" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            let response = oneshot::evaluate_hook_bytes(&bytes)?;
            write_bytes_response(&response)
        }
        [command, state_flag, state_dir]
            if command == "migrate-policy"
                && state_flag == "--state-dir" =>
        {
            let runtime_identity = resident_state::runtime_digest()?;
            policy_store::PolicySnapshotStore::migrate_legacy_state(
                std::path::Path::new(state_dir),
                &runtime_identity,
            )
        }
        [command, state_flag, state_dir, record_flag, record_path]
            if command == "enroll-approval-authority"
                && state_flag == "--state-dir"
                && record_flag == "--record" =>
        {
            policy_store::approval_authority::install_record(
                std::path::Path::new(state_dir),
                std::path::Path::new(record_path),
            )
        }
        [command, state_flag, state_dir, record_flag, record_path]
            if command == "enroll-approval-v4-authority"
                && state_flag == "--state-dir"
                && record_flag == "--record" =>
        {
            policy_store::approval_v4_authority::install_record(
                std::path::Path::new(state_dir),
                std::path::Path::new(record_path),
            )
        }
        [command, state_flag, state_dir, rp_flag, rp_id, origin_flag, origin]
            if command == "prepare-approval-v4-enrollment"
                && state_flag == "--state-dir"
                && rp_flag == "--rp-id"
                && origin_flag == "--origin" =>
        {
            let request = policy_store::approval_v4_authority::prepare_enrollment(
                std::path::Path::new(state_dir),
                rp_id,
                origin,
            )?;
            write_bytes_response(&request)
        }
        [command, state_flag, state_dir]
            if command == "prepare-approval-enrollment" && state_flag == "--state-dir" =>
        {
            let request = policy_store::approval_authority::prepare_enrollment(
                std::path::Path::new(state_dir),
            )?;
            write_bytes_response(&request)
        }
        [command, flag, state_dir]
            if matches!(command.as_str(), "hook-client" | "resident-client")
                && flag == "--stdin" =>
        {
            let bytes = read_stdin_bounded()?;
            let timeout = managed_resident::client_timeout(&bytes);
            let response = managed_resident::client_request(
                std::path::Path::new(state_dir),
                &bytes,
                timeout,
            )?;
            write_bytes_response(&response)
        }
        [command, flag, state_dir]
            if command == "resident-client-stream" && flag == "--stdin" =>
        {
            managed_resident::client_stream(std::path::Path::new(state_dir))
        }
        [command, flag, state_dir] if command == "resident-stop" && flag == "--state-dir" => {
            managed_resident::stop_managed(std::path::Path::new(state_dir))
        }
        [command, flag] if command == "command-model" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            let response = oneshot::evaluate_command_model_bytes(&bytes)?;
            write_bytes_response(&response)
        }
        [command, flag] if command == "pre-tool" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            let response = oneshot::evaluate_pre_tool_bytes(&bytes)?;
            write_bytes_response(&response)
        }
        [command, flag, path] if command == "serve" && flag == "--socket" => serve(path),
        [command, flag, address] if command == "serve" && flag == "--tcp-loopback" => {
            serve_loopback(address)
        }
        [
            command,
            state_flag,
            state_dir,
            generation_flag,
            generation,
            owner_flag,
            owner_process_id,
            digest_flag,
            digest,
        ]
            if command == "serve-managed"
                && state_flag == "--state-dir"
                && generation_flag == "--generation"
                && owner_flag == "--owner-process-id"
                && digest_flag == "--runtime-sha256" =>
        {
            managed_resident::serve_managed(
                std::path::Path::new(state_dir),
                managed_resident::parse_generation(generation)?,
                managed_resident::parse_process_id(owner_process_id)?,
                digest,
            )
        }
        [command, state_flag, state_dir, generation_flag, generation, digest_flag, digest]
            if command == "supervise-managed"
                && state_flag == "--state-dir"
                && generation_flag == "--generation"
                && digest_flag == "--runtime-sha256" =>
        {
            managed_resident::supervise_managed(
                std::path::Path::new(state_dir),
                managed_resident::parse_generation(generation)?,
                digest,
            )
        }
        [
            command,
            state_flag,
            state_dir,
            generation_flag,
            generation,
            owner_flag,
            owner_process_id,
            digest_flag,
            digest,
        ]
            if command == "supervise-managed"
                && state_flag == "--state-dir"
                && generation_flag == "--generation"
                && owner_flag == "--owner-process-id"
                && digest_flag == "--runtime-sha256" =>
        {
            managed_resident::supervise_managed_for_owner(
                std::path::Path::new(state_dir),
                managed_resident::parse_generation(generation)?,
                digest,
                managed_resident::parse_process_id(owner_process_id)?,
            )
        }
        _ => Err(
            "usage: hol-guard-runtime capabilities --json | rule-contract --json | self-test --json | hook --stdin | migrate-policy --state-dir STATE_DIR | prepare-approval-enrollment --state-dir STATE_DIR | enroll-approval-authority --state-dir STATE_DIR --record RECORD | prepare-approval-v4-enrollment --state-dir STATE_DIR --rp-id RP_ID --origin ORIGIN | enroll-approval-v4-authority --state-dir STATE_DIR --record RECORD | hook-client --stdin STATE_DIR | resident-client --stdin STATE_DIR | resident-client-stream --stdin STATE_DIR | command-model --stdin | pre-tool --stdin | serve --socket PATH | serve --tcp-loopback 127.0.0.1:PORT | resident-stop --state-dir STATE_DIR | serve-managed --state-dir STATE_DIR --generation N --owner-process-id PID --runtime-sha256 SHA | supervise-managed --state-dir STATE_DIR --generation N --owner-process-id PID --runtime-sha256 SHA"
                .into(),
        ),
    }
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
}
