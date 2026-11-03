//! `release-manifest-verify --stdin`: verify a machine runtime's signed
//! release manifest for the Python integrity and lifecycle surfaces.
//!
//! `release_manifest_verify` does the verification; this command only frames
//! the caller's expectations and writes the verdict back as JSON.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::release_manifest_verify::{verify_release_manifest, Expectations, Verification, LIMITS};

const SCHEMA: &str = "release-manifest-verify.v1";
// A managed policy is bounded at 1 MiB, so its release keys fit well inside.
const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    manifest_path: PathBuf,
    runtime_root: PathBuf,
    /// Key id to the raw Ed25519 public key, hex encoded.
    #[serde(default)]
    trusted_keys: BTreeMap<String, String>,
    require_signature: bool,
    #[serde(default)]
    expected_platform: Option<String>,
    #[serde(default)]
    expected_architecture: Option<String>,
    #[serde(default)]
    expected_owner_uid: Option<u32>,
    #[serde(default)]
    expected_installer_identity: Option<String>,
    #[serde(default)]
    expected_native_version: Option<String>,
    #[serde(default)]
    minimum_version: Option<String>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "release-manifest-verify"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "release_manifest_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("release_manifest_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| "release_manifest_request_invalid".to_owned())?;
    if request.schema != SCHEMA {
        return Err("release_manifest_request_invalid".to_owned());
    }
    let verification = respond(request)?;
    serde_json::to_vec(&verification_json(&verification))
        .map_err(|_| "release_manifest_response_encode_failed".to_owned())
}

fn respond(request: Request) -> Result<Verification, String> {
    let trusted_keys = request
        .trusted_keys
        .into_iter()
        .map(|(key_id, key)| hex::decode(key).map(|key| (key_id, key)))
        .collect::<Result<_, _>>()
        .map_err(|_| "release_manifest_request_invalid".to_owned())?;
    let expected = Expectations {
        trusted_keys,
        require_signature: request.require_signature,
        platform: request.expected_platform,
        architecture: request.expected_architecture,
        owner_uid: request.expected_owner_uid,
        installer_identity: request.expected_installer_identity,
        native_version: request.expected_native_version,
        minimum_version: request.minimum_version,
    };
    Ok(verify_release_manifest(
        &request.manifest_path,
        &request.runtime_root,
        &expected,
        &LIMITS,
    ))
}

fn verification_json(verification: &Verification) -> Value {
    json!({
        "status": verification.status,
        "reason_code": verification.reason_code,
        "version": verification.version,
        "build_id": verification.build_id,
        "installer_identity": verification.installer_identity,
        "signature_state": verification.signature_state,
    })
}
