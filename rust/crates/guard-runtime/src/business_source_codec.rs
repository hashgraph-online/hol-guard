//! Local whole-source codec only. No state access, approval or installation.

use guard_policy_snapshot::business_source_anchor::{
    sign_business_source_anchor, verify_business_source_anchor, BusinessSourcePhase,
};
use guard_policy_snapshot::business_source_authority::{
    sign_business_source, verify_business_source, MAX_BUSINESS_SOURCE_AUTHORITY_BYTES,
};
use guard_policy_snapshot::canonical_json_bytes;
use serde::Deserialize;
use serde_json::json;
use std::io::Read;
use zeroize::{Zeroize, Zeroizing};

const ERROR: &str = "native_business_source_codec_invalid";
// A JSON string containing canonical JSON needs space for escaped quotes and
// backslashes. Bound both the wire envelope and its decoded record separately.
const MAX_REQUEST_BYTES: usize = 2 * MAX_BUSINESS_SOURCE_AUTHORITY_BYTES + 4096;

#[derive(Deserialize)]
struct PublisherKey([u8; 32]);

impl Drop for PublisherKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildRequest {
    schema: String,
    version: u16,
    verifier_key: PublisherKey,
    mutation_revision: u64,
    import_mode: String,
    source_json: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyRequest {
    schema: String,
    version: u16,
    verifier_key: PublisherKey,
    record_json: String,
    #[serde(default)]
    retained_floor: Option<guard_policy_snapshot::business_source_authority::BusinessSourceFloor>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildAnchorRequest {
    schema: String,
    version: u16,
    verifier_key: PublisherKey,
    record_json: String,
    phase: BusinessSourcePhase,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyAnchorRequest {
    schema: String,
    version: u16,
    verifier_key: PublisherKey,
    anchor_json: String,
}

fn read_request(mut reader: impl Read) -> Result<(Zeroizing<Vec<u8>>, usize), String> {
    // Fixed allocation keeps key bytes out of abandoned growth allocations.
    let mut bytes = Zeroizing::new(vec![0u8; MAX_REQUEST_BYTES + 1]);
    let mut filled = 0;
    while filled < bytes.len() {
        match reader.read(&mut bytes[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ERROR.into()),
        }
    }
    if filled > MAX_REQUEST_BYTES {
        return Err(ERROR.into());
    }
    Ok((bytes, filled))
}

fn build_from_reader(reader: impl Read) -> Result<Vec<u8>, String> {
    let (bytes, filled) = read_request(reader)?;
    let request: BuildRequest =
        serde_json::from_slice(&bytes[..filled]).map_err(|_| ERROR.to_owned())?;
    if request.schema != "guard.business-source-build.v1"
        || request.version != 1
        || request.import_mode != "replace"
        || request.source_json.len() > MAX_BUSINESS_SOURCE_AUTHORITY_BYTES
    {
        return Err(ERROR.into());
    }
    // The key is not passed through Value or a logging/serialization type.
    // Parse only source content with the runtime's duplicate-member boundary.
    let source =
        crate::strict_json::parse(request.source_json.as_bytes()).map_err(|_| ERROR.to_owned())?;
    if canonical_json_bytes(&source).map_err(|_| ERROR.to_owned())?
        != request.source_json.as_bytes()
    {
        return Err(ERROR.into());
    }
    sign_business_source(&source, request.mutation_revision, &request.verifier_key.0)
        .map_err(|_| ERROR.to_owned())
}

fn verify_from_reader(reader: impl Read) -> Result<Vec<u8>, String> {
    let (bytes, filled) = read_request(reader)?;
    let request: VerifyRequest =
        serde_json::from_slice(&bytes[..filled]).map_err(|_| ERROR.to_owned())?;
    if request.schema != "guard.business-source-verify.v1" || request.version != 1 {
        return Err(ERROR.into());
    }
    let source = verify_business_source(request.record_json.as_bytes(), &request.verifier_key.0)
        .map_err(|_| ERROR.to_owned())?;
    if let Some(floor) = request.retained_floor.as_ref() {
        source
            .check_retained_floor(floor)
            .map_err(|_| ERROR.to_owned())?;
    }
    let response = json!({
        "schema":"guard.business-source-verification.v1", "version":1,
        "authentication":"provided_key_verified", "approval":"not_checked",
        "currentness":"not_checked", "installed":false,
        "source_digest":source.compiled().source_digest(),
        "record_digest":source.record_digest(), "mutation_revision":source.mutation_revision(),
        "business_policy":source.compiled().binding(), "retained_identity":source.floor(),
    });
    let bytes = canonical_json_bytes(&response).map_err(|_| ERROR.to_owned())?;
    if bytes.len() > MAX_BUSINESS_SOURCE_AUTHORITY_BYTES {
        return Err(ERROR.into());
    }
    Ok(bytes)
}

fn build_anchor_from_reader(reader: impl Read) -> Result<Vec<u8>, String> {
    let (bytes, filled) = read_request(reader)?;
    let request: BuildAnchorRequest =
        serde_json::from_slice(&bytes[..filled]).map_err(|_| ERROR.to_owned())?;
    if request.schema != "guard.business-source-anchor-build.v1" || request.version != 1 {
        return Err(ERROR.into());
    }
    let source = verify_business_source(request.record_json.as_bytes(), &request.verifier_key.0)
        .map_err(|_| ERROR.to_owned())?;
    sign_business_source_anchor(&source, request.phase, &request.verifier_key.0)
        .map_err(|_| ERROR.to_owned())
}

fn verify_anchor_from_reader(reader: impl Read) -> Result<Vec<u8>, String> {
    let (bytes, filled) = read_request(reader)?;
    let request: VerifyAnchorRequest =
        serde_json::from_slice(&bytes[..filled]).map_err(|_| ERROR.to_owned())?;
    if request.schema != "guard.business-source-anchor-verify.v1" || request.version != 1 {
        return Err(ERROR.into());
    }
    let anchor =
        verify_business_source_anchor(request.anchor_json.as_bytes(), &request.verifier_key.0)
            .map_err(|_| ERROR.to_owned())?;
    canonical_json_bytes(&json!({
        "schema":"guard.business-source-anchor-verification.v1", "version":1,
        "authentication":"provided_key_verified", "approval":"not_checked",
        "currentness":"not_checked", "retention":"not_checked", "installed":false,
        "anchor_digest":anchor.anchor_digest(), "phase":anchor.phase(), "retained_identity":anchor.floor(),
    })).map_err(|_| ERROR.to_owned())
}

pub(crate) fn is_command(command: &str) -> bool {
    matches!(
        command,
        "business-source-build"
            | "business-source-verify"
            | "business-source-anchor-build"
            | "business-source-anchor-verify"
    )
}

pub(crate) fn run_command(command: &str, reader: impl Read) -> Result<Vec<u8>, String> {
    match command {
        "business-source-build" => build_from_reader(reader),
        "business-source-verify" => verify_from_reader(reader),
        "business-source-anchor-build" => build_anchor_from_reader(reader),
        "business-source-anchor-verify" => verify_anchor_from_reader(reader),
        _ => Err(ERROR.into()),
    }
}

#[cfg(test)]
#[path = "business_source_codec_tests.rs"]
mod tests;
