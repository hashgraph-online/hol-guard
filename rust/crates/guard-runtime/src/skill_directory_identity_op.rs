//! `SkillDirectoryIdentity` — the native identity and discovery of agent skill
//! directories.
//!
//! The resident walks the tree itself. A caller supplies only absolute paths
//! and resource ceilings and gets back a complete digest or a typed incomplete
//! state; neither side ever recomputes the other's digest.

use std::path::Path;

use guard_contracts::{
    SkillDirectoryCommandV1, SkillDirectoryIdentityRequestV1, SkillDirectoryIdentityResultV1,
    SKILL_DIRECTORY_IDENTITY_REQUEST_SCHEMA, SKILL_DIRECTORY_IDENTITY_RESULT_SCHEMA,
};
use serde_json::Value;

const PATH_INVALID: &str = "native_skill_directory_identity_path_invalid";
const PAYLOAD_INVALID: &str = "native_skill_directory_identity_payload_invalid";

pub(crate) fn evaluate_skill_directory_identity_request(
    request: &SkillDirectoryIdentityRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != SKILL_DIRECTORY_IDENTITY_REQUEST_SCHEMA {
        return Err("native_skill_directory_identity_schema_mismatch".to_owned());
    }
    let (status, code, payload) = match decide(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code.to_owned(), None),
    };
    crate::resident_protocol::encode_response(&SkillDirectoryIdentityResultV1 {
        schema: SKILL_DIRECTORY_IDENTITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

fn request_digest(request: &SkillDirectoryIdentityRequestV1) -> Result<String, String> {
    let material = serde_json::to_value(request)
        .map_err(|_| "native_skill_directory_identity_request_invalid".to_owned())?;
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| "native_skill_directory_identity_request_invalid".to_owned())?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

fn require_absolute(value: &str) -> Result<&Path, &'static str> {
    let path = Path::new(value);
    if value.is_empty() || value.contains('\0') || !path.is_absolute() {
        return Err(PATH_INVALID);
    }
    Ok(path)
}

fn decide(request: &SkillDirectoryIdentityRequestV1) -> Result<Value, &'static str> {
    require_absolute(&request.guard_home)?;
    match &request.command {
        SkillDirectoryCommandV1::Inspect {
            skill_document,
            scope_root,
            limits,
        } => {
            let identity = crate::skill_identity_inspect::inspect_skill_directory(
                require_absolute(skill_document)?,
                require_absolute(scope_root)?,
                limits,
            );
            serde_json::to_value(identity).map_err(|_| PAYLOAD_INVALID)
        }
        SkillDirectoryCommandV1::Discover { skill_root, limits } => {
            let discovery = crate::skill_identity_discovery::discover_skill_documents(
                require_absolute(skill_root)?,
                limits,
            );
            serde_json::to_value(discovery).map_err(|_| PAYLOAD_INVALID)
        }
    }
}

#[cfg(test)]
#[path = "skill_directory_identity_op_tests.rs"]
mod tests;
