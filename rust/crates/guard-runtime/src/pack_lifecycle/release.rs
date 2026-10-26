//! Reuse the installed package trust boundary, never a request-supplied path.
//! The adapter reads only the fixed installed manifests and verified Root.
use super::*;
use sha2::{Digest, Sha256};

pub(super) fn identity(input: &Value) -> Result<Identity, String> {
    let runtime = &input["runtime_manifest"];
    let compiler = &input["compiler_manifest"];
    let data = input["release_data"]
        .as_str()
        .ok_or("pack_lifecycle_release_missing")?;
    if data.is_empty() || data.len() > 65536 {
        return Err("pack_lifecycle_release_invalid".into());
    }
    let root: Value = serde_json::from_str(data).map_err(|_| "pack_lifecycle_release_invalid")?;
    if runtime["schema"] != "hol-guard-native-runtime.v1"
        || compiler["schema"] != "hol-guard-native-source-compiler.v2"
        || runtime["protocol_version"] != 1
        || compiler["protocol_version"] != 1
        || root["schema"] != "guard.command-pack-bundle.v1"
        || root["publication_id"] != "0.0"
    {
        return Err("pack_lifecycle_release_invalid".into());
    }
    for field in [
        "source_sha",
        "package_version",
        "target",
        "platform_tag",
        "command_pack_bundle",
    ] {
        if runtime[field].is_null() || runtime[field] != compiler[field] {
            return Err("pack_lifecycle_release_binding_invalid".into());
        }
    }
    let path = std::env::current_exe().map_err(|_| "pack_lifecycle_executable_unavailable")?;
    let binary = std::fs::read(path).map_err(|_| "pack_lifecycle_executable_unavailable")?;
    if binary.len() > 128 * 1024 * 1024 {
        return Err("pack_lifecycle_executable_invalid".into());
    }
    let digest = hex::encode(Sha256::digest(&binary));
    if runtime["runtime_sha256"] != digest
        || compiler["compiler_sha256"] != digest
        || runtime["runtime_size"] != binary.len()
        || compiler["compiler_size"] != binary.len()
    {
        return Err("pack_lifecycle_executable_binding_invalid".into());
    }
    let descriptor = &runtime["command_pack_bundle"];
    let engine = &guard_command::source_cli::compiler_info()["implementation_digest"];
    let root_digest = hex::encode(Sha256::digest(data.as_bytes()));
    if descriptor["sha256"] != root_digest
        || descriptor["length"] != data.len()
        || descriptor["source_sha"] != runtime["source_sha"]
        || root["source_sha"] != runtime["source_sha"]
        || descriptor["engine"] != *engine
        || compiler["implementation_digest"] != *engine
        || root["engine"] != *engine
    {
        return Err("pack_lifecycle_release_binding_invalid".into());
    }
    let result = Identity {
        profile: "installed".into(),
        source: runtime["source_sha"]
            .as_str()
            .ok_or("pack_lifecycle_release_invalid")?
            .into(),
        engine: engine
            .as_str()
            .ok_or("pack_lifecycle_release_invalid")?
            .into(),
        root: root_digest,
        version: runtime["package_version"]
            .as_str()
            .ok_or("pack_lifecycle_release_invalid")?
            .into(),
        authority: root["authority_epoch"]
            .as_u64()
            .ok_or("pack_lifecycle_release_invalid")?,
        revocation: root["policy"]["revocations"]["epoch"]
            .as_u64()
            .ok_or("pack_lifecycle_release_invalid")?,
    };
    result.validate()?;
    Ok(result)
}
