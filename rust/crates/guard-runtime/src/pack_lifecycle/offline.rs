//! Explicit control-plane transfer. No authority is inferred from a cache or ZIP.
use super::*;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

mod archive;
mod cleanup;
mod copy;
mod graph;
#[cfg(test)]
mod tests;
const LIMIT: usize = 512 * 1024 * 1024;
type Result<T> = std::result::Result<T, String>;
fn invalid() -> String {
    "offline_pack_invalid".into()
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    if guard_secure_fs::contains_symlink_component(path) {
        return Err(invalid());
    }
    let bytes = guard_secure_fs::read_stable(path, maximum, false)
        .map_err(|_| invalid())?
        .bytes;
    if guard_secure_fs::contains_symlink_component(path) {
        return Err(invalid());
    }
    Ok(bytes)
}
fn decode(bytes: &[u8]) -> Result<Value> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let canonical = guard_policy_snapshot::canonical_json_bytes(&value).map_err(|_| invalid())?;
    if bytes != canonical && bytes.strip_suffix(b"\n") != Some(canonical.as_slice()) {
        return Err(invalid());
    }
    Ok(value)
}

pub(super) fn evaluate(input: &Value) -> Result<Value> {
    if input["operation"] == "expired-leases" {
        let now = input["now"]
            .as_f64()
            .filter(|t| t.is_finite() && *t >= 0.0)
            .ok_or_else(invalid)?;
        let items = input["expires"]
            .as_array()
            .filter(|a| a.len() <= 136)
            .ok_or_else(invalid)?;
        let mut expired = Vec::new();
        for (index, item) in items.iter().enumerate() {
            if item.is_null() {
                continue;
            }
            let expiry = item
                .as_f64()
                .filter(|t| t.is_finite() && *t >= 0.0)
                .ok_or_else(invalid)?;
            if expiry <= now {
                expired.push(index);
            }
        }
        return Ok(json!({"expired":expired}));
    }
    if input["operation"] == "cleanup" {
        return cleanup::run(input);
    }
    if input["operation"] == "archive" {
        return archive::admit(input);
    }
    let directory = Path::new(input["directory"].as_str().ok_or_else(invalid)?);
    // The production adapter obtains these from fixed verified factories only.
    // Installed compatibility is exact, never a fabricated fresh remote 0.0 Root.
    let data = input["release_data"].as_str().ok_or_else(invalid)?;
    let root: Value = serde_json::from_str(data).map_err(|_| invalid())?;
    if input["profile"] == "installed" {
        super::release::identity(input)?;
    } else if input["profile"] == "remote" {
        let now = input["now"].as_u64().ok_or_else(invalid)?;
        if root["schema"] != "guard.extension-distribution.v2"
            || root["issued_at"].as_u64().is_none_or(|t| t > now)
            || root["expires_at"].as_u64().is_none_or(|t| t <= now)
            || root["engine"] != guard_command::source_cli::compiler_info()["implementation_digest"]
        {
            return Err("offline_pack_fresh_authority_required".into());
        }
    } else {
        return Err("offline_pack_authority_required".into());
    }
    if matches!(input["operation"].as_str(), Some("import" | "import-copy")) {
        let exported = read(&directory.join("root.json"), 65536)?;
        if exported != data.as_bytes() {
            return Err("offline_pack_exact_release_required".into());
        }
    }
    let mut graph = graph::Graph::new(directory);
    graph
        .walk(&root, 0)
        .map_err(|code| format!("offline_pack_graph:{code}"))?;
    if !graph.needs.is_empty() || !graph.ingests.is_empty() {
        return Ok(json!({"needs":graph.needs,"ingests":graph.ingests}));
    }
    if graph.unavailable {
        return Err("offline_pack_uncached_unavailable".into());
    }
    graph
        .validate(&root)
        .map_err(|code| format!("offline_pack_admission:{code}"))?;
    if matches!(
        input["operation"].as_str(),
        Some("export-copy" | "import-copy")
    ) {
        return copy::batch(
            input,
            directory,
            data.as_bytes(),
            &graph.objects,
            &graph.archives,
        );
    }
    Ok(
        json!({"complete":true,"root":hash(data.as_bytes()),"objects":graph.objects,
        "archives":graph.archives,"bytes":graph.total,"extensions":root["policy"]["root"]["extensions"]}),
    )
}
