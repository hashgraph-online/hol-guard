//! Config-derived deterministic conformance tuple, never selected by records.

use crate::{EvidenceError, Result};
use serde_json::{json, Map, Value};

const MCP_IMAGE_ID: &str =
    "sha256:827eaec482942aa5805beac1a75afd755b0daebade43024883b7d1637c27e52d";

pub(crate) fn expected_runtime(config: &Value) -> Result<Value> {
    let options = &config["runtime"];
    let assets = &config["assets"];
    let private = options["private_cell"]
        .as_object()
        .ok_or(EvidenceError::Invalid("private-cell config missing"))?;
    let mut cell = Map::new();
    cell.insert(
        "artifact_manifest_sha256".into(),
        assets["private_cell"]["sha256"].clone(),
    );
    for name in [
        "initializer_sha256",
        "native_sha256",
        "runtime_tree_digest",
        "idmap_runtime",
        "cpu_profile",
    ] {
        cell.insert(
            name.into(),
            private
                .get(name)
                .cloned()
                .ok_or(EvidenceError::Invalid("private-cell tuple missing"))?,
        );
    }
    let mut expected = json!({
        "source_sha":options["guard_source_sha"],
        "prefix_digest":assets["guard_prefix"]["sha256"],
        "bwrap_sha256":options["guard_bwrap_sha256"],
        "executor_image_id":options["guard_executor_image_id"],
        "mcp_image_id":MCP_IMAGE_ID,
        "private_cell":Value::Object(cell),
    });
    if let Some(version) = options.get("guard_package_version") {
        expected["package_version"] = version.clone();
    }
    Ok(expected)
}
