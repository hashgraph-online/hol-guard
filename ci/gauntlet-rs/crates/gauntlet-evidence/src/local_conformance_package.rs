//! Read-only opening of a source-bound local executor conformance package.
//! Signed producer reports are inspected, never promoted to a Guard verdict.

use crate::crypto::{decode_hex, is_sha256, sha256};
use crate::payload::exact_keys;
use crate::{
    verify_control_reported_relations, verify_control_reported_tail, EvidenceError, Result,
};
use gauntlet_contracts::canonicalize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const MAX_PACKAGE_BYTES: usize = 8 * 1024 * 1024;
const ROLES: [&str; 5] = ["boundary", "cancel", "input-binding", "success", "timeout"];
const REQUIREMENTS: [&str; 12] = [
    "identity",
    "separation",
    "task-custody",
    "readonly-inputs",
    "network",
    "syscalls-devices",
    "proc-paths",
    "resources",
    "input-output-replay",
    "timeout",
    "cancellation",
    "cleanup",
];

// The exact Python local_executor_conformance.EXECUTION_SOURCES set at the
// integration source pin. Additions require a reviewed schema/source update.
pub const EXECUTION_SOURCES: [&str; 50] = [
    "builtin_hook_supervisor.py",
    "contained_exec_relay.py",
    "contained_output_binding.py",
    "contained_request_file.py",
    "developer_product_runtime.py",
    "developer_sdk_gate.py",
    "developer_pilot.py",
    "developer_pilot_services.py",
    "developer_resources.py",
    "private_cell_factory.py",
    "private_cell_hook_plane.py",
    "product_cell_actor.py",
    "product_cell_idmap.py",
    "product_cell_image.py",
    "product_cell_layout.py",
    "product_cell_protocol.py",
    "product_cell_supervisor.py",
    "product_cell_system.py",
    "product_cell_task_mounts.py",
    "product_exec_gate.py",
    "product_vm_network.py",
    "product_vm_rootfs.py",
    "product_vm_seccomp.py",
    "native_product_container.py",
    "native_builtin_plane.py",
    "native_mcp_supervisor.py",
    "mcp_task_context.py",
    "service_supervisor.py",
    "mcp_server.py",
    "mcp_protocol_profiles.py",
    "mcp_protocol_campaign.py",
    "developer_budget.py",
    "developer_model_relay.py",
    "mcp_agent_profile.py",
    "runtime_bundle.py",
    "vm_bridge_frames.py",
    "vm_bridge_io.py",
    "vm_bridge_rpc.py",
    "vm_product_operations.py",
    "product_version.py",
    "private_cell_readiness.py",
    "release_mcp_entry.py",
    "release_hook_entry.py",
    "builtin_guard_bridge.ts",
    "private_cell_sdk_conformance.ts",
    "developer_omp_episode.ts",
    "mcp_agent_surfaces.ts",
    "service_relay.py",
    "product_vm.apparmor",
    "product_vm_seccomp_oci_v1.json",
];

const INVALID: EvidenceError = EvidenceError::Invalid("invalid local conformance package");
const SOURCE: EvidenceError =
    EvidenceError::Invalid("execution source differs from outside controller tree");
const CONTROL: EvidenceError = EvidenceError::Invalid("control differs from pinned package anchor");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalConformancePackageShadow {
    pub package_sha256: String,
    pub source_count: usize,
    pub role_session_ids: BTreeMap<String, String>,
    pub contained_routes: usize,
    pub output_bindings: usize,
    pub public_prompt_relations: usize,
    pub contained_cli_results: usize,
    pub public_inputs_verified: bool,
    pub outside_control_keys_matched: bool,
    pub execution_eligible: bool,
}

impl LocalConformancePackageShadow {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-local-conformance-package-shadow.v1",
            "package_sha256":self.package_sha256,
            "execution_source_count":self.source_count,
            "control_roles":self.role_session_ids.keys().collect::<Vec<_>>(),
            "distinct_signed_sessions":self.role_session_ids.len(),
            "native_review_summaries_recomputed":self.role_session_ids.len(),
            "contained_routes_recomputed":self.contained_routes,
            "output_bindings_recomputed":self.output_bindings,
            "public_prompt_relations_recomputed":self.public_prompt_relations,
            "contained_cli_results_checked":self.contained_cli_results,
            "cancel_partial_relation_checked":true,
            "public_inputs_verified":self.public_inputs_verified,
            "signed_openings_checked":true,
            "outside_control_keys_matched":self.outside_control_keys_matched,
            "independent_kernel_sdk_effects_verified":false,
            "qualification_eligible":false,
            "execution_eligible":false,
        })
    }
}

fn canonical_value(value: &Value) -> Result<Vec<u8>> {
    canonicalize(&serde_json::to_vec(value).map_err(|_| INVALID)?).map_err(|_| INVALID)
}

fn exact_set(value: &Value, names: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == names.len() && names.iter().all(|name| object.contains_key(*name))
    })
}

fn verify_review(review: &Value) -> Result<()> {
    if !exact_keys(
        review,
        &[
            "schema",
            "reviewer_role",
            "verdict",
            "requirements",
            "document",
            "document_sha256",
        ],
    ) || review["schema"] != "local-executor-equivalence-review.v1"
        || review["reviewer_role"] != "implementation-author"
        || review["verdict"] != "scoped-local-conformance"
        || !exact_set(&review["requirements"], &REQUIREMENTS)
    {
        return Err(EvidenceError::Invalid(
            "local security-equivalence review missing",
        ));
    }
    let requirements = review["requirements"].as_object().ok_or(INVALID)?;
    if !requirements.values().all(|value| {
        value
            .as_str()
            .is_some_and(|text| !text.is_empty() && text.len() <= 4096)
    }) {
        return Err(EvidenceError::Invalid(
            "local security-equivalence review missing",
        ));
    }
    let document = review["document"].as_str().ok_or(INVALID)?;
    if document.len() > 65_536
        || !is_sha256(review["document_sha256"].as_str().unwrap_or(""))
        || sha256(document.as_bytes()) != review["document_sha256"]
    {
        return Err(EvidenceError::Invalid(
            "local security-equivalence review digest differs",
        ));
    }
    Ok(())
}

/// Compare the whole package with *outside* pins and open its five signed
/// records. The source hashes must be read from a separately pinned controller
/// tree, and `expected_runtime` must be derived from an outside-pinned config.
/// The existing control tail does not authenticate SDK, Native or kernel effects.
pub fn verify_local_conformance_package_ineligible(
    raw: &[u8],
    outside_package_sha256: &str,
    expected_runtime: &Value,
    observed_platform: &Value,
    outside_source_hashes: &BTreeMap<String, String>,
    observed_public_assets: Option<&Value>,
) -> Result<LocalConformancePackageShadow> {
    verify_package(
        raw,
        outside_package_sha256,
        expected_runtime,
        observed_platform,
        outside_source_hashes,
        observed_public_assets,
        None,
    )
}

/// Require each signed control to use a public key supplied by a distinct
/// caller. The map must contain exactly the five deterministic conformance
/// roles; a key repeated in the producer's own package is not an outside pin.
pub fn verify_local_conformance_package_with_key_pins_ineligible(
    raw: &[u8],
    outside_package_sha256: &str,
    expected_runtime: &Value,
    observed_platform: &Value,
    outside_source_hashes: &BTreeMap<String, String>,
    observed_public_assets: Option<&Value>,
    outside_control_keys: &BTreeMap<String, String>,
) -> Result<LocalConformancePackageShadow> {
    verify_package(
        raw,
        outside_package_sha256,
        expected_runtime,
        observed_platform,
        outside_source_hashes,
        observed_public_assets,
        Some(outside_control_keys),
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_package(
    raw: &[u8],
    outside_package_sha256: &str,
    expected_runtime: &Value,
    observed_platform: &Value,
    outside_source_hashes: &BTreeMap<String, String>,
    observed_public_assets: Option<&Value>,
    outside_control_keys: Option<&BTreeMap<String, String>>,
) -> Result<LocalConformancePackageShadow> {
    if outside_control_keys.is_some_and(|keys| {
        keys.len() != ROLES.len()
            || keys.values().collect::<BTreeSet<_>>().len() != ROLES.len()
            || ROLES.iter().any(|role| {
                keys.get(*role)
                    .is_none_or(|key| !is_sha256(key) || decode_hex(key, 32).is_err())
            })
    }) {
        return Err(EvidenceError::Invalid(
            "exact outside control key pins required",
        ));
    }
    if raw.is_empty()
        || raw.len() > MAX_PACKAGE_BYTES
        || !is_sha256(outside_package_sha256)
        || sha256(raw) != outside_package_sha256
    {
        return Err(EvidenceError::Invalid(
            "conformance bytes differ from outside pin",
        ));
    }
    let canonical = canonicalize(raw).map_err(|_| INVALID)?;
    let package: Value = serde_json::from_slice(&canonical).map_err(|_| INVALID)?;
    if !exact_keys(
        &package,
        &[
            "schema",
            "scope",
            "qualification_eligible",
            "platform",
            "runtime",
            "public_assets",
            "execution_sources",
            "review",
            "controls",
        ],
    ) || package["schema"] != "local-executor-conformance.v1"
        || package["scope"] != "local-diagnostic-only"
        || package["qualification_eligible"] != false
    {
        return Err(EvidenceError::Invalid(
            "explicit local-only conformance required",
        ));
    }
    if &package["platform"] != observed_platform || &package["runtime"] != expected_runtime {
        return Err(EvidenceError::Invalid(
            "platform or runtime differs from outside pins",
        ));
    }
    let sources = package["execution_sources"].as_object().ok_or(SOURCE)?;
    if !exact_set(&package["execution_sources"], &EXECUTION_SOURCES)
        || outside_source_hashes.len() != EXECUTION_SOURCES.len()
        || EXECUTION_SOURCES.iter().any(|name| {
            let package_digest = sources.get(*name).and_then(Value::as_str);
            let outside_digest = outside_source_hashes.get(*name).map(String::as_str);
            package_digest.is_none_or(|digest| !is_sha256(digest) || Some(digest) != outside_digest)
        })
    {
        return Err(SOURCE);
    }
    verify_review(&package["review"])?;
    if !exact_set(&package["controls"], &ROLES)
        || !exact_set(&package["public_assets"], &["sdk", "bun"])
    {
        return Err(INVALID);
    }
    let mut role_session_ids = BTreeMap::new();
    let mut sessions = BTreeSet::new();
    let mut contained_routes = 0;
    let mut output_bindings = 0;
    let mut public_prompt_relations = 0;
    let mut contained_cli_results = 0;
    for role in ROLES {
        let row = &package["controls"][role];
        if !exact_keys(row, &["public_key", "record", "record_digest"]) {
            return Err(CONTROL);
        }
        let key_text = row["public_key"].as_str().ok_or(CONTROL)?;
        if !is_sha256(key_text) {
            return Err(CONTROL);
        }
        if outside_control_keys.is_some_and(|keys| keys[role] != key_text) {
            return Err(EvidenceError::Invalid(
                "control key differs from outside pin",
            ));
        }
        let key = decode_hex(key_text, 32).map_err(|_| CONTROL)?;
        let record = &row["record"];
        let record_digest = row["record_digest"]
            .as_str()
            .filter(|text| is_sha256(text))
            .ok_or(CONTROL)?;
        let record_raw = canonical_value(record)?;
        if sha256(&record_raw) != record_digest
            || record["public_input_assets_before"] != package["public_assets"]
        {
            return Err(CONTROL);
        }
        let tail = verify_control_reported_tail(&record_raw, role, &key, expected_runtime)?;
        let relations =
            verify_control_reported_relations(&record_raw, role, &key, expected_runtime, &tail)?;
        contained_routes += relations.contained_routes;
        output_bindings += relations.output_bindings;
        public_prompt_relations += relations.public_prompts;
        contained_cli_results += relations.contained_cli_results;
        let session_id = tail.session.session_id;
        if !sessions.insert(session_id.clone()) {
            return Err(EvidenceError::Invalid(
                "conformance roles must be distinct runs",
            ));
        }
        role_session_ids.insert(role.to_owned(), session_id);
    }
    if let Some(assets) = observed_public_assets {
        if assets["sdk"] != package["public_assets"]["sdk"]
            || ["sha256", "size", "mode"]
                .iter()
                .any(|field| assets["bun"][*field] != package["public_assets"]["bun"][*field])
        {
            return Err(EvidenceError::Invalid(
                "actual SDK/Bun differs from conformance",
            ));
        }
    }
    Ok(LocalConformancePackageShadow {
        package_sha256: outside_package_sha256.to_owned(),
        source_count: sources.len(),
        role_session_ids,
        contained_routes,
        output_bindings,
        public_prompt_relations,
        contained_cli_results,
        public_inputs_verified: observed_public_assets.is_some(),
        outside_control_keys_matched: outside_control_keys.is_some(),
        execution_eligible: false,
    })
}

#[cfg(test)]
#[path = "local_conformance_package_tests.rs"]
mod tests;
