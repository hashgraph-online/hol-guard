//! First, independently pinned opening of Python's deterministic control.
//! The returned signed records still require the remaining product/SDK checks.

use crate::crypto::decode_hex;
use crate::{verify_controller_envelope, EvidenceError, Result};
use gauntlet_contracts::canonicalize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Component, Path};

const INVALID: EvidenceError = EvidenceError::Invalid("invalid deterministic control record");
const FAILED: EvidenceError =
    EvidenceError::Invalid("control failed, imported product into Root or exercised inference");
const UNCLEAN: EvidenceError = EvidenceError::Invalid("control resources survived");
const KEY: EvidenceError = EvidenceError::Invalid("control key differs from outside pin");
const RUNTIME: EvidenceError =
    EvidenceError::Invalid("control runtime differs from conformance tuple");
const VERSION: EvidenceError =
    EvidenceError::Invalid("control package version differs from conformance tuple");
const PROFILE: EvidenceError =
    EvidenceError::Invalid("current completion/output profiles required");
const BACKEND: EvidenceError = EvidenceError::Invalid("control backend differs from tuple");
const PLANE: EvidenceError =
    EvidenceError::Invalid("detached control plane differs from signed observation");
const ALLOCATION: EvidenceError = EvidenceError::Invalid("control allocation differs from session");
const TASK_PATHS: EvidenceError =
    EvidenceError::Invalid("control task paths differ from declared allocation");
const SDK_BINDING: EvidenceError =
    EvidenceError::Invalid("control lacks outside pre-import SDK binding");

/// Signed portions of a control after the opening checks. This does **not**
/// establish actual SDK traffic, Native reviews, kernel effects or a verdict.
#[derive(Debug)]
pub struct ControlOpening {
    pub runtime: Value,
    pub builtin: Value,
    pub settings: Value,
    pub plane: Value,
}

/// Signed allocation and reported outside SDK gate fields, still awaiting
/// independent kernel/process custody and a complete deterministic verdict.
#[derive(Debug)]
pub struct ControlSessionOpening {
    pub signed: ControlOpening,
    pub session_id: String,
    pub workspace_source: String,
    pub provider_mounts: Vec<String>,
    pub sdk_observation: Value,
    pub agent_identity: Value,
    pub public_prompt_digest: Value,
}

fn exact_true(record: &Value, name: &str) -> bool {
    record.get(name) == Some(&Value::Bool(true))
}

fn exact_false(record: &Value, name: &str) -> bool {
    record.get(name) == Some(&Value::Bool(false))
}

fn matches_fields(actual: &Value, expected: &Value, names: &[&str]) -> bool {
    names.iter().all(|name| {
        let Some(wanted) = expected.get(*name) else {
            return false;
        };
        actual.get(*name) == Some(wanted)
    })
}

/// Port the opening checks of Python `local_executor_controls.verify_control`.
/// `outside_expected` and `outside_public_key` must come from a reviewed source
/// other than the candidate or producer record. Only signed runtime/builtin
/// records and their immediate tuple/plane bindings are returned.
pub fn verify_control_opening(
    raw_control: &[u8],
    role: &str,
    outside_public_key: &[u8],
    outside_expected: &Value,
) -> Result<ControlOpening> {
    if !matches!(
        role,
        "success" | "timeout" | "cancel" | "input-binding" | "boundary"
    ) {
        return Err(EvidenceError::Invalid("unknown conformance role"));
    }
    let canonical = canonicalize(raw_control).map_err(|_| INVALID)?;
    let value: Value = serde_json::from_slice(&canonical).map_err(|_| INVALID)?;
    if !value.is_object() {
        return Err(INVALID);
    }
    if !exact_true(&value, "control_completed")
        || !exact_true(&value, "sdk_exercised")
        || !exact_false(&value, "model_exercised")
        || !exact_false(&value, "root_imported_product")
        || ["error", "cleanup_error", "gate_cleanup_error"]
            .iter()
            .any(|name| value.get(*name).is_some_and(|item| !item.is_null()))
    {
        return Err(FAILED);
    }
    if !exact_true(&value, "image_released")
        || !exact_true(&value, "agent_cgroup_absent")
        || !exact_true(&value, "agent_profile_removed")
        || value.get("agent_remove_returncode").and_then(Value::as_i64) != Some(0)
    {
        return Err(UNCLEAN);
    }
    let declared = value
        .get("controller_public_key_hex")
        .and_then(Value::as_str)
        .ok_or(KEY)?;
    let declared = decode_hex(declared, 32).map_err(|_| KEY)?;
    if declared != outside_public_key {
        return Err(KEY);
    }
    let runtime_envelope = value.get("developer_runtime").ok_or(INVALID)?;
    let runtime_raw = serde_json::to_vec(runtime_envelope).map_err(|_| INVALID)?;
    let runtime = verify_controller_envelope(&runtime_raw, outside_public_key)?;
    let settings = runtime.get("settings").ok_or(RUNTIME)?;
    if !matches_fields(
        settings,
        outside_expected,
        &[
            "source_sha",
            "prefix_digest",
            "bwrap_sha256",
            "executor_image_id",
            "mcp_image_id",
        ],
    ) {
        return Err(RUNTIME);
    }
    let has_version = outside_expected.get("package_version").is_some();
    if has_version && settings.get("package_version") != outside_expected.get("package_version") {
        return Err(VERSION);
    }
    let expected_schema = if has_version { "5.0" } else { "4.0" };
    if runtime.get("schema_version") != Some(&Value::String(expected_schema.into()))
        || settings.get("contained_output_binding")
            != Some(&Value::String("controller-contained-output.v1".into()))
        || settings.get("contained_completion_profile")
            != Some(&Value::String("guard-contained-completion.v1".into()))
    {
        return Err(PROFILE);
    }
    if !matches_fields(
        settings.get("private_cell").ok_or(BACKEND)?,
        outside_expected.get("private_cell").ok_or(BACKEND)?,
        &[
            "artifact_manifest_sha256",
            "initializer_sha256",
            "native_sha256",
            "runtime_tree_digest",
            "idmap_runtime",
            "cpu_profile",
        ],
    ) {
        return Err(BACKEND);
    }
    let builtin_envelope = runtime.get("native_builtin_audit").ok_or(INVALID)?;
    let builtin_raw = serde_json::to_vec(builtin_envelope).map_err(|_| INVALID)?;
    let builtin = verify_controller_envelope(&builtin_raw, outside_public_key)?;
    let plane = builtin.get("product_plane").ok_or(PLANE)?.clone();
    if value.get("plane") != Some(&plane) {
        return Err(PLANE);
    }
    Ok(ControlOpening {
        runtime: runtime.clone(),
        builtin,
        settings: settings.clone(),
        plane,
    })
}

/// Continue Python `verify_control` through the signed session allocation,
/// task-path relation and pre-import SDK gate flags. These flags are supplied
/// by the producer; they do not authenticate the kernel peer or SDK process.
pub fn verify_control_session_opening(
    raw_control: &[u8],
    role: &str,
    outside_public_key: &[u8],
    outside_expected: &Value,
) -> Result<ControlSessionOpening> {
    let signed = verify_control_opening(raw_control, role, outside_public_key, outside_expected)?;
    let canonical = canonicalize(raw_control).map_err(|_| INVALID)?;
    let value: Value = serde_json::from_slice(&canonical).map_err(|_| INVALID)?;
    let session_id = signed
        .runtime
        .get("controller_session_id")
        .and_then(Value::as_str)
        .ok_or(INVALID)?
        .to_owned();
    let workspace_path = signed
        .plane
        .get("workspace_path")
        .and_then(Value::as_str)
        .ok_or(INVALID)?;
    let mounts = signed
        .plane
        .get("task_mounts")
        .and_then(Value::as_array)
        .ok_or(INVALID)?;
    let workspace_source = mounts
        .iter()
        .find(|row| row.get("destination").and_then(Value::as_str) == Some(workspace_path))
        .and_then(|row| row.get("source"))
        .and_then(Value::as_str)
        .ok_or(INVALID)?
        .to_owned();
    let root_path = Path::new(&workspace_source)
        .parent()
        .and_then(Path::parent)
        .ok_or(ALLOCATION)?;
    let root = root_path.to_str().ok_or(ALLOCATION)?;
    if root_path.file_name().and_then(|name| name.to_str()) != Some(session_id.as_str())
        || root_path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(ALLOCATION);
    }
    let provider_mounts: Vec<String> = mounts
        .iter()
        .filter(|row| row.get("destination").and_then(Value::as_str) != Some(workspace_path))
        .map(|row| {
            row.get("source")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(INVALID)
        })
        .collect::<Result<_>>()?;
    let actual_providers: BTreeSet<&str> = provider_mounts.iter().map(String::as_str).collect();
    let expected_providers = [format!("{root}/tasks/remote"), format!("{root}/tasks/home")];
    let expected_providers: BTreeSet<&str> =
        expected_providers.iter().map(String::as_str).collect();
    if workspace_source != format!("{root}/tasks/checkout")
        || actual_providers != expected_providers
    {
        return Err(TASK_PATHS);
    }
    let sdk_gate = value.get("sdk_gate").ok_or(INVALID)?;
    let sdk_observation = sdk_gate.get("observation").ok_or(INVALID)?;
    if sdk_gate.get("cleanup_complete") != Some(&Value::Bool(true))
        || sdk_gate.get("error") != Some(&Value::Null)
        || sdk_observation.get("kernel_peer_authenticated") != Some(&Value::Bool(true))
        || sdk_observation.get("bound_before_sdk_import") != Some(&Value::Bool(true))
    {
        return Err(SDK_BINDING);
    }
    sdk_observation.get("pid").ok_or(INVALID)?;
    sdk_observation.get("identity").ok_or(INVALID)?;
    let agent_identity = value.get("agent_identity").ok_or(INVALID)?.clone();
    let public_prompt_digest = signed
        .runtime
        .get("public_prompt_digest")
        .ok_or(INVALID)?
        .clone();
    Ok(ControlSessionOpening {
        signed,
        session_id,
        workspace_source,
        provider_mounts,
        sdk_observation: sdk_observation.clone(),
        agent_identity,
        public_prompt_digest,
    })
}
