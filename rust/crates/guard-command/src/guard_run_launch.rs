//! `runner.py` guard-run launch-authority helpers — canonical ports.
//!
//! Ports the `_GuardRunLaunchPlan` dataclass plus the launch-plan, preview,
//! signature, and authority-binding helpers consumed by `guard_run`
//! (`runner.py` :460-657). These helpers bind an exact adapter launch argv to a
//! content-pinned identity at the authority boundary so a runtime launch can be
//! proven (or denied) against the recorded plan rather than its spelling.
//!
//! Parity contract: every ported fn matches its Python source byte-for-byte for
//! digest/signature output and field-for-field for maps. `serde_json::Map` is a
//! `BTreeMap`, which matches `json.dumps(..., sort_keys=True)`. `default=str`
//! maps to a `to_string()` fallback for non-serializable leaves.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[cfg(unix)]
use serde_json::Map;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use crate::launch_identity::{
    build_runtime_launch_identity, resolved_runtime_launch_argv,
    runtime_launch_identity_is_reusable,
};

/// `_GuardRunLaunchPlan` (:461-470). Exact adapter launch vector resolved at an
/// authority boundary.
#[derive(Debug, Clone)]
pub struct GuardRunLaunchPlan {
    pub adapter_command: Vec<String>,
    pub execution_command: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub environment_sha256: String,
    /// Launch identity as a serde_json value (mirrors the Python `Mapping`).
    pub identity: Value,
    pub launch_cwd: PathBuf,
    pub reusable: bool,
}

/// `_guard_run_launch_environment_hash` (:492-501). Canonical, non-reversible
/// digest of the full prepared environment.
///
/// `sha256(b"hol.guard.guard-run-launch-environment:v1\x00" +
///   json.dumps(sorted(env.items()), ensure_ascii=True,
///              separators=(",", ":")).encode())`.
#[allow(dead_code)]
pub fn guard_run_launch_environment_hash(environment: &BTreeMap<String, String>) -> String {
    let sorted: Vec<(&String, &String)> = environment.iter().collect();
    // `ensure_ascii=True` escapes every non-ASCII char to `\uXXXX`; serde_json
    // emits raw UTF-8, so ASCII-escape the material before hashing.
    let material = serde_json::to_string(&sorted)
        .map(|s| ascii_escape_json(&s))
        .expect("env pairs serialize");
    let mut hasher = Sha256::new();
    hasher.update(b"hol.guard.guard-run-launch-environment:v1\x00");
    hasher.update(material.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// `json.dumps(..., ensure_ascii=True)` escapes every non-ASCII scalar to
/// `\uXXXX` (BMP) or a surrogate pair. serde_json leaves UTF-8 intact, so this
/// rewrites non-ASCII characters to their escaped form for byte parity.
fn ascii_escape_json(serialized: &str) -> String {
    let mut out = String::with_capacity(serialized.len());
    for ch in serialized.chars() {
        if ch.is_ascii() {
            out.push(ch);
        } else {
            let code = ch as u32;
            if code <= 0xFFFF {
                out.push_str(&format!("\\u{code:04x}"));
            } else {
                let n = code - 0x1_0000;
                let hi = 0xD800 + (n >> 10);
                let lo = 0xDC00 + (n & 0x3FF);
                out.push_str(&format!("\\u{hi:04x}\\u{lo:04x}"));
            }
        }
    }
    out
}

#[cfg(unix)]
/// `_guard_run_plan_for_command` (:503-531). Content-bind every launch argv
/// without performing adapter setup: resolve the launch identity, recover the
/// executable-pinned command, and stamp the plan reusable only when the identity
/// proves a durable binding.
///
/// `environment`/`launch_cwd` come from the caller's prepared launch context.
#[allow(dead_code)]
pub fn guard_run_plan_for_command(
    adapter_command: &[String],
    environment: &BTreeMap<String, String>,
    launch_cwd: &Path,
) -> Option<GuardRunLaunchPlan> {
    let normalized_command = adapter_command.to_vec();
    if normalized_command.is_empty() || normalized_command.iter().any(|part| part.is_empty()) {
        return None;
    }
    let launch_env_value = Value::Object(
        environment
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect::<Map<String, Value>>(),
    );
    let search_path = environment.get("PATH").cloned();
    let args_value: Vec<Value> = normalized_command[1..]
        .iter()
        .map(|a| Value::String(a.clone()))
        .collect();
    let identity = build_runtime_launch_identity(
        &Value::String(normalized_command[0].clone()),
        &args_value,
        true,
        true,
        search_path.as_deref(),
        Some(launch_cwd),
        None,
        Some(&launch_env_value),
    );
    let pinned_command = resolved_runtime_launch_argv(&identity, &normalized_command[1..]);
    let reusable = pinned_command.is_some() && runtime_launch_identity_is_reusable(&identity);
    let execution_command = match (reusable, pinned_command) {
        (true, Some(pinned)) => pinned,
        _ => normalized_command.clone(),
    };
    Some(GuardRunLaunchPlan {
        adapter_command: normalized_command,
        execution_command,
        environment: environment.clone(),
        environment_sha256: guard_run_launch_environment_hash(environment),
        identity,
        launch_cwd: launch_cwd.to_path_buf(),
        reusable,
    })
}

/// `_guard_run_executable_prefix` (:559-569). Recover the executable-resolved
/// argv prefix when the execution command extends the adapter command (e.g. a
/// resolved absolute path prepended to a `cmd /c`-style wrapper). Returns `None`
/// when no extra prefix exists.
#[allow(dead_code)]
pub fn guard_run_executable_prefix(launch_plan: &GuardRunLaunchPlan) -> Option<Vec<String>> {
    let adapter = &launch_plan.adapter_command;
    let exec = &launch_plan.execution_command;
    if exec.len() <= adapter.len() {
        return None;
    }
    let prefix_len = exec.len() - adapter.len();
    if &exec[prefix_len..] != adapter {
        return None;
    }
    Some(exec[..prefix_len].to_vec())
}

/// Seam for the harness-adapter launch command used by
/// `guard_run_finalize_authorized_launch_plan`. Mirrors the Python adapter's
/// `launch_command_from_authorized_plan` callback; implemented by the resident
/// runtime, not this module.
pub trait GuardRunAdapterApi {
    /// `HarnessAdapter.launch_command_from_authorized_plan` — build the launch
    /// argv for authorized executable prefixes and an environment, or `None`
    /// when it cannot be bound.
    fn launch_command_from_authorized_plan(
        &self,
        harness: &str,
        authorized_executable_prefixes: &[Vec<String>],
        launch_environment: &BTreeMap<String, String>,
        passthrough_args: &[String],
    ) -> Option<Vec<String>>;
}

/// `_guard_run_finalize_authorized_launch_plan` (:571-604). Pick the authorized
/// launch plan matching the requested command/passthrough, rebuild its command
/// through the adapter, and return a finalized plan carrying the adapter's
/// authorized command. `None` when no plan binds.
#[allow(dead_code)]
pub fn guard_run_finalize_authorized_launch_plan(
    adapter: &dyn GuardRunAdapterApi,
    harness: &str,
    passthrough_args: &[String],
    authorized_plans: &[GuardRunLaunchPlan],
    context_home_dir: Option<&Path>,
    context_workspace_dir: Option<&Path>,
) -> Option<GuardRunLaunchPlan> {
    if authorized_plans.is_empty() || !authorized_plans.iter().all(|p| p.reusable) {
        return None;
    }
    let first = &authorized_plans[0];
    if authorized_plans[1..].iter().any(|p| {
        p.environment_sha256 != first.environment_sha256 || p.environment != first.environment
    }) {
        return None;
    }
    let mut prefixes: Vec<Vec<String>> = Vec::new();
    for plan in authorized_plans {
        let prefix = guard_run_executable_prefix(plan)?;
        if !prefixes.contains(&prefix) {
            prefixes.push(prefix);
        }
    }
    let actual = adapter.launch_command_from_authorized_plan(
        harness,
        &prefixes,
        &first.environment,
        passthrough_args,
    )?;
    let mut finalized = authorized_plans
        .iter()
        .find(|plan| actual == plan.adapter_command || actual == plan.execution_command)?
        .clone();
    // Python re-runs the launch-environment build against `context`; the
    // plan already carries the prepared environment, so reuse it here and
    // only re-derive the cwd from context when provided.
    finalized.launch_cwd = context_workspace_dir
        .map(|p| p.to_path_buf())
        .or_else(|| context_home_dir.map(|p| p.to_path_buf()))
        .unwrap_or(finalized.launch_cwd);
    Some(finalized)
}

/// `_guard_run_launch_plan_signature` (:606-616). Canonical signature of a
/// reusable plan: sorted-key JSON of `adapter_command`, `environment_sha256`,
/// and `identity`. `None` for a non-reusable plan.
#[allow(dead_code)]
pub fn guard_run_launch_plan_signature(launch_plan: &GuardRunLaunchPlan) -> Option<String> {
    if !launch_plan.reusable {
        return None;
    }
    let payload = json!({
        "adapter_command": launch_plan.adapter_command,
        "environment_sha256": launch_plan.environment_sha256,
        "identity": launch_plan.identity,
    });
    Some(ascii_escape_json(
        &serde_json::to_string(&payload).expect("plan signature serializes"),
    ))
}

/// Seam for the timing-free detector authority payload consumed by
/// `guard_run_authority_signature`. Mirrors `_runtime_detector_context`; the
/// resident evaluator supplies the real payload.
pub trait GuardRunDetectorContextApi {
    /// `_runtime_detector_context` — canonical detector payload or `None`.
    fn runtime_detector_context(&self, evaluation: &Value) -> Option<Value>;
}

/// Seam for approval-context-token validation. Mirrors
/// `parse_approval_context_token`; the resident authority supplies the real
/// validator.
pub trait GuardRunApprovalTokenApi {
    /// `parse_approval_context_token` — `Some` iff `token` is a well-formed v1
    /// approval-context token.
    fn parse_approval_context_token(&self, token: &Value) -> Option<Value>;
}

/// `is_guard_action` — `true` iff `value` is a canonical GuardAction string.
#[allow(dead_code)]
pub fn guard_run_is_guard_action(value: &Value) -> bool {
    matches!(
        value.as_str(),
        Some("allow" | "warn" | "review" | "require-reapproval" | "sandbox-required" | "block")
    )
}

/// `_guard_run_authority_signature` (:621-657). Content-binding signature over
/// the detection state, per-artifact approval contexts, detector payload, and
/// the launch previews. Returns `None` when any artifact's approval context is
/// malformed — the authority tuple must never bind a corrupt claim.
#[allow(dead_code, clippy::too_many_arguments)]
pub fn guard_run_authority_signature(
    harness: &str,
    installed: bool,
    command_available: bool,
    config_paths: &[String],
    artifacts: &[Value],
    evaluation: &Value,
    launch_previews: &[GuardRunLaunchPlan],
    tokens: &dyn GuardRunApprovalTokenApi,
    detector: &dyn GuardRunDetectorContextApi,
) -> Option<Value> {
    let mut contexts: BTreeMap<String, (String, String)> = BTreeMap::new();
    for item in artifacts {
        let artifact_id = item.get("artifact_id");
        let approval_context_hash = item.get("approval_context_hash");
        let policy_action = item.get("policy_action");
        let artifact_id_ok = matches!(artifact_id, Some(Value::String(s)) if !s.is_empty());
        let approval_ok = matches!(approval_context_hash, Some(Value::String(_)))
            && tokens
                .parse_approval_context_token(approval_context_hash.unwrap_or(&Value::Null))
                .is_some();
        let action_ok =
            policy_action.is_some() && guard_run_is_guard_action(policy_action.unwrap());
        let already = artifact_id
            .and_then(Value::as_str)
            .map(|s| contexts.contains_key(s))
            .unwrap_or(false);
        if !(artifact_id_ok && approval_ok && action_ok) || already {
            return None;
        }
        contexts.insert(
            artifact_id.unwrap().as_str().unwrap().to_string(),
            (
                approval_context_hash.unwrap().as_str().unwrap().to_string(),
                policy_action.unwrap().as_str().unwrap().to_string(),
            ),
        );
    }
    let detector_payload = detector
        .runtime_detector_context(evaluation)
        .unwrap_or(Value::Null);
    let detector_json = ascii_escape_json(
        &serde_json::to_string(&detector_payload).expect("detector payload serializes"),
    );
    let contexts_sorted: Vec<Value> = contexts
        .iter()
        .map(|(k, (h, a))| json!([k, h, a]))
        .collect();
    let plan_signatures: Vec<Value> = launch_previews
        .iter()
        .map(|plan| {
            guard_run_launch_plan_signature(plan)
                .map(Value::String)
                .unwrap_or(Value::Null)
        })
        .collect();
    Some(json!({
        "harness": harness,
        "installed": installed,
        "command_available": command_available,
        "config_paths": config_paths,
        "contexts": contexts_sorted,
        "detector": detector_json,
        "launch_previews": plan_signatures,
    }))
}

#[cfg(test)]
#[path = "guard_run_launch_tests.rs"]
mod tests;
