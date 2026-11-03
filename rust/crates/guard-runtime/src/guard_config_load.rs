//! One-shot native loader for the effective Guard configuration.
//!
//! Reads the Guard home `config.toml` and the sanitized workspace override
//! files, composes the managed policy the caller resolved, and coerces every
//! value. The caller never recalculates a value: malformed input falls back to
//! the documented default and an unreadable or untrusted source is an error.

use std::io::Read;
use std::path::{Path, PathBuf};

use guard_command::effect_decision::GuardAction;
use guard_context_assistance::{restrict_value, ContextAssistanceConfig};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::guard_config_coerce as coerce;
use crate::guard_config_harness as harness;
use crate::guard_config_managed::{apply_managed_policy, ManagedInput};
use crate::managed_policy_floor::effective_managed_policy;
use crate::managed_policy_load::{load_managed_policy, ManagedPolicySource};
use crate::package_authority_config as base;
#[path = "context_assistance_update_preferences.rs"]
pub(crate) mod cigar_updates;
#[path = "context_assistance_config_snapshot.rs"]
mod context_snapshot;
#[cfg(all(test, unix))]
pub(crate) use context_snapshot::with_changed_reads;

const SCHEMA: &str = "guard-config-load.v1";
const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
static TRUE: Value = Value::Bool(true);
const DEFAULT_WATCH_AUTO_REVERT_HOURS: i64 = 24;
const MAX_WATCH_AUTO_REVERT_HOURS: i64 = 168;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoadRequest {
    schema: String,
    guard_home: PathBuf,
    #[serde(default)]
    workspace: Option<PathBuf>,
    #[serde(default)]
    require_canonical_workspace: bool,
    #[serde(default)]
    managed: Option<ManagedInput>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "guard-config-load"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "guard_config_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("guard_config_request_too_large".to_owned());
    }
    let request: LoadRequest =
        serde_json::from_slice(&bytes).map_err(|_| "guard_config_request_invalid".to_owned())?;
    if request.schema != SCHEMA {
        return Err("guard_config_request_invalid".to_owned());
    }
    // A load failure is data, not a crash: the caller maps it to its own error.
    let response = match load(&request) {
        Ok(config) => json!({"ok": true, "config": config}),
        Err(reason) => json!({"ok": false, "error": reason}),
    };
    serde_json::to_vec(&response).map_err(|_| "guard_config_response_encode_failed".to_owned())
}

fn error_reason(error: guard_command::supply_chain_package_eval::EvalError) -> String {
    use guard_command::supply_chain_package_eval::EvalError;
    match error {
        EvalError::Internal(message)
        | EvalError::Validation(message)
        | EvalError::NotFound(message) => message
            .strip_prefix("guard config unavailable: ")
            .unwrap_or(&message)
            .to_owned(),
        _ => "config_file_unavailable".to_owned(),
    }
}

fn load(request: &LoadRequest) -> Result<Value, String> {
    let home = base::read_config_table(&request.guard_home, base::HOME_CONFIG_FILENAME)
        .map_err(error_reason)?
        .unwrap_or_default();
    load_from_home(request, &home)
}

fn load_from_home(request: &LoadRequest, home: &Map<String, Value>) -> Result<Value, String> {
    let workspace: Option<&Path> = request.workspace.as_deref();
    let (workspace_config, assistance_restrictions) =
        base::load_workspace_config_parts(workspace, request.require_canonical_workspace)
            .map_err(error_reason)?;
    let mut merged = base::merge_config_payload(home, &workspace_config);
    let mut assistance = home.get("context_assistance").cloned();
    for restriction in assistance_restrictions {
        assistance = Some(restrict_value(assistance.as_ref(), &restriction));
    }
    if let Some(assistance) = assistance {
        merged.insert("context_assistance".to_owned(), assistance);
    }
    if let Some(policy) = &request.managed {
        merged = apply_managed_policy(&merged, policy);
    }
    let mut value = coerce_config(&merged, request.managed.as_ref());
    // Preserve validated local intent for presentation/settings round trips.
    // Enforcement continues to use the restricted context_assistance value.
    value["context_assistance_requested"] = match home.get("context_assistance") {
        Some(local) => json!(ContextAssistanceConfig::load(Some(local)).0),
        None => Value::Null,
    };
    Ok(value)
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct AssistanceSettings {
    pub(crate) requested: ContextAssistanceConfig,
    pub(crate) effective: ContextAssistanceConfig,
    pub(crate) diagnostic: Option<String>,
    pub(crate) restriction: Option<&'static str>,
    pub(crate) verification_permitted: bool,
}

impl Default for AssistanceSettings {
    fn default() -> Self {
        Self {
            requested: ContextAssistanceConfig::default(),
            effective: ContextAssistanceConfig::default(),
            diagnostic: None,
            restriction: None,
            verification_permitted: true,
        }
    }
}

impl AssistanceSettings {
    pub(crate) fn unavailable(code: &str) -> Self {
        Self {
            diagnostic: Some(code.into()),
            verification_permitted: false,
            ..Default::default()
        }
    }
}

/// Assistance control operations resolve machine authority themselves. A
/// public request cannot omit or replace managed restrictions.
pub(crate) fn context_assistance_config(home: &Path) -> Result<AssistanceSettings, String> {
    let mut source = crate::managed_policy_load::ManagedPolicySource::native();
    source.write_cache = false;
    context_assistance_from_source(home, &source)
}

pub(crate) fn context_assistance_from_source(
    home: &Path,
    source: &crate::managed_policy_load::ManagedPolicySource,
) -> Result<AssistanceSettings, String> {
    context_assistance_at(home, None, source)
}

pub(crate) fn context_assistance_for_workspace(
    home: &Path,
    workspace: &Path,
) -> Result<AssistanceSettings, String> {
    let mut source = crate::managed_policy_load::ManagedPolicySource::native();
    source.write_cache = false;
    context_assistance_at(home, Some(workspace), &source)
}

fn context_assistance_at(
    home: &Path,
    workspace: Option<&Path>,
    source: &crate::managed_policy_load::ManagedPolicySource,
) -> Result<AssistanceSettings, String> {
    let home_config = context_snapshot::read_home(home)?;
    context_assistance_from_home(home, workspace, source, &home_config)
}

/// Hypothetical local intent is composed through the same native machine
/// authority as ordinary activation. It never writes config or grants a scope.
pub(crate) fn context_assistance_target_from_source(
    home: &Path,
    requested: &ContextAssistanceConfig,
    source: &crate::managed_policy_load::ManagedPolicySource,
) -> Result<AssistanceSettings, String> {
    requested.validate().map_err(|e| e.0.to_owned())?;
    let mut table = context_snapshot::read_home(home)?;
    table.insert(
        "context_assistance".into(),
        serde_json::to_value(requested)
            .map_err(|_| "context_assistance_schema_invalid".to_owned())?,
    );
    context_assistance_from_home(home, None, source, &table)
}

fn context_assistance_from_home(
    home: &Path,
    workspace: Option<&Path>,
    source: &crate::managed_policy_load::ManagedPolicySource,
    home_config: &Map<String, Value>,
) -> Result<AssistanceSettings, String> {
    let (requested, requested_error) =
        ContextAssistanceConfig::load(home_config.get("context_assistance"));
    let state = crate::managed_policy_load::load_managed_policy(source);
    if state.status.fails_closed() {
        let mut effective = requested.clone();
        effective.enabled = false;
        return Ok(AssistanceSettings {
            requested,
            effective,
            diagnostic: Some("managed_policy_unavailable".into()),
            restriction: Some("managed_policy"),
            verification_permitted: false,
        });
    }
    let managed =
        crate::managed_policy_floor::effective_managed_policy(&state).map(|policy| ManagedInput {
            settings: policy.settings,
            locked_settings: policy.locked_settings.into_iter().collect(),
        });
    let verification_permitted = managed
        .as_ref()
        .and_then(|policy| {
            policy
                .settings
                .get("context_assistance")
                .and_then(|value| value.get("enabled"))
        })
        .and_then(Value::as_bool)
        != Some(false);
    let value = load_from_home(
        &LoadRequest {
            schema: SCHEMA.into(),
            guard_home: home.into(),
            workspace: workspace.map(Path::to_path_buf),
            require_canonical_workspace: true,
            managed,
        },
        home_config,
    )?;
    let (effective, fallback) =
        ContextAssistanceConfig::load(value.get("context_assistance").filter(|v| !v.is_null()));
    let diagnostic = value
        .get("context_assistance_diagnostic")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| fallback.or(requested_error).map(|e| e.0.to_owned()));
    let restriction =
        (effective != requested || !verification_permitted).then_some(if workspace.is_some() {
            "workspace_or_managed_policy"
        } else {
            "managed_policy"
        });
    Ok(AssistanceSettings {
        requested,
        effective,
        diagnostic,
        restriction,
        verification_permitted,
    })
}

/// Effective `approval_wait_timeout_seconds` for an in-process caller (the
/// native MCP relay, a waiting Codex hook's live wait): the Guard home and
/// workspace configuration under this machine's managed policy, as
/// `load_guard_config` composes them.
pub(crate) fn approval_wait_timeout_seconds(
    guard_home: &Path,
    workspace: Option<&Path>,
) -> Result<i64, String> {
    approval_wait_timeout_seconds_under(guard_home, workspace, &ManagedPolicySource::native())
}

/// `approval_wait_timeout_seconds` under the managed policy `source` loads.
pub(crate) fn approval_wait_timeout_seconds_under(
    guard_home: &Path,
    workspace: Option<&Path>,
    source: &ManagedPolicySource,
) -> Result<i64, String> {
    let managed =
        effective_managed_policy(&load_managed_policy(source)).map(|policy| ManagedInput {
            settings: policy.settings.clone(),
            locked_settings: policy.locked_settings.iter().cloned().collect(),
        });
    let request = LoadRequest {
        schema: SCHEMA.to_owned(),
        guard_home: guard_home.to_path_buf(),
        workspace: workspace.map(Path::to_path_buf),
        require_canonical_workspace: false,
        managed,
    };
    let config = load(&request)?;
    Ok(config
        .get("approval_wait_timeout_seconds")
        .and_then(Value::as_i64)
        .unwrap_or(120))
}

fn watch_hours(value: Option<&Value>) -> i64 {
    match value.and_then(Value::as_i64) {
        Some(hours) if (0..=MAX_WATCH_AUTO_REVERT_HOURS).contains(&hours) => hours,
        _ => DEFAULT_WATCH_AUTO_REVERT_HOURS,
    }
}

fn watch_entered_at(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?;
    (!text.trim().is_empty() && crate::guard_config_iso::is_valid_iso_datetime(text))
        .then(|| text.trim().to_owned())
}

fn action_text(value: Option<&Value>, fallback: GuardAction) -> &'static str {
    coerce::action_or_default(value, fallback).as_str()
}

/// Derive every field of the loaded configuration from the composed payload.
pub(crate) fn coerce_config(merged: &Map<String, Value>, managed: Option<&ManagedInput>) -> Value {
    let get = |key: &str| merged.get(key);
    let (assistance, assistance_diagnostic) = match get("context_assistance") {
        None => (None, None),
        value => {
            let (config, diagnostic) = ContextAssistanceConfig::load(value);
            (Some(config), diagnostic.map(|error| error.0))
        }
    };
    let assistance_export = assistance.as_ref().map(ContextAssistanceConfig::for_export);
    let loaded_mode = coerce::loaded_mode(get("mode"), "prompt");
    let security_level = base::coerce_security_level(get("security_level"));
    let explicit_posture = get("protection_posture").and_then(harness::normalize_posture);
    let managed_locks_level = managed.is_some_and(|policy| {
        policy
            .locked_settings
            .iter()
            .any(|key| key == "security_level")
    });
    let derived = base::derive_posture(Some(&Value::from(loaded_mode)), &security_level);
    let (posture, posture_explicit) = match (managed_locks_level, explicit_posture) {
        (false, Some(explicit)) => (explicit, true),
        _ => (derived, false),
    };
    let local_postures = harness::loaded_postures(get("harness_postures"));
    let postures = match managed {
        Some(policy) => {
            harness::managed_effective(local_postures, &policy.locked_settings, &policy.settings)
        }
        None => local_postures,
    };
    let stamps = harness::loaded_watch_stamps(get("harness_watch_entered_at"), &postures);
    let legacy = coerce::legacy_presentation_value(merged);
    let presentation = coerce::presentation(
        legacy,
        get("presentation_mode_explicit").or_else(|| legacy.map(|_| &TRUE)),
        get("presentation_schema_version"),
    );
    json!({
        "mode": if posture == "watch" { "observe" } else { loaded_mode },
        "presentation_mode": presentation.value,
        "presentation_mode_explicit": presentation.explicit,
        "presentation_schema_version": 1,
        "presentation_revision": coerce::non_negative_int(get("presentation_revision"), 0),
        "presentation_source": presentation.source,
        "presentation_diagnostic": presentation.diagnostic,
        "protection_posture": posture,
        "protection_posture_explicit": posture_explicit,
        "watch_auto_revert_hours": watch_hours(get("watch_auto_revert_hours")),
        "watch_entered_at": watch_entered_at(get("watch_entered_at")),
        "harness_postures": postures,
        "harness_watch_entered_at": stamps,
        "default_action": action_text(get("default_action"), GuardAction::Warn),
        "unknown_publisher_action": action_text(get("unknown_publisher_action"), GuardAction::Review),
        "changed_hash_action": action_text(get("changed_hash_action"), GuardAction::RequireReapproval),
        "new_network_domain_action": action_text(get("new_network_domain_action"), GuardAction::Warn),
        "subprocess_action": action_text(get("subprocess_action"), GuardAction::Warn),
        "approval_wait_timeout_seconds": coerce::non_negative_int(get("approval_wait_timeout_seconds"), 120),
        "approval_surface_policy": coerce::approval_surface_policy(get("approval_surface_policy")),
        "blocked_request_mode": coerce::blocked_request_mode(get("blocked_request_mode")),
        "approval_browser_delay_seconds": coerce::bounded_int(get("approval_browser_delay_seconds"), 20, 300),
        "approval_browser_immediate_severity": coerce::approval_browser_severity(get("approval_browser_immediate_severity")),
        "desktop_notifications": match get("desktop_notifications") {
            None => true,
            other => coerce::loaded_bool(other),
        },
        "update_channel": coerce::update_channel(get("update_channel")),
        "telemetry": coerce::python_truthy(get("telemetry")),
        "sync": coerce::python_truthy(get("sync")),
        "billing": coerce::python_truthy(get("billing")),
        "context_assistance": assistance,
        "context_assistance_diagnostic": assistance_diagnostic,
        "context_assistance_export": assistance_export,
        "runtime_detector_registry": coerce::loaded_bool(get("runtime_detector_registry")),
        "runtime_detector_timeout_ms": coerce::positive_int(get("runtime_detector_timeout_ms"), 50),
        "runtime_detector_debug_trace": coerce::loaded_bool(get("runtime_detector_debug_trace")),
        "runtime_detector_disabled_ids": coerce::string_list(get("runtime_detector_disabled_ids")),
        "sandbox_analysis": coerce::sandbox_analysis(get("sandbox_analysis")),
        // Only an explicit `false` stops the worker; a value Guard cannot read leaves it on.
        "workspace_assessment_enabled": !matches!(
            get("workspace_assessment_enabled"),
            Some(Value::Bool(false))
        ),
        "harness_actions": coerce::action_map(get("harnesses")),
        "publisher_actions": coerce::action_map(get("publishers")),
        "artifact_actions": coerce::action_map(get("artifacts")),
        "security_level": security_level,
        "risk_actions": coerce::risk_action_map(get("risk_actions")),
        "harness_risk_actions": base::coerce_harness_risk_actions(get("harness_risk_actions")),
        "receipt_redaction_level": coerce::receipt_redaction_level(get("receipt_redaction_level")),
        "evidence_retain_days": coerce::bounded_positive_int(get("evidence_retain_days"), 90, 3_650),
        "receipt_detail_limit": coerce::optional_bounded_positive_int(get("receipt_detail_limit"), 1_000_000),
        "guard_event_limit": coerce::optional_bounded_positive_int(get("guard_event_limit"), 1_000_000),
    })
}

#[cfg(test)]
#[path = "guard_config_load_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "guard_config_context_assistance_tests.rs"]
mod context_assistance_tests;
