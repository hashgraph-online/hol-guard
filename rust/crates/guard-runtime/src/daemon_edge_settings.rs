//! `GET /v1/settings` and `GET /v1/settings/export`, composed from the same
//! native loader, resolver and approval-gate snapshot the daemon's Python
//! `editable_guard_settings` reads.
//!
//! A settings read that would first revert or stamp a Watch posture writes
//! the configuration, so it goes to the daemon, which records the posture
//! change as well.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use guard_command::harness_identity::registered_harness_ids;
use serde_json::{json, Map, Value};

use super::ReadConfig;
use crate::approval_gate_settings::public_config_locked;
use crate::approval_gate_verify::SessionSignalsScope;
use crate::guard_config_load::load_under;
use crate::managed_policy_floor::effective_managed_policy;
use crate::managed_policy_load::{load_managed_policy, ManagedPolicySource};

const RESOLVE_SCHEMA: &str = "guard-config-resolve.v1";
const HARNESS_POSTURE_LOCK_KEYS: [&str; 4] = [
    "protection_posture",
    "mode",
    "security_level",
    "harness_postures",
];
const EXPORT_PRIVACY_WARNING: &str =
    "Exports include local Guard preferences but not secrets or receipt evidence.";

/// The `protection_capability_payloads()` keys each harness contract carries.
const CAPABILITY_KEYS: [&str; 9] = [
    "harness",
    "display_name",
    "can_pre_block",
    "can_ask_inline",
    "has_native_remember",
    "fail_open_on_hook_failure",
    "can_pre_block_limited",
    "honesty_sentence",
    "limited",
];

/// The daemon's `/v1/settings` answer, or `None` when the read must go to the
/// daemon: a Watch posture to stamp or revert, or a configuration the native
/// loader refuses.
pub(super) fn settings(config: &ReadConfig) -> Option<(u16, Value)> {
    let guard_home = Path::new(&config.guard_home);
    let loaded = Loaded::read(guard_home)?;
    if loaded.watch_needs_write(now_micros()?)? {
        return None;
    }
    response(config, &loaded)
}

/// `_settings_response_payload(guard_home, editable_guard_settings(config))`.
pub(super) fn response(config: &ReadConfig, loaded: &Loaded) -> Option<(u16, Value)> {
    let guard_home = Path::new(&config.guard_home);
    // Without the daemon's session the gate cannot see a recent TOTP proof,
    // so the daemon answers.
    let signals = config.session_signals.as_deref()?;
    let settings = loaded.editable(guard_home, signals)?;
    Some((
        200,
        json!({
            "guard_home": config.guard_home,
            "config_path": guard_home.join("config.toml").to_str()?,
            "settings": settings,
            "protection_capabilities": protection_capabilities()?,
        }),
    ))
}

/// `_settings_export_payload(load_guard_config(guard_home))`.
pub(super) fn export(config: &ReadConfig) -> Option<(u16, Value)> {
    let guard_home = Path::new(&config.guard_home);
    let signals = config.session_signals.as_deref()?;
    let loaded = Loaded::read(guard_home)?;
    let mut settings = loaded.editable(guard_home, signals)?;
    match loaded.config.get("context_assistance_export") {
        None | Some(Value::Null) => {
            settings.remove("context_assistance");
        }
        Some(portable) => {
            settings.insert("context_assistance".to_owned(), portable.clone());
        }
    }
    settings.remove("context_assistance_diagnostic");
    settings.remove("context_assistance_requested");
    Some((
        200,
        json!({
            "schema_version": 1,
            "privacy_warning": EXPORT_PRIVACY_WARNING,
            "settings": settings,
        }),
    ))
}

/// One `load_guard_config(guard_home)`: the loaded fields and the managed
/// policy facts the Python `GuardConfig` carries beside them.
pub(super) struct Loaded {
    config: Map<String, Value>,
    managed_status: &'static str,
    managed_hash: Option<String>,
    locked: Vec<String>,
    install_owner: &'static str,
}

impl Loaded {
    pub(super) fn read(guard_home: &Path) -> Option<Self> {
        let state = load_managed_policy(&ManagedPolicySource::native());
        let policy = effective_managed_policy(&state);
        let Value::Object(config) = load_under(guard_home, None, policy.as_ref()).ok()? else {
            return None;
        };
        Some(Self {
            config,
            managed_status: state.status.as_str(),
            managed_hash: policy.as_ref().map(|policy| policy.content_hash.clone()),
            locked: policy
                .as_ref()
                .map(|policy| policy.locked_settings.iter().cloned().collect())
                .unwrap_or_default(),
            install_owner: policy
                .as_ref()
                .map_or("user", |policy| policy.install_owner().as_str()),
        })
    }

    pub(super) fn get(&self, key: &str) -> Value {
        self.config.get(key).cloned().unwrap_or(Value::Null)
    }

    pub(super) fn map(&self, key: &str) -> Map<String, Value> {
        match self.config.get(key) {
            Some(Value::Object(map)) => map.clone(),
            _ => Map::new(),
        }
    }

    /// `maybe_auto_revert_watch` writes before it answers: an explicit
    /// unstamped Watch it stamps, or a Watch whose window has run out.
    fn watch_needs_write(&self, now: i64) -> Option<bool> {
        let posture = self
            .config
            .get("protection_posture")
            .and_then(Value::as_str);
        let hours = self.config.get("watch_auto_revert_hours")?.as_i64()?;
        let stamp = self.config.get("watch_entered_at").and_then(Value::as_str);
        if posture == Some("watch")
            && self.get("protection_posture_explicit") == Value::Bool(true)
            && stamp.is_none_or(str::is_empty)
            && hours > 0
            && !self.locked.iter().any(|key| key == "protection_posture")
        {
            return Some(true);
        }
        let deadlines = resolve(json!({
            "op": "watch_auto_revert_deadlines",
            "watch": {
                "auto_revert_hours": hours,
                "protection_posture": posture?,
                "watch_entered_at": stamp,
                "harness_postures": string_entries(&self.map("harness_postures")),
                "harness_watch_entered_at": string_entries(&self.map("harness_watch_entered_at")),
            },
        }))?;
        let due = |at: &Value| at.as_i64().is_some_and(|at| now >= at);
        let harness_due = match deadlines.get("harnesses")? {
            Value::Object(harnesses) => harnesses.values().any(due),
            _ => return None,
        };
        Some(harness_due || deadlines.get("protection_posture").is_some_and(due))
    }

    /// `editable_guard_settings(config)`.
    fn editable(
        &self,
        guard_home: &Path,
        session_signals: &[String],
    ) -> Option<Map<String, Value>> {
        let harness_postures = self.map("harness_postures");
        let stamps = self.map("harness_watch_entered_at");
        let resolved = resolve(json!({
            "op": "harness_postures",
            "postures": {
                "protection_posture": self.get("protection_posture"),
                "mode": self.get("mode"),
                "security_level": self.get("security_level"),
                "harness_postures": string_entries(&harness_postures),
            },
        }))?;
        let baseline = resolved.get("baseline")?.as_str()?;
        let Value::Object(effective) = resolved.get("effective")? else {
            return None;
        };
        let mut effective_known = Map::new();
        let mut status = Vec::new();
        for harness in registered_harness_ids() {
            let posture = effective.get(harness)?.as_str()?;
            effective_known.insert(harness.to_owned(), Value::from(posture));
            let override_ = harness_postures
                .get(harness)
                .cloned()
                .unwrap_or(Value::Null);
            status.push(json!({
                "harness": harness,
                "posture": effective.get(harness).and_then(Value::as_str).unwrap_or(baseline),
                "inherited": override_.is_null(),
                "override": override_,
                "watch_entered_at": stamps.get(harness).cloned().unwrap_or(Value::Null),
            }));
        }
        let risk_actions = resolve(json!({
            "op": "risk_actions",
            "harness": null,
            "facts": {
                "security_level": self.get("security_level"),
                "protection_posture": self.get("protection_posture"),
                "protection_posture_explicit": self.get("protection_posture_explicit") == Value::Bool(true),
                "managed_locked_settings": self.locked,
                "risk_actions": self.map("risk_actions"),
                "harness_risk_actions": self.map("harness_risk_actions"),
                "harness_postures": harness_postures,
            },
        }))?
        .get("risk_actions")?
        .clone();
        let presentation_mode = self.get("presentation_mode");
        let mut settings = Map::new();
        let mut put = |key: &str, value: Value| {
            settings.insert(key.to_owned(), value);
        };
        put("mode", self.get("mode"));
        put("presentation_mode", presentation_mode.clone());
        put(
            "presentation_mode_explicit",
            self.get("presentation_mode_explicit"),
        );
        put(
            "presentation_schema_version",
            self.get("presentation_schema_version"),
        );
        put("presentation_revision", self.get("presentation_revision"));
        put(
            "presentation",
            json!({
                "value": presentation_mode,
                "source": self.get("presentation_source"),
                "explicit": self.get("presentation_mode_explicit"),
                "writable": true,
                "schema_version": self.get("presentation_schema_version"),
                "revision": self.get("presentation_revision"),
                "diagnostic": self.get("presentation_diagnostic"),
            }),
        );
        for key in [
            "presentation_diagnostic",
            "protection_posture",
            "protection_posture_explicit",
            "watch_auto_revert_hours",
        ] {
            put(key, self.get(key));
        }
        put("harness_postures", Value::Object(harness_postures.clone()));
        put("harness_watch_entered_at", Value::Object(stamps.clone()));
        put("harness_postures_effective", Value::Object(effective_known));
        put("harness_posture_status", Value::Array(status));
        put(
            "harness_postures_locked",
            Value::Bool(
                self.locked
                    .iter()
                    .any(|key| HARNESS_POSTURE_LOCK_KEYS.contains(&key.as_str())),
            ),
        );
        for key in [
            "security_level",
            "default_action",
            "unknown_publisher_action",
            "changed_hash_action",
            "new_network_domain_action",
            "subprocess_action",
        ] {
            put(key, self.get(key));
        }
        put("risk_actions", risk_actions);
        put(
            "risk_action_overrides",
            Value::Object(self.map("risk_actions")),
        );
        put(
            "harness_risk_actions",
            Value::Object(self.map("harness_risk_actions")),
        );
        for key in [
            "approval_wait_timeout_seconds",
            "approval_surface_policy",
            "blocked_request_mode",
            "approval_browser_delay_seconds",
            "approval_browser_immediate_severity",
            "desktop_notifications",
            "update_channel",
            "update_mode",
            "telemetry",
            "sync",
            "receipt_redaction_level",
            "billing",
        ] {
            put(key, self.get(key));
        }
        // The gate reads a recent TOTP proof against the daemon's session.
        let _session = SessionSignalsScope::enter(session_signals);
        put(
            "approval_gate",
            public_config_locked(guard_home, None).to_dict(),
        );
        // The native loader always reports the locally requested value, so the
        // requested value is what the dashboard edits.
        let requested = self.get("context_assistance_requested");
        put("context_assistance", requested.clone());
        put(
            "context_assistance_diagnostic",
            self.get("context_assistance_diagnostic"),
        );
        put("managed_policy_status", Value::from(self.managed_status));
        put("managed_policy_hash", json!(self.managed_hash));
        put("managed_locked_settings", json!(self.locked));
        put("install_owner", Value::from(self.install_owner));
        put("context_assistance_requested", requested);
        Some(settings)
    }
}

/// The well-formed string entries of a loaded map, as the daemon sends them.
fn string_entries(map: &Map<String, Value>) -> Map<String, Value> {
    map.iter()
        .filter(|(_, value)| value.is_string())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// One in-process `guard-config-resolve` call.
fn resolve(mut request: Value) -> Option<Map<String, Value>> {
    request["schema"] = Value::from(RESOLVE_SCHEMA);
    let bytes = serde_json::to_vec(&request).ok()?;
    let output = crate::guard_config_resolve::run_command(bytes.as_slice()).ok()?;
    let mut response: Map<String, Value> = serde_json::from_slice(&output).ok()?;
    if response.get("ok") != Some(&Value::Bool(true)) {
        return None;
    }
    match response.remove("result")? {
        Value::Object(result) => Some(result),
        _ => None,
    }
}

fn now_micros() -> Option<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_micros(),
    )
    .ok()
}

/// `protection_capability_payloads()`, read from the harness contract index
/// in registry order.
pub(super) fn protection_capabilities() -> Option<Value> {
    super::inventory::contracts()?
        .iter()
        .map(|(_, contract)| {
            CAPABILITY_KEYS
                .iter()
                .map(|key| Some(((*key).to_owned(), contract.get(*key)?.clone())))
                .collect::<Option<Map<String, Value>>>()
                .map(Value::Object)
        })
        .collect::<Option<Vec<_>>>()
        .map(Value::Array)
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_settings_tests.rs"]
mod tests;
