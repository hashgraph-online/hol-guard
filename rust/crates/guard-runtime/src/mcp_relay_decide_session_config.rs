//! The blocked-request mode and receipt redaction level a relayed call is
//! answered under when the binding leaves them unbound.
//!
//! A publication binds `blocked_request_mode`, and each relayed harness's
//! `receipt_redaction_level`, only when every compiled config agrees on it
//! (`policy_effective_views.rs`). Where the home and workspace configs
//! disagree, the proxy still answers from its own session config,
//! `load_guard_config(guard_home, workspace)` composed against the managed
//! policy, and so does the relay. The same loader composes the config for
//! the proxy's `--workspace`, and the two settings are read from it.
//!
//! - A setting the binding carries is used as bound, and the config is not
//!   read when the binding carries both.
//! - A config the loader cannot compose leaves the setting unbound, and the
//!   call is refused as it was before this fallback existed.
//! - The approval center and review OAuth source the `ask` branch needs are
//!   still read from the binding only.

use std::path::Path;
use std::sync::Arc;

use serde_json::Value;

use super::{view, Admitted};
use crate::managed_policy_load::ManagedPolicySource;
use crate::policy_store::policy_store_direct_lane::DirectLaneBinding;

const BLOCKED_REQUEST_MODES: [&str; 2] = ["ask", "safe-alternative"];
const REDACTION_LEVELS: [&str; 3] = ["full", "partial", "none"];

/// The session config's settings, read only for what the binding left unbound.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct SessionSettings {
    blocked_request_mode: Option<String>,
    redaction_level: Option<String>,
}

/// The session settings for a call admitted under `binding`.
pub(super) fn session_settings(
    binding: &Arc<DirectLaneBinding>,
    harness: &str,
    guard_home: &str,
    workspace: Option<&str>,
) -> SessionSettings {
    session_settings_under(
        binding,
        harness,
        guard_home,
        workspace,
        &ManagedPolicySource::native(),
    )
}

fn session_settings_under(
    binding: &Arc<DirectLaneBinding>,
    harness: &str,
    guard_home: &str,
    workspace: Option<&str>,
    source: &ManagedPolicySource,
) -> SessionSettings {
    let mode_bound = binding.review.blocked_request_mode.is_some();
    let level_bound = match view::bound_harness_view(binding, harness) {
        Ok(view) => view.receipt_redaction_level.is_some(),
        // A harness the view does not bind is refused before either setting
        // is read.
        Err(_) => true,
    };
    if mode_bound && level_bound {
        return SessionSettings::default();
    }
    let Ok(config) = crate::guard_config_load::effective_config(
        Path::new(guard_home),
        workspace.map(Path::new),
        source,
    ) else {
        return SessionSettings::default();
    };
    SessionSettings {
        blocked_request_mode: known(&config, "blocked_request_mode", &BLOCKED_REQUEST_MODES),
        redaction_level: known(&config, "receipt_redaction_level", &REDACTION_LEVELS),
    }
}

fn known(config: &Value, key: &str, allowed: &[&str]) -> Option<String> {
    config
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| allowed.contains(value))
        .map(str::to_owned)
}

impl SessionSettings {
    /// `bound`, else the session config's blocked-request mode.
    fn blocked_request_mode<'a>(&'a self, bound: Option<&'a str>) -> Option<&'a str> {
        bound.or(self.blocked_request_mode.as_deref())
    }

    /// `bound`, else the session config's redaction level.
    fn redaction_level<'a>(&'a self, bound: Option<&'a str>) -> Option<&'a str> {
        bound.or(self.redaction_level.as_deref())
    }
}

impl Admitted {
    /// The bound blocked-request mode, else the session config's.
    pub(super) fn blocked_request_mode(&self) -> Option<&str> {
        self.session
            .blocked_request_mode(self.binding.review.blocked_request_mode.as_deref())
    }

    /// The harness view's bound redaction level, else the session config's.
    pub(super) fn redaction_level<'a>(&'a self, bound: Option<&'a str>) -> Option<&'a str> {
        self.session.redaction_level(bound)
    }
}

#[cfg(all(test, unix))]
#[path = "mcp_relay_decide_session_config_tests.rs"]
mod tests;
