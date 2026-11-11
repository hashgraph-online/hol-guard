//! Diagnostic counts of the hooks the daemon's hook route receives.
//!
//! A bridge asks the resident first and posts here only when the resident
//! defers or cannot be used, so these counts beside the resident's own
//! (logged from its evidence pages) show how often the direct lane misses.
//! A bridge that knows why names the reason in `X-Guard-Direct-Miss`, counted
//! per harness too. Nothing reads the counts to decide a hook. Harness names
//! reduce to a fixed set of slots and nothing else is kept; the daemon log
//! gets one line when the counts change, at most once per interval.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::json;

/// `HARNESS_SLOTS` without the catch-all.
const NAMED_SLOTS: [&str; 15] = [
    "codex",
    "claude-code",
    "cursor",
    "copilot",
    "kimi",
    "devin",
    "zcode",
    "openclaw",
    "hermes",
    "cline",
    "opencode",
    "grok",
    "pi",
    "omp",
    "muse",
];
const OTHER: &str = "other";
/// The reasons a bridge names for a hook the resident did not answer.
const MISS_CODES: [&str; 10] = [
    "disabled",
    "event",
    "request",
    "no_state",
    "no_resident",
    "token",
    "late",
    "send",
    "defer",
    "unanswered",
];
const UNKNOWN_MISS: &str = "unknown";
const LOG_EVENT: &str = "hook_route_counters";
const LOG_INTERVAL: Duration = Duration::from_secs(300);

/// Received hooks and miss reasons, by harness slot.
#[derive(Default, Clone, PartialEq, Eq)]
pub(super) struct Counts {
    received: BTreeMap<&'static str, u64>,
    missed: BTreeMap<&'static str, BTreeMap<&'static str, u64>>,
}

impl Counts {
    pub(super) fn note(&mut self, harness: &str, miss: Option<&str>) {
        let slot = slot(harness);
        *self.received.entry(slot).or_default() += 1;
        if let Some(miss) = miss {
            let code = MISS_CODES
                .iter()
                .copied()
                .find(|code| *code == miss)
                .unwrap_or(UNKNOWN_MISS);
            *self
                .missed
                .entry(slot)
                .or_default()
                .entry(code)
                .or_default() += 1;
        }
    }

    pub(super) fn detail(&self) -> String {
        json!({"received": self.received, "missed": self.missed}).to_string()
    }
}

/// The slot a harness name counts under; any unknown name is `other`.
pub(super) fn slot(harness: &str) -> &'static str {
    NAMED_SLOTS
        .iter()
        .copied()
        .find(|slot| *slot == harness)
        .unwrap_or(OTHER)
}

struct State {
    counts: Counts,
    logged: Option<Counts>,
    logged_at: Option<Instant>,
}

fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(State {
            counts: Counts::default(),
            logged: None,
            logged_at: None,
        })
    })
}

/// Counts one hook the route received, then logs the counts when they
/// changed and the interval has passed. The interval also paces retries:
/// a line the log refused is written again only after it.
pub(super) fn note_received(guard_home: &Path, harness: &str, miss: Option<&str>) {
    let Ok(mut state) = state().lock() else {
        return;
    };
    state.counts.note(harness, miss);
    let now = Instant::now();
    if state
        .logged_at
        .is_some_and(|logged_at| now.duration_since(logged_at) < LOG_INTERVAL)
        || state.logged.as_ref() == Some(&state.counts)
    {
        return;
    }
    state.logged_at = Some(now);
    let current = state.counts.clone();
    if super::super::writes::record_diagnostic(guard_home, LOG_EVENT, Some(&current.detail()))
        .is_ok()
    {
        state.logged = Some(current);
    }
}

/// `get_adapter(name).harness`: the adapter a harness name or alias
/// resolves to, or `other` for a name no adapter claims.
pub(super) fn capacity_harness(name: &str) -> &'static str {
    match name {
        "codex" => "codex",
        "claude-code" | "claude" => "claude-code",
        "copilot" => "copilot",
        "cursor" => "cursor",
        "cline" | "cline-cli" | "cline-vscode" => "cline",
        "devin" | "devin-cli" | "cognition-devin" => "devin",
        "antigravity" => "antigravity",
        "gemini" => "gemini",
        "grok" | "grok-build" | "grok-build-cli" | "xai-grok" => "grok",
        "hermes" => "hermes",
        "kimi" | "kimi-code" | "kimi-cli" => "kimi",
        "omp" | "oh-my-pi" => "omp",
        "pi" | "pi-agent" | "pi-coding-agent" => "pi",
        "openclaw" => "openclaw",
        "opencode" => "opencode",
        "zcode" | "zai" | "z-code" | "zai-zcode" => "zcode",
        "paseo" => "paseo",
        "muse" | "muse-code" => "muse",
        _ => OTHER,
    }
}

#[cfg(test)]
#[path = "daemon_edge_hook_counters_tests.rs"]
mod tests;
