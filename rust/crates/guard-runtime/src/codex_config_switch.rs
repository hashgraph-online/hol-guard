//! The two Codex config switches CIGAR offers: lean sessions (the compaction
//! limit the user picks) and short replies.
//!
//! `transition_files` owns each change (`publication_lean_sessions`,
//! `publication_short_replies`). A change first takes the lock Guard's Codex
//! install takes, as an install owner that finishes an interrupted hook
//! install before anything reads the config, so the two never write the
//! config file at the same time. Reads take no lock.
//!
//! The dashboard routes, the settings save that turns CIGAR on and
//! `hol-guard context lean` all come through here.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{json, Map, Value};

#[path = "codex_config_switch_op.rs"]
mod op;
#[cfg(test)]
#[path = "codex_config_switch_tests.rs"]
mod tests;

pub(crate) use op::dispatch;

/// Another change holds the Codex config lock.
pub(crate) const BUSY: &str = "codex_config_busy";
/// Guard could not read or change the Codex config.
pub(crate) const UNAVAILABLE: &str = "codex_config_unavailable";
/// An interrupted hook install needs `hol-guard` to finish it first.
pub(crate) const HOOKS: &str = "codex_hooks_need_recovery";
/// How long a change waits for the Codex config lock.
const LOCK_WAIT_MS: u64 = 5_000;
const ACTOR: &str = "lean-sessions";

/// Which switch a request is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Switch {
    Lean,
    ShortReplies,
}

impl Switch {
    fn op(self) -> &'static str {
        match self {
            Self::Lean => "publication_lean_sessions",
            Self::ShortReplies => "publication_short_replies",
        }
    }
}

/// The folders a switch reads: the Guard home, the user's home and
/// `CODEX_HOME` as the caller's environment sets it.
#[derive(Clone, Debug)]
pub(crate) struct Homes {
    pub(crate) guard_home: PathBuf,
    pub(crate) home_dir: PathBuf,
    pub(crate) codex_home: Option<String>,
}

impl Homes {
    /// The homes for a caller whose working folder is this process's: Codex
    /// resolves a relative `CODEX_HOME` from the folder it runs in.
    pub(crate) fn here(guard_home: &Path, home_dir: &Path, codex_home: Option<String>) -> Self {
        let codex_home = codex_home.map(|raw| {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('~') {
                return raw;
            }
            std::path::absolute(trimmed)
                .map_or(raw.clone(), |path| path.to_string_lossy().into_owned())
        });
        Self {
            guard_home: guard_home.to_path_buf(),
            home_dir: home_dir.to_path_buf(),
            codex_home,
        }
    }
}

fn files(request: Value) -> Result<Map<String, Value>, String> {
    match crate::transition_files::dispatch(&request) {
        Ok(Value::Object(answer)) => Ok(answer),
        _ => Err(UNAVAILABLE.to_owned()),
    }
}

/// One publication op; a refusal the user can act on comes back as its code.
fn publication(
    switch: Switch,
    homes: &Homes,
    action: &str,
    limit: Option<&Value>,
    owner: Option<&Owner>,
) -> Result<Value, String> {
    let mut request = json!({
        "op": switch.op(),
        "home": homes.guard_home.to_string_lossy(),
        "action": action,
        "home_dir": homes.home_dir.to_string_lossy(),
        "codex_home": homes.codex_home,
    });
    if let Some(limit) = limit {
        request["limit"] = limit.clone();
    }
    let answer = files(request)?;
    let events = answer.get("events").and_then(Value::as_array);
    let mutations: Vec<Value> = events
        .into_iter()
        .flatten()
        .filter_map(|event| event.get("mutation").cloned())
        .collect();
    if let Some(owner) = owner {
        owner.record(mutations.clone());
    }
    if answer.get("ok") != Some(&Value::Bool(true))
        || events.is_none_or(|events| events.len() != mutations.len())
    {
        return Err(UNAVAILABLE.to_owned());
    }
    let value = answer.get("value").cloned().unwrap_or(Value::Null);
    if let Some(code) = value.get("error").and_then(Value::as_str) {
        return Err(code.to_owned());
    }
    Ok(value)
}

/// The switch as the config has it now.
pub(crate) fn status(switch: Switch, homes: &Homes) -> Result<Value, String> {
    publication(switch, homes, "status", None, None)
}

/// The runtime's check of a size the user picked: there is no default.
pub(crate) fn check_limit(limit: Option<&Value>) -> Result<Value, String> {
    let homes = Homes {
        guard_home: std::env::temp_dir(),
        home_dir: std::env::temp_dir(),
        codex_home: None,
    };
    publication(Switch::Lean, &homes, "check", limit, None)
}

/// `enable`, `disable` or (short replies) `ensure`, under the Codex install
/// lock.
pub(crate) fn change(
    switch: Switch,
    homes: &Homes,
    action: &str,
    limit: Option<&Value>,
) -> Result<Value, String> {
    if switch == Switch::Lean && action == "enable" {
        check_limit(limit)?;
    }
    let target = publication(Switch::Lean, homes, "path", None, None)?;
    let target = PathBuf::from(target.as_str().ok_or(UNAVAILABLE)?);
    let owner = Owner::begin(&homes.guard_home, &target)?;
    let changed = publication(switch, homes, action, limit, Some(&owner));
    owner.end(changed.is_ok());
    changed
}

/// This process's hold on the Codex install lock.
struct Owner {
    token: Value,
    leases: Vec<Value>,
    thread: u64,
}

impl Owner {
    fn begin(guard_home: &Path, target: &Path) -> Result<Self, String> {
        // Each change is its own owner thread, so two at once never share one.
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let thread = NEXT.fetch_add(1, Ordering::Relaxed);
        let dirs: Vec<String> = target
            .parent()
            .map(|dir| dir.to_string_lossy().into_owned())
            .into_iter()
            .collect();
        let answer = files(json!({
            "op": "owned_begin",
            "guard_home": guard_home.to_string_lossy(),
            "target": target.to_string_lossy(),
            "actor": ACTOR,
            "process_identity": format!("guard-runtime:{}", std::process::id()),
            "client_pid": std::process::id(),
            "thread": thread,
            "deadline_ms": LOCK_WAIT_MS,
            "dirs": dirs,
            "recover": true,
        }))?;
        if answer.get("ok") != Some(&Value::Bool(true)) {
            return Err(failure(&answer).to_owned());
        }
        let token = answer.get("owner").cloned().ok_or(UNAVAILABLE)?;
        let leases = answer
            .get("leases")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(Self {
            token,
            leases,
            thread,
        })
    }

    /// Journal what the change wrote. A diagnostic: it never replaces the
    /// change's own answer.
    fn record(&self, mutations: Vec<Value>) {
        if mutations.is_empty() {
            return;
        }
        let _ = files(json!({
            "op": "owned_record",
            "owner": self.token,
            "client_pid": std::process::id(),
            "thread": self.thread,
            "mutations": mutations,
        }));
    }

    fn end(self, committed: bool) {
        let ended = files(json!({
            "op": "owned_end",
            "owner": self.token,
            "committed": committed,
        }));
        if ended.is_ok_and(|answer| answer.get("ended") == Some(&Value::Bool(true))) {
            return;
        }
        // The runtime had already forgotten this owner: the leases may remain.
        for lease in self.leases {
            let _ = files(json!({"op": "lease_release", "lease": lease}));
        }
    }
}

/// The user-facing code for a failed `owned_begin`.
fn failure(answer: &Map<String, Value>) -> &'static str {
    match answer
        .get("failure")
        .and_then(|failure| failure.get("kind"))
        .and_then(Value::as_str)
    {
        Some("timeout") => BUSY,
        Some("integrity") => HOOKS,
        _ => UNAVAILABLE,
    }
}

const BILL_NOTE: &str = "Summing up sooner keeps the chat small but can raise the bill: \
Codex reads again, at full price, the files it had already read.";

/// What `hol-guard context lean` prints for a lean sessions state.
pub(crate) fn render_lean(state: &Value) -> String {
    let limit = state.get("limit").and_then(Value::as_u64).unwrap_or(0);
    let lines = match state.get("state").and_then(Value::as_str) {
        Some("on") => vec![
            format!(
                "Guard set Codex to sum up older turns once a session passes {} tokens.",
                crate::context_usage_meter::grouped(limit)
            ),
            BILL_NOTE.to_owned(),
            "Remove it with: hol-guard context lean off".to_owned(),
        ],
        Some("yours") => vec![format!(
            "Your Codex config already sets model_auto_compact_token_limit = {}. Guard left it as it is.",
            state.get("limit").map_or(String::new(), Value::to_string)
        )],
        _ => vec![
            "Off. Codex sums up long sessions on its own schedule.".to_owned(),
            BILL_NOTE.to_owned(),
            "To pick a size anyway: hol-guard context lean on --limit 100000".to_owned(),
        ],
    };
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// What `hol-guard context lean` prints when nothing changed.
pub(crate) fn render_lean_failure(code: &str) -> String {
    match code {
        "codex_lean_limit_required" => "Pick a size: hol-guard context lean on --limit 100000. \
Guard sets no size of its own. Nothing was changed."
            .to_owned(),
        "codex_lean_limit_invalid" => {
            "The limit must be a whole number from 10,000 to 10,000,000. Nothing was changed."
                .to_owned()
        }
        code => format!("Guard could not change the Codex config ({code}). Nothing was changed."),
    }
}
