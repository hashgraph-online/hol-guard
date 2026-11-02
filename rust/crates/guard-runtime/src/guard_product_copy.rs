//! `guard_product_copy` runner-authority kind: the decisions and copy of the
//! `hol-guard start`/`status` product payload. Ported from `cli/product.py`
//! (`_recommended_harness`, `_approval_experience_rank`, `_resolve_next_action`,
//! `_build_next_steps`, `_resolve_runtime_status`, `_resolve_guard_urls`,
//! `_cloud_state_label` and `_cloud_state_detail`, plus the per-harness
//! command strings).
//!
//! Python still detects harnesses and reads the store, then ships:
//!
//! - `harnesses`: one fact object per harness summary, with `harness`,
//!   `installed`, `command_available`, `managed`, `scanned` (false for a
//!   summary built from a managed install without a scan), `artifact_count`,
//!   `review_count`, `warning_count` and `approval_flow`;
//! - `cloud_state`, `sync_url` (or `null`) and the boolean repair flags
//!   `oauth_repair_required`, `connect_retry_required`,
//!   `connect_retry_refresh_race` and `shared_proof_recorded`;
//! - `approval_center_url` (or `null`) and `runtime_state_present`;
//! - `include_steps`.
//!
//! The answer carries the derived fields of each harness, the index of the
//! recommended harness, the runtime status, the cloud copy and URLs, and the
//! next steps when they were asked for.

use serde_json::{json, Map, Value};

use crate::cloud_request_text::py_truthy;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};
use crate::runner_sync_url::urlsplit;

const GUARD_COMMAND: &str = "hol-guard";
const GUARD_DASHBOARD_URL: &str = "https://hol.org/guard";
const HARNESS_PRIORITY: [&str; 8] = [
    "codex",
    "claude-code",
    "copilot",
    "hermes",
    "cursor",
    "antigravity",
    "gemini",
    "opencode",
];

struct Harness<'a> {
    name: &'a str,
    installed: bool,
    command_available: bool,
    managed: bool,
    scanned: bool,
    artifact_count: u64,
    review_count: u64,
    warning_count: u64,
    approval_flow: Option<&'a Value>,
}

struct Cloud<'a> {
    state: &'a str,
    oauth_repair_required: bool,
    connect_retry_required: bool,
    connect_retry_refresh_race: bool,
    shared_proof_recorded: bool,
}

struct Urls {
    dashboard: String,
    connect: String,
    inbox: String,
    fleet: String,
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let flag = |key: &str| args.get(key).and_then(Value::as_bool).ok_or(ERR_INVALID);
    let harnesses = args
        .get("harnesses")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(harness)
        .collect::<Result<Vec<_>, _>>()?;
    let cloud = Cloud {
        state: args
            .get("cloud_state")
            .and_then(Value::as_str)
            .ok_or(ERR_INVALID)?,
        oauth_repair_required: flag("oauth_repair_required")?,
        connect_retry_required: flag("connect_retry_required")?,
        connect_retry_refresh_race: flag("connect_retry_refresh_race")?,
        shared_proof_recorded: flag("shared_proof_recorded")?,
    };
    let sync_url = nullable_text(args, "sync_url")?;
    let approval_center_url = nullable_text(args, "approval_center_url")?;
    let runtime_state_present = flag("runtime_state_present")?;
    let include_steps = flag("include_steps")?;

    let urls = guard_urls(sync_url);
    let actions: Vec<&str> = harnesses.iter().map(next_action).collect();
    let recommended = recommended_harness(&harnesses);
    let steps = include_steps.then(|| {
        next_steps(
            recommended.map(|index| (harnesses[index].name, actions[index])),
            cloud.state,
            &urls,
        )
    });
    Ok(json!({
        "harnesses": harnesses
            .iter()
            .zip(&actions)
            .map(|(item, action)| harness_fields(item.name, action))
            .collect::<Vec<_>>(),
        "recommended": recommended,
        "runtime_status": runtime_status(approval_center_url, runtime_state_present),
        "cloud_state_label": cloud_state_label(cloud.state),
        "cloud_state_detail": cloud_state_detail(&cloud, &urls),
        "dashboard_url": urls.dashboard,
        "connect_url": urls.connect,
        "inbox_url": urls.inbox,
        "fleet_url": urls.fleet,
        "next_steps": steps,
    }))
}

fn nullable_text<'a>(
    args: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, &'static str> {
    match args.get(key) {
        Some(Value::String(text)) => Ok(Some(text)),
        Some(Value::Null) => Ok(None),
        _ => Err(ERR_INVALID),
    }
}

fn harness(value: &Value) -> Result<Harness<'_>, &'static str> {
    let item = value.as_object().ok_or(ERR_INVALID)?;
    let flag = |key: &str| item.get(key).and_then(Value::as_bool).ok_or(ERR_INVALID);
    let count = |key: &str| item.get(key).and_then(Value::as_u64).ok_or(ERR_INVALID);
    Ok(Harness {
        name: item
            .get("harness")
            .and_then(Value::as_str)
            .ok_or(ERR_INVALID)?,
        installed: flag("installed")?,
        command_available: flag("command_available")?,
        managed: flag("managed")?,
        scanned: flag("scanned")?,
        artifact_count: count("artifact_count")?,
        review_count: count("review_count")?,
        warning_count: count("warning_count")?,
        approval_flow: item.get("approval_flow"),
    })
}

/// `_resolve_next_action` for a scanned harness; a managed install without
/// a scan is reviewed when its manifest names missing files.
fn next_action(item: &Harness<'_>) -> &'static str {
    if !item.scanned {
        return if !item.managed {
            "install"
        } else if item.warning_count == 0 {
            "run"
        } else {
            "review"
        };
    }
    if !item.managed {
        if !item.installed && !item.command_available {
            return "install-harness";
        }
        return "install";
    }
    if item.review_count > 0 {
        "review"
    } else {
        "run"
    }
}

fn harness_fields(name: &str, action: &str) -> Value {
    json!({
        "next_action": action,
        "install_command": format!("{GUARD_COMMAND} install {name}"),
        "run_command": format!("{GUARD_COMMAND} run {name} --dry-run"),
        "review_command": format!("{GUARD_COMMAND} diff {name}"),
        "receipts_command": format!("{GUARD_COMMAND} receipts"),
    })
}

/// `_recommended_harness`: the first harness with the smallest sort key.
fn recommended_harness(harnesses: &[Harness<'_>]) -> Option<usize> {
    let key = |item: &Harness<'_>| {
        (
            u8::from(!item.installed),
            u8::from(item.artifact_count == 0),
            approval_experience_rank(item.approval_flow),
            HARNESS_PRIORITY
                .iter()
                .position(|name| *name == item.name)
                .unwrap_or(HARNESS_PRIORITY.len()),
            u8::from(!item.command_available),
        )
    };
    let mut best: Option<(usize, _)> = None;
    for (index, item) in harnesses.iter().enumerate() {
        let candidate = key(item);
        if best
            .as_ref()
            .is_none_or(|(_, current)| candidate < *current)
        {
            best = Some((index, candidate));
        }
    }
    best.map(|(index, _)| index)
}

/// `str(flow.get(key) or default)`, or `None` for a non-text value, whose
/// Python spelling never names a known channel or tier.
fn flow_text<'a>(flow: &'a Map<String, Value>, key: &str, default: &'a str) -> Option<&'a str> {
    match flow.get(key) {
        Some(value) if py_truthy(value) => value.as_str(),
        _ => Some(default),
    }
}

/// `_approval_experience_rank`: native prompts first, the browser last.
fn approval_experience_rank(flow: Option<&Value>) -> u8 {
    let Some(flow) = flow.and_then(Value::as_object) else {
        return 4;
    };
    let prompt_channel = flow_text(flow, "prompt_channel", "browser");
    let tier = flow_text(flow, "tier", "approval-center");
    let auto_open_browser = flow.get("auto_open_browser").is_none_or(py_truthy);
    let native_prompt = matches!(prompt_channel, Some("native" | "hook"));
    if native_prompt && matches!(tier, Some("native-harness" | "native-or-center" | "mixed")) {
        return 0;
    }
    if native_prompt && !auto_open_browser {
        return 1;
    }
    if !auto_open_browser {
        return 2;
    }
    if tier == Some("approval-center") {
        return 3;
    }
    4
}

fn runtime_status(approval_center_url: Option<&str>, runtime_state_present: bool) -> &'static str {
    if approval_center_url.is_some_and(|url| !url.is_empty()) {
        "active"
    } else if runtime_state_present {
        "stale"
    } else {
        "offline"
    }
}

/// `_resolve_guard_urls`: the Guard pages on the sync URL's origin.
fn guard_urls(sync_url: Option<&str>) -> Urls {
    let origin = sync_url
        .filter(|url| !url.is_empty())
        .map(urlsplit)
        .filter(|split| !split.scheme.is_empty() && !split.netloc.is_empty())
        .map(|split| format!("{}://{}", split.scheme, split.netloc));
    let dashboard = origin.map_or_else(
        || GUARD_DASHBOARD_URL.to_owned(),
        |origin| format!("{origin}/guard"),
    );
    Urls {
        connect: format!("{dashboard}/connect"),
        inbox: format!("{dashboard}/inbox"),
        fleet: format!("{dashboard}/protect"),
        dashboard,
    }
}

fn cloud_state_label(cloud_state: &str) -> &'static str {
    match cloud_state {
        "paired_waiting" => "Connected, waiting for first sync",
        "paired_active" => "Connected and active",
        _ => "Local only",
    }
}

fn cloud_state_detail(cloud: &Cloud<'_>, urls: &Urls) -> String {
    let connect_url = &urls.connect;
    if cloud.oauth_repair_required {
        return format!(
            "Guard Cloud sign-in on this machine is incomplete. Run `{GUARD_COMMAND} connect` or \
             reopen {connect_url} to repair local authorization and resume sync."
        );
    }
    if cloud.connect_retry_refresh_race {
        return format!(
            "Local Guard remains available. The first shared Guard Cloud proof stalled after a \
             refresh-token race. Run `{GUARD_COMMAND} connect` or reopen {connect_url} when you \
             want shared proof restored."
        );
    }
    if cloud.connect_retry_required {
        // `resolve_guard_cloud_repair_detail`.
        return if cloud.shared_proof_recorded {
            format!(
                "Guard Cloud connection on this machine needs repair before shared proof can \
                 resume. Run `{GUARD_COMMAND} connect` or reopen {connect_url} to restore sync."
            )
        } else {
            format!(
                "Guard Cloud connection on this machine needs repair before the first shared \
                 proof can land. Run `{GUARD_COMMAND} connect` or reopen {connect_url} to repair \
                 the first sync."
            )
        };
    }
    match cloud.state {
        "paired_waiting" => format!(
            "Guard Cloud credentials are saved, but this machine has not finished the first shared \
             sync yet. Keep Local Guard running so it can retry automatically, or run \
             `{GUARD_COMMAND} sync` to force a retry now."
        ),
        "paired_active" => format!(
            "Guard is paired with Guard Cloud. Use the local CLI for protection and the signed-in \
             command center at {} for Home, Inbox, Fleet, Evidence, upgrades, and team workflows.",
            urls.dashboard
        ),
        _ => format!(
            "Local Guard is active and keeps receipts on this machine. Guard Cloud is optional; \
             run `{GUARD_COMMAND} connect` when you want shared history, live advisories, or team \
             policy."
        ),
    }
}

fn step(title: String, command: String, detail: String) -> Value {
    json!({"title": title, "command": command, "detail": detail})
}

/// `_build_next_steps` for the recommended harness and its next action.
fn next_steps(recommended: Option<(&str, &str)>, cloud_state: &str, urls: &Urls) -> Vec<Value> {
    let Some((harness, action)) = recommended else {
        return vec![step(
            "Install a supported harness".to_owned(),
            format!("{GUARD_COMMAND} detect"),
            "Guard did not find a local harness config yet. Start by installing Codex, Claude \
             Code, Copilot CLI, Hermes, Cursor, Antigravity, Gemini, or OpenCode."
                .to_owned(),
        )];
    };
    let first = match action {
        "review" => step(
            format!("Review changed {harness} tools"),
            format!("{GUARD_COMMAND} diff {harness}"),
            "Guard found changes since the last approval. Review them before the next launch."
                .to_owned(),
        ),
        "install-harness" => step(
            format!("Install {harness}"),
            format!("{GUARD_COMMAND} detect"),
            "Guard needs a local harness install before it can protect launches.".to_owned(),
        ),
        _ => step(
            format!("Install Guard for {harness}"),
            format!("{GUARD_COMMAND} install {harness}"),
            "Create a local launcher shim so Guard runs before the harness starts.".to_owned(),
        ),
    };
    let cloud = if cloud_state == "local_only" {
        step(
            "Optional cloud connect".to_owned(),
            format!("{GUARD_COMMAND} connect"),
            "Keep local protection free by default, then run one command when you want shared \
             inbox state, fleet continuity, evidence, or team policy."
                .to_owned(),
        )
    } else {
        step(
            "Open Guard Home".to_owned(),
            urls.dashboard.clone(),
            "Guard Cloud is already paired. Use the signed-in command center for Home, Fleet, \
             Evidence, and upgrades."
                .to_owned(),
        )
    };
    vec![
        first,
        step(
            "Run Guard before launch".to_owned(),
            format!("{GUARD_COMMAND} run {harness} --dry-run"),
            format!(
                "Dry-run {harness} once so Guard records the current tool state before you rely \
                 on it."
            ),
        ),
        step(
            "Inspect receipts".to_owned(),
            format!("{GUARD_COMMAND} receipts"),
            "See what Guard approved, blocked, or flagged after local runs.".to_owned(),
        ),
        step(
            "Resolve queued approvals".to_owned(),
            format!("{GUARD_COMMAND} approvals"),
            "Use the local approval center or the approvals queue when a harness session cannot \
             prompt inline."
                .to_owned(),
        ),
        cloud,
    ]
}

#[cfg(test)]
#[path = "guard_product_copy_tests.rs"]
mod tests;
