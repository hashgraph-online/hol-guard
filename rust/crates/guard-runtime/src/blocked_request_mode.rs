//! `safe_alternative_reason` from `blocked_request_mode.py`: the deny text a
//! safe-alternative blocked request returns to the agent.

use crate::guard_store_json::py_strip;

/// `SAFE_ALTERNATIVE_GUIDANCE`.
const SAFE_ALTERNATIVE_GUIDANCE: &str = "This action remains blocked. Continue with a safe, \
     permitted alternative that respects the same protection. Do not retry an equivalent \
     command, bypass Guard, or seek permission to run it. If no safe alternative can complete \
     the task, explain the limitation.";
/// `_APPROVAL_WAIT`.
const APPROVAL_WAIT: &str = "It is waiting for the user to approve it in the HOL Guard inbox \
     (`hol-guard approvals`). Do not retry the same action until it is approved; continue with \
     other work meanwhile.";
/// `_NOT_QUEUED`.
const NOT_QUEUED: &str = "No approval is waiting in HOL Guard for this action. Do not retry it \
     or work around the block; continue with a permitted alternative or tell the user what is \
     blocked.";

/// `_REASON_CODE_HINTS`: plain-language next steps keyed by the native
/// decision's reason code; unknown codes have none.
fn reason_code_hint(reason_code: &str) -> &'static str {
    match reason_code {
        "native_destructive_command" => {
            "This command deletes or overwrites data. Use `git worktree remove` for a worktree, \
             or target one specific path."
        }
        "native_package_review" => {
            "Package installs download code from a registry, so Guard reviews them. An install \
             that only restores the committed lockfile and runs no scripts (`bun install \
             --frozen-lockfile --ignore-scripts`, `pnpm install --frozen-lockfile \
             --ignore-scripts` or `npm ci --ignore-scripts`) can proceed once Guard has checked \
             the lockfile and settings. If this was already that form, reuse dependencies that \
             are already installed where you can."
        }
        "native_network_review" => "This makes a network request that Guard has not seen before.",
        "native_file_read_review" => "This reads a file outside what Guard treats as safe to read.",
        "native_pre_tool_unknown_review" => "Guard does not recognize this tool call.",
        "native_command_review_required" => {
            "Guard could not prove this exact command is read-only. Use a simpler built-in tool \
             where one fits."
        }
        _ => "",
    }
}

/// `safe_alternative_reason(reason, reason_code=..., approval_queued=...)`.
pub(crate) fn safe_alternative_reason(
    reason: &str,
    reason_code: Option<&str>,
    approval_queued: Option<bool>,
) -> String {
    let reason = py_strip(reason);
    if reason_code.is_none() && approval_queued.is_none() {
        return py_strip(&format!("{reason} {SAFE_ALTERNATIVE_GUIDANCE}")).to_owned();
    }
    let hint = reason_code_hint(reason_code.unwrap_or_default());
    let wait = if approval_queued == Some(true) {
        APPROVAL_WAIT
    } else {
        NOT_QUEUED
    };
    [reason, hint, wait]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}
