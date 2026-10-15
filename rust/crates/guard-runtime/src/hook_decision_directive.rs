//! The generic-hook response directive: which host-facing branch the
//! transport renders, with which emitter and exit code. The transport only
//! executes the named branch; every routing choice is made here.

use guard_contracts::{GuardAction, HookResponseDirectiveV1};

const NATIVE_RESPONSE_HARNESSES: [&str; 8] = [
    "claude-code",
    "codex",
    "kimi",
    "grok",
    "pi",
    "omp",
    "zcode",
    "devin",
];
const EXIT_BLOCK_HARNESSES: [&str; 7] = ["kimi", "grok", "hermes", "pi", "omp", "zcode", "devin"];
const EXIT_TWO_HARNESSES: [&str; 4] = ["cursor", "devin", "kimi", "hermes"];
const EXIT_ONE_HARNESSES: [&str; 2] = ["opencode", "superagent"];
const ENVELOPE_HARNESSES: [&str; 5] = ["codex", "claude-code", "copilot", "pi", "omp"];
const PREEMPTIVE_EVENTS: [&str; 3] = ["PreToolUse", "UserPromptSubmit", "PermissionRequest"];

pub(crate) struct DirectiveFacts<'a> {
    pub(crate) harness: &'a str,
    pub(crate) canonical: &'a str,
    pub(crate) event: &'a str,
    pub(crate) action: GuardAction,
    pub(crate) observed: bool,
    pub(crate) observe_mode: bool,
    pub(crate) has_approval_requests_list: bool,
    pub(crate) json: bool,
    pub(crate) output_stream_present: bool,
    pub(crate) replayed: bool,
}

/// Hook events whose action is decided before the tool runs.
pub(crate) fn is_pre_event(event: &str) -> bool {
    matches!(
        event,
        "PreToolUse" | "preToolUse" | "copilotPermissionRequest"
    )
}

/// Hook events reported after the tool ran.
pub(crate) fn is_post_event(event: &str) -> bool {
    matches!(
        event,
        "PostToolUse"
            | "PostToolUseFailure"
            | "postToolUse"
            | "afterShellExecution"
            | "afterMCPExecution"
    )
}

pub(crate) fn is_blocking(action: GuardAction) -> bool {
    action >= GuardAction::Review
}

fn compact_event(event: &str) -> String {
    event.replace(['_', '-'], "").to_lowercase()
}

fn zcode_exit(action: GuardAction, event: &str) -> i32 {
    let ask = matches!(action, GuardAction::Review | GuardAction::RequireReapproval);
    if compact_event(event) == "pretooluse" && ask {
        0
    } else {
        i32::from(is_blocking(action)) * 2
    }
}

/// The per-harness verdict exit code; `None` leaves grok to its adapter.
fn exit_code(canonical: &str, action: GuardAction, event: &str) -> Option<i32> {
    let blocking = is_blocking(action);
    if canonical == "grok" {
        return None;
    }
    if canonical == "zcode" {
        return Some(zcode_exit(action, event));
    }
    Some(if EXIT_TWO_HARNESSES.contains(&canonical) {
        if blocking {
            2
        } else {
            0
        }
    } else if EXIT_ONE_HARNESSES.contains(&canonical) {
        i32::from(blocking)
    } else if ENVELOPE_HARNESSES.contains(&canonical) {
        i32::from(blocking && !PREEMPTIVE_EVENTS.contains(&event))
    } else {
        i32::from(blocking)
    })
}

fn emitter(canonical: &str) -> &'static str {
    match canonical {
        "grok" => "grok",
        "pi" | "omp" => "pi",
        "zcode" => "zcode",
        "devin" => "devin",
        _ => "default",
    }
}

fn exit_block(f: &DirectiveFacts<'_>) -> bool {
    let compact = compact_event(f.event);
    if !EXIT_BLOCK_HARNESSES.contains(&f.canonical)
        || !matches!(
            compact.as_str(),
            "pretooluse" | "userpromptsubmit" | "pretoolcall"
        )
    {
        return false;
    }
    if f.canonical == "zcode" {
        return zcode_exit(f.action, f.event) == 2;
    }
    is_blocking(f.action)
}

fn native_response(f: &DirectiveFacts<'_>) -> bool {
    let plain =
        f.canonical == "hermes" || (NATIVE_RESPONSE_HARNESSES.contains(&f.canonical) && !f.json);
    let json_native = match f.canonical {
        "grok" | "zcode" => f.json,
        "codex" => {
            f.json
                && (f.event == "UserPromptSubmit"
                    || (f.output_stream_present
                        && matches!(f.event, "PreToolUse" | "Notification")))
        }
        "claude-code" => {
            f.json
                && f.output_stream_present
                && matches!(f.event, "PreToolUse" | "Notification" | "UserPromptSubmit")
        }
        _ => false,
    };
    plain || json_native
}

pub(crate) fn directive(f: &DirectiveFacts<'_>) -> HookResponseDirectiveV1 {
    let blocking = is_blocking(f.action);
    let ask = matches!(
        f.action,
        GuardAction::Review | GuardAction::RequireReapproval
    );
    let silent_exit = f.canonical == "codex" && f.event == "PostToolUse" && !f.json && !blocking;
    let copilot = f.harness == "copilot" && !f.json;
    let early = silent_exit || copilot;
    let exit_block = !early && exit_block(f);
    let route = if silent_exit {
        "silent_exit"
    } else if copilot {
        "copilot"
    } else if exit_block {
        "exit_block"
    } else {
        "render"
    };
    let pre = is_pre_event(f.event);
    let after_json = if native_response(f) {
        "native_response"
    } else if f.event == "PostToolUse" {
        "post_tool_envelope"
    } else {
        "fallback_envelope"
    };
    let mut exit = exit_code(f.canonical, f.action, f.event);
    if route == "render" && after_json == "fallback_envelope" && f.replayed {
        // A replayed decision was recorded upstream; acknowledge without
        // re-blocking the harness.
        exit = Some(0);
    }
    let system_message = if f.canonical == "claude-code"
        && matches!(f.event, "UserPromptSubmit" | "PreToolUse")
        && blocking
    {
        "claude_punctuated"
    } else if f.canonical == "codex" && f.event == "UserPromptSubmit" {
        "codex_prompt"
    } else {
        "none"
    };
    let codex_native_reason = match (f.canonical, f.event) {
        ("codex", "UserPromptSubmit") => "always",
        ("codex", _) => "with_approval_context",
        _ => "never",
    };
    HookResponseDirectiveV1 {
        route: route.to_owned(),
        queue_observe_request: !early && f.observe_mode && pre && f.observed,
        queue_approval_request: !early && pre && ask && !f.has_approval_requests_list,
        emitter: emitter(f.canonical).to_owned(),
        exit_code: exit,
        stderr_only_on_nonzero_exit: f.canonical == "grok",
        codex_native_reason: codex_native_reason.to_owned(),
        include_remediation: blocking,
        terminal_notice: f.canonical == "claude-code" && f.event == "PreToolUse" && ask,
        system_message: system_message.to_owned(),
        try_json_document: f.json && !f.output_stream_present,
        after_json: after_json.to_owned(),
        envelope_decision: if blocking { "block" } else { "allow" }.to_owned(),
    }
}
