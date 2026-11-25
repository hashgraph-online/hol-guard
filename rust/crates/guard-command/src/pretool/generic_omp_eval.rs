//! Literal-only parser for Oh My Pi's `eval` bridge.
//!
//! OMP's Codex-style code mode routes tool calls through one JavaScript
//! program, so the host hook sees only an opaque `eval`. This module accepts
//! a deliberately tiny language: statements built from `tool.read`,
//! `tool.grep`, `tool.glob` and `tool.bash` calls whose arguments are object
//! literals of scalar literals, the SDK's `await read(literal_path)` helper, or
//! the prelude's `await sh(literal_command)` shell helper,
//! plus `display`/`log`, `const`/`let` bindings,
//! `Promise.all`, `JSON.stringify`, `.text` and `.length`. Every extracted call is then
//! evaluated as the equivalent standalone tool, through the same entry point
//! a direct call takes, so a bridged `bash` call's `cwd` is resolved exactly
//! as the direct `bash` tool's; any non-allow reviews the
//! whole program, except a bridged `bash` call that would run under Guard
//! containment on its own, since the bridge re-hooks it. Everything else,
//! including comments, templates with interpolation, operators, other identifiers and other languages, is
//! rejected rather than interpreted. A `py` program may only be whole lines of
//! the Python prelude's `read(literal_path)`, optionally inside `print` or
//! `display`.

use super::{strict_tool_input, OmpContext};
use crate::pretool::generic::extract::GenericSignals;
use crate::pretool::generic::result::{generic_action, generic_result};
use guard_contracts::{PreToolActionTypeV1, PreToolOperationV1, PreToolResultV1};
use serde_json::{json, Map, Value};

#[path = "generic_omp_eval_browser.rs"]
mod browser;
#[path = "generic_omp_eval_parser.rs"]
mod parser;
#[path = "generic_omp_eval_pure.rs"]
mod pure;
#[path = "generic_omp_eval_tokens.rs"]
mod tokens;
use parser::{parse_program, parse_python, uses_earlier_cell_draft, Call, Lit};

/// The command an Oh My Pi `commit` draft stands for. The prelude reads the
/// worktree and writes objects, an index of its own and the branch ref, so it
/// may start what `git add` and `git commit` start: clean filters, an
/// fsmonitor, hooks and a signing program. The message is a placeholder; the
/// real one is literal text that runs nothing.
const COMMIT_PRELUDE_COMMAND: &str = "git add -A && git commit -m 'omp eval commit'";

/// Map one literal call onto the equivalent standalone tool payload.
fn standalone_payload(call: &Call, context: &OmpContext<'_>) -> Option<Value> {
    if call.tool == "commit" {
        // The draft's repository runs Git the way a `bash` call in that
        // directory would, so the `bash` tool's own `cwd` proof resolves it.
        let mut input = Map::new();
        input.insert("command".to_owned(), json!(COMMIT_PRELUDE_COMMAND));
        for (key, lit) in &call.args {
            match (key.as_str(), lit) {
                ("cwd", Lit::Str(repo)) if context.harness == "omp" => {
                    input.insert("cwd".to_owned(), json!(repo));
                }
                _ => return None,
            }
        }
        return Some(json!({"tool_name": "bash", "tool_input": Value::Object(input)}));
    }
    let mut input = Map::new();
    for (key, lit) in &call.args {
        let allowed_string = match call.tool.as_str() {
            "read" => &["path"][..],
            "grep" => &["pattern", "path", "glob", "type"][..],
            "glob" => &["pattern", "path"][..],
            // The shell inherits the workspace; only an explicit `.` matches.
            _ => &["command", "cwd"][..],
        };
        match lit {
            // OMP's session-tool wrapper accepts a literal intent label.
            Lit::Str(text) if key == "i" => {
                input.insert(key.clone(), Value::String(text.clone()));
            }
            Lit::Str(text) if allowed_string.contains(&key.as_str()) => {
                if call.sdk_read_helper
                    && text.contains(':')
                    && !super::host_refs::tool_docs_url(text)
                {
                    let path = std::path::Path::new(text);
                    let candidate = if path.is_absolute() {
                        path.to_path_buf()
                    } else {
                        std::path::Path::new(context.path.cwd?).join(path)
                    };
                    // A colon can be a literal filename, but the SDK never
                    // strips read selectors. Prove that the exact file exists.
                    if !candidate.is_file() {
                        return None;
                    }
                }
                if call.tool == "bash" && key == "cwd" {
                    // `.` is the session directory everywhere. Oh My Pi's
                    // bridge hands any other `cwd` to the same `bash` tool,
                    // whose standalone proof resolves it; other harnesses
                    // have no such argument to model.
                    if text == "." {
                        continue;
                    }
                    if context.harness != "omp" {
                        return None;
                    }
                }
                input.insert(key.clone(), Value::String(text.clone()));
            }
            Lit::Str(_) => return None,
            // Only modeled options on read-only tools survive; the shell and
            // unknown options are reviewed rather than silently dropped.
            Lit::Scalar(value) if super::modeled_scalar(&call.tool, key, value) => {
                input.insert(key.clone(), value.clone());
            }
            Lit::Scalar(_) => return None,
        }
    }
    let required = match call.tool.as_str() {
        "read" => "path",
        "grep" => "pattern",
        "bash" => "command",
        _ => "",
    };
    if !required.is_empty() && !input.contains_key(required) {
        return None;
    }
    Some(json!({"tool_name": call.tool, "tool_input": Value::Object(input)}))
}

/// A JavaScript eval that only drives OMP's isolated browser against
/// loopback pages. URLs in such a program are checked by the parser, so this
/// runs before the generic URL bail-out.
pub(super) fn evaluate_browser(
    payload: &Value,
    context: &OmpContext<'_>,
) -> Option<PreToolResultV1> {
    let input = strict_tool_input(payload)?;
    let modeled = input.iter().all(|(key, value)| match key.as_str() {
        "code" | "language" => value.is_string(),
        "title" => value.is_string() || value.is_null(),
        "reset" => value.is_boolean() || value.is_null(),
        "timeout" => value.is_number() || value.is_null(),
        _ => false,
    });
    if !modeled
        || input.get("language")?.as_str()? != "js"
        || !browser::loopback_browser_program(input.get("code")?.as_str()?, context.path.home_dir)
    {
        return None;
    }
    Some(generic_result(
        generic_action(
            context.harness,
            context.event,
            PreToolActionTypeV1::Harness,
            PreToolOperationV1::Read,
            true,
            false,
        ),
        "allow",
        "native_omp_eval_loopback_browser",
        "The Rust authority read this eval program and found only isolated-browser reads and interactions on loopback pages and GET requests to loopback URLs, with page functions that run inside the page: no files, processes, modules or other hosts.",
    ))
}

/// The review reason for a JavaScript cell that calls draft methods on a name
/// an earlier cell bound. Each cell is judged alone, so the review stays; the
/// reason names the one-cell form Guard can check. `None` for anything else,
/// which keeps the ordinary eval review reason.
pub(super) fn earlier_cell_draft_reason(payload: &Value) -> Option<&'static str> {
    let input = strict_tool_input(payload)?;
    let code = input.get("code")?.as_str()?;
    (input.get("language")?.as_str()? == "js"
        && parse_program(code).is_none()
        && uses_earlier_cell_draft(code))
    .then_some(EARLIER_CELL_DRAFT_REASON)
}

const EARLIER_CELL_DRAFT_REASON: &str = "HOL Guard requires review because this eval cell uses a commit draft made in an earlier cell, and Guard checks each cell on its own, so it cannot confirm the name still holds that draft. Make the draft and use it in the same cell instead, for example: const d = await commit.draft(); await d.take('path/to/file'); await d.commit('subject', ['body line']). Guard checks that cell as one local git commit.";

pub(super) fn evaluate(
    payload: &Value,
    signals: &GenericSignals,
    context: &OmpContext<'_>,
) -> Option<PreToolResultV1> {
    if !signals.path_values.is_empty() {
        return None;
    }
    let input = strict_tool_input(payload)?;
    let language = input.get("language")?.as_str()?;
    if !matches!(language, "js" | "py")
        || !input.iter().all(|(key, value)| match key.as_str() {
            "code" | "language" => value.is_string(),
            // Codex-style code mode sends `null` for an optional field the
            // model left unset; it means the default, like an absent key.
            "title" => value.is_string() || value.is_null(),
            "reset" => value.is_boolean() || value.is_null(),
            "timeout" => value.is_number() || value.is_null(),
            _ => false,
        })
    {
        return None;
    }
    let code = input.get("code")?.as_str()?;
    let calls = if language == "py" {
        match parse_python(code) {
            Some(calls) => calls,
            None if pure::pure_python(code) => {
                return Some(generic_result(
                    generic_action(
                        context.harness,
                        context.event,
                        PreToolActionTypeV1::Harness,
                        PreToolOperationV1::Read,
                        true,
                        false,
                    ),
                    "allow",
                    "native_omp_eval_pure_compute",
                    "The Rust authority read this eval program and found only in-memory computation: no files, processes, network or environment.",
                ));
            }
            None => return None,
        }
    } else {
        parse_program(code)?
    };
    let mut evaluated = Vec::with_capacity(calls.len());
    let mut saw_unmodeled_call = false;
    for call in &calls {
        // A malformed sibling call cannot erase a protection verdict already
        // established for a literal sh() command elsewhere in this eval.
        let Some(inner) = standalone_payload(call, context) else {
            saw_unmodeled_call = true;
            continue;
        };
        // The `commit` prelude runs Git in the harness process, where no
        // sandbox can reach it, so it is judged without containment.
        let _in_process = (call.tool == "commit").then(crate::pretool::in_process_scope::scope);
        // The entry point a direct call takes, so the bridged call gets the
        // same `cwd` resolution and compound re-judging as that call.
        let result = crate::pretool::generic::evaluate_pre_tool_envelope_with_execution_context(
            context.harness,
            context.event,
            &inner,
            context.controls,
            context.deadline,
            context.path,
            context.execution_environment,
        );
        evaluated.push((call, result));
    }
    // Wherever an `sh()` call sits in the program, its protection verdict
    // decides the whole program.
    if let Some(stopped) = evaluated
        .iter()
        .filter(|(call, _)| call.shell_helper)
        .find_map(|(_, result)| shell_helper_protection(result, context))
    {
        return Some(stopped);
    }
    // Unsupported calls still require an unknown-program review. Only an
    // established sh() block may take precedence over that fallback.
    if saw_unmodeled_call {
        return None;
    }
    if let Some(verdict) = draft_only_verdict(&evaluated, context) {
        return verdict;
    }
    let mut ran_shell = false;
    for (call, result) in evaluated {
        ran_shell |= matches!(call.tool.as_str(), "bash" | "commit");
        if result.action.sensitive_target {
            return None;
        }
        if result.minimum_action != "allow" && !contained_bash(call, &result) {
            // One bridged call is the whole program, so the bridge adds
            // nothing to judge: the program carries that call's own verdict
            // instead of the unknown-tool review the fall-through gives it,
            // which named no reason the person could act on and left the
            // review without the approval the direct call offers. A program
            // of several calls keeps the fall-through: no single verdict
            // speaks for it. Containment is the inner call's own hook to
            // arrange, so a sandbox verdict keeps the fall-through too.
            // A `commit` draft beside other calls has no single verdict
            // either; a program of drafts alone was answered above.
            return (calls.len() == 1
                && call.tool != "commit"
                && matches!(result.minimum_action.as_str(), "review" | "block"))
            .then_some(result);
        }
    }
    let (action_type, operation) = if ran_shell {
        (PreToolActionTypeV1::Command, PreToolOperationV1::Execute)
    } else {
        (PreToolActionTypeV1::FileRead, PreToolOperationV1::Read)
    };
    Some(generic_result(
        generic_action(context.harness, context.event, action_type, operation, true, false),
        "allow",
        "native_omp_eval_bounded_tools",
        "The Rust authority parsed this eval as literal Oh My Pi tool calls and proved each one allowed, or contained, on its own.",
    ))
}

/// The verdict for a program made only of `commit` drafts, when Git's own
/// rules do not allow every draft. The command extensions judge each draft as
/// the Git write it runs, so the program carries the strongest of those
/// verdicts and its reason, as a direct `git commit` would, not the review for
/// an unknown program. Its approval is bound to the drafts' repositories, not
/// to the program text, by [`omp_eval_commit_drafts`]. `None` leaves the
/// ordinary path to answer, and `Some(None)` sends the program to the
/// unknown-program review: a sensitive target, or a containment verdict the
/// harness process cannot take.
fn draft_only_verdict(
    evaluated: &[(&Call, PreToolResultV1)],
    context: &OmpContext<'_>,
) -> Option<Option<PreToolResultV1>> {
    if evaluated.is_empty() || evaluated.iter().any(|(call, _)| call.tool != "commit") {
        return None;
    }
    let (_, strongest) = evaluated
        .iter()
        .max_by_key(|(_, result)| verdict_rank(&result.minimum_action))?;
    if strongest.minimum_action == "allow" {
        return None;
    }
    if evaluated
        .iter()
        .any(|(_, result)| result.action.sensitive_target)
        || !matches!(
            strongest.minimum_action.as_str(),
            "review" | "require-reapproval" | "block"
        )
    {
        return Some(None);
    }
    let mut verdict = strongest.clone();
    verdict.action = generic_action(
        context.harness,
        context.event,
        PreToolActionTypeV1::Command,
        PreToolOperationV1::Execute,
        true,
        false,
    );
    Some(Some(verdict))
}

fn verdict_rank(action: &str) -> u8 {
    match action {
        "allow" => 0,
        "warn" => 1,
        "review" => 2,
        "require-reapproval" => 3,
        "sandbox-required" => 4,
        _ => 5,
    }
}

/// The repositories an Oh My Pi eval commits to, when the program is nothing
/// but literal `commit` drafts: `""` for the session's repository, else the
/// `repo` option as written. A draft's subject, body and file selection are
/// literal text Git stores and runs nothing, so an approval for such a program
/// is bound to these repositories and holds for the next draft there.
/// `None` for any other tool or program.
pub fn omp_eval_commit_drafts(
    harness: &str,
    tool_name: &str,
    tool_input: &Value,
) -> Option<Vec<String>> {
    if harness != "omp" || tool_name != "eval" {
        return None;
    }
    let input = tool_input.as_object()?;
    let modeled = input.iter().all(|(key, value)| match key.as_str() {
        "code" | "language" => value.is_string(),
        "title" => value.is_string() || value.is_null(),
        "reset" => value.is_boolean() || value.is_null(),
        "timeout" => value.is_number() || value.is_null(),
        _ => false,
    });
    if !modeled || input.get("language")?.as_str()? != "js" {
        return None;
    }
    let calls = parse_program(input.get("code")?.as_str()?)?;
    if calls.is_empty() || calls.iter().any(|call| call.tool != "commit") {
        return None;
    }
    calls
        .iter()
        .map(|call| match call.args.as_slice() {
            [] => Some(String::new()),
            [(key, Lit::Str(repo))] if key == "cwd" => Some(repo.clone()),
            _ => None,
        })
        .collect()
}

/// What stops an `sh()` call outright. The eval shell bridge raises no hook
/// of its own, so the eval is the only call Guard sees, and approving the
/// eval would run whatever it holds. A command the direct call blocks stays
/// blocked. One the direct call would only review because it reaches
/// sensitive local data is blocked too, rather than offered as an approvable
/// eval: the `bash` tool runs the same command under its own review, with
/// Allow once and Always allow, so that is where the person decides.
fn shell_helper_protection(
    result: &PreToolResultV1,
    context: &OmpContext<'_>,
) -> Option<PreToolResultV1> {
    if result.minimum_action == "block" {
        return Some(result.clone());
    }
    if !result.action.sensitive_target || result.minimum_action == "allow" {
        return None;
    }
    Some(generic_result(
        generic_action(
            context.harness,
            context.event,
            PreToolActionTypeV1::Command,
            PreToolOperationV1::Execute,
            true,
            true,
        ),
        "block",
        "native_secret_exfiltration",
        "HOL Guard blocked an eval sh() command that reaches sensitive local data. sh() runs on the eval shell bridge, which Guard cannot review on its own; run the command with the bash tool instead, where Guard reviews it and you can approve it.",
    ))
}

/// Whether a bridged `bash` call needs only the containment its standalone
/// form would get. OMP wraps every tool the eval bridge reaches in its
/// extension gate, so the bridged call raises its own `tool_call` hook and
/// Guard contains it, or refuses to start it, exactly as when the agent
/// calls `bash` directly. Anything that would be reviewed standalone, or a
/// verdict with no containment profile, keeps the whole program reviewed.
fn contained_bash(call: &Call, result: &PreToolResultV1) -> bool {
    // `sh()` runs on the eval shell bridge, which raises no `bash` hook, so
    // nothing would arrange the containment the verdict relies on.
    call.tool == "bash"
        && !call.shell_helper
        && result.minimum_action == "sandbox-required"
        && result.policy_action == "sandbox-required"
        && crate::hook_responses::contained_execution_profile(&result.reason_code).is_some()
}
