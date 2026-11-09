//! Oh My Pi PreToolUse proofs that need the raw tool input: delegation and
//! bookkeeping tools, names-only listings, bounded `grep` scopes, and the
//! literal-only `eval` bridge. Every proof is gated on harness `omp`,
//! `PreToolUse`, and an exact tool name; anything else falls through to the
//! ordinary generic review path. Upstream Pi ships the same `ls`, `find` and
//! `grep` built-ins, so those listing and search proofs also cover harness `pi`.

#[path = "generic_omp_eval.rs"]
mod eval;
#[path = "generic_omp_grep_glob.rs"]
mod grep_glob;
#[path = "generic_omp_learn.rs"]
mod learn;
#[path = "generic_omp_listing_proof.rs"]
mod listing_proof;
#[path = "generic_omp_yield.rs"]
mod yield_report;

use super::extract::GenericSignals;
use super::result::{generic_action, generic_result};
use crate::native_command_controls::CompiledNativeCommandControls;
use guard_contracts::{PreToolActionTypeV1, PreToolOperationV1, PreToolResultV1};
use listing_proof::{listing, search_targets, walk_inside_session};
use serde_json::{Map, Value};
use std::time::Instant;

pub(super) fn yield_signal_payload(payload: &Value) -> Option<Value> {
    yield_report::signal_payload(payload)
}

/// Oh My Pi 18.8 adds `path` and `paths` to an `edit` hook input, copied from
/// the patch's `[PATH#TAG]` headers. They name no new target, so when they
/// match the headers exactly they are dropped and the patch keeps its own
/// proof. Any other value is not Oh My Pi's derivation and stays reviewed.
pub(super) fn edit_signal_payload(payload: &Value) -> Option<Value> {
    if payload.get("tool_name")?.as_str()? != "edit" {
        return None;
    }
    let input = strict_tool_input(payload)?;
    if input.len() < 2
        || !input
            .keys()
            .all(|key| matches!(key.as_str(), "input" | "path" | "paths"))
    {
        return None;
    }
    let headers = super::super::omp_hashline_writes::header_paths(input.get("input")?.as_str()?)?;
    let paths = input.get("paths")?.as_array()?;
    if headers.is_empty()
        || paths.len() != headers.len()
        || !paths
            .iter()
            .zip(&headers)
            .all(|(path, header)| path.as_str() == Some(*header))
    {
        return None;
    }
    match input.get("path") {
        None if headers.len() > 1 => {}
        Some(path) if headers.len() == 1 && path.as_str() == Some(headers[0]) => {}
        _ => return None,
    }
    let projected_input = Map::from_iter([("input".to_owned(), input["input"].clone())]);
    let mut projected = payload.clone();
    for alias in super::extract::EMBEDDED_ARGUMENT_KEYS {
        if projected.get(alias).is_some() {
            projected[alias] = Value::Object(projected_input.clone());
        }
    }
    Some(projected)
}

pub(super) struct OmpContext<'a> {
    pub(super) harness: &'a str,
    pub(super) event: &'a str,
    pub(super) controls: Option<&'a CompiledNativeCommandControls>,
    pub(super) deadline: Option<Instant>,
    pub(super) path: super::super::PathContext<'a>,
    pub(super) execution_environment: Option<&'a guard_contracts::GuardExecutionEnvironmentV1>,
    pub(super) yield_report_verified: bool,
}

/// The acknowledgement of a delegated task adds no executable operation.
/// Any returned content still needs the normal output scan and policy floors.
pub(super) fn bounded_delegation_metadata(payload: &Value) -> bool {
    let Ok(signals) = super::extract::extract_generic_signals(payload) else {
        return false;
    };
    let Some(input) = strict_tool_input(payload) else {
        return false;
    };
    let known_tool = match signals.tool_name.as_deref() {
        Some("task" | "wait" | "todo" | "todo_write") => true,
        Some("learn") => learn_input(input),
        _ => false,
    };
    known_tool
        && !signals.sensitive_target
        && signals.command.is_none()
        && !signals.package_present
        && signals.url_values.is_empty()
        && signals.path_values.is_empty()
}

/// `learn` stores one memory note, optionally with one managed skill, and
/// returns the store's acknowledgement.
/// Its PreToolUse stays an unknown-tool review, so under enforce the call has
/// run only after a person approved it, and the result it returns has nothing
/// left to approve. Withholding it would leave Oh My Pi without the
/// acknowledgement for a call that already happened. The note shapes this
/// covers are named in `generic_omp_learn`.
fn learn_input(input: &Map<String, Value>) -> bool {
    learn::note_input(input)
}

/// `Some` only when a bounded proof applies; `None` keeps the normal path.
pub(super) fn evaluate(
    payload: &Value,
    signals: &GenericSignals,
    context: &OmpContext<'_>,
) -> Option<PreToolResultV1> {
    if context.event != "PreToolUse"
        || !matches!(context.harness, "omp" | "pi")
        || signals.sensitive_target
        || signals.command.is_some()
        || signals.package_present
    {
        return None;
    }
    let tool = signals.tool_name.as_deref()?;
    if context.harness == "omp" && tool == "eval" {
        if let Some(result) = eval::evaluate_browser(payload, context) {
            return Some(result);
        }
    }
    if !signals.url_values.is_empty() {
        return None;
    }
    if context.harness == "pi" && !matches!(tool, "find" | "ls" | "grep") {
        return None;
    }
    match tool {
        "yield" => {
            if !context.yield_report_verified {
                return None;
            }
            Some({
                let readable = yield_report::references_are_readable(&signals.path_values, context);
                generic_result(
                    generic_action(context.harness, context.event, PreToolActionTypeV1::Harness, PreToolOperationV1::Set, true, false),
                    if readable { "allow" } else { "review" },
                    if readable { "native_omp_yield_metadata" } else { "native_omp_yield_report_review" },
                    "The Rust authority verified this bounded result report and every file reference; submitted content retains output scanning and policy floors.",
                )
            })
        }
        "task" | "wait" | "todo" | "todo_write" => {
            // Delegated work runs through its own guarded tool calls. A
            // path-bearing input is not a delegation envelope.
            signals
                .path_values
                .is_empty()
                .then(|| delegation_result(tool, context))
        }
        "eval" => eval::evaluate(payload, signals, context),
        "edit" => todo_shaped_edit(payload, signals, context),
        "glob" | "find" | "ls" => listing(payload, signals, context),
        "grep" => grep_scope(payload, signals, context),
        "lsp" => lsp_read(payload, signals, context),
        _ => None,
    }
}

/// Models sometimes send a todo update (`{op, phase, task}`) to `edit`,
/// with the op under `input`. Every edit mode names its file in `path`,
/// `edits`, or a header line inside `input`, and a lone todo op word has no
/// room for a header, so the call cannot change a file; Oh My Pi rejects it
/// and the agent retries with `todo`. Any other edit keeps its normal proof.
fn todo_shaped_edit(
    payload: &Value,
    signals: &GenericSignals,
    context: &OmpContext<'_>,
) -> Option<PreToolResultV1> {
    let input = strict_tool_input(payload)?;
    let op = input.get("input")?.as_str()?;
    let todo_keys = input.iter().all(|(key, value)| match key.as_str() {
        "input" => true,
        "phase" | "task" | "reason" => value.is_string(),
        _ => false,
    });
    let todo_op = matches!(
        op,
        "init" | "start" | "done" | "rm" | "drop" | "block" | "unblock" | "append" | "view"
    );
    (todo_keys
        && todo_op
        && (input.contains_key("phase") || input.contains_key("task"))
        && signals.path_values.is_empty())
    .then(|| {
        generic_result(
            generic_action(context.harness, context.event, PreToolActionTypeV1::Harness, PreToolOperationV1::Set, true, false),
            "allow",
            "native_omp_edit_without_target",
            "The Rust authority found a todo update sent to edit: it names no file and has no patch header, so it cannot change any file.",
        )
    })
}

fn delegation_result(tool: &str, context: &OmpContext<'_>) -> PreToolResultV1 {
    let (action_type, operation) = match tool {
        "task" => (PreToolActionTypeV1::Harness, PreToolOperationV1::Start),
        "wait" => (PreToolActionTypeV1::Harness, PreToolOperationV1::Read),
        _ => (PreToolActionTypeV1::Harness, PreToolOperationV1::Set),
    };
    generic_result(
        generic_action(context.harness, context.event, action_type, operation, true, false),
        "allow",
        "native_omp_agent_task",
        "The Rust authority allowed this Oh My Pi task, wait, or todo control call; any tool a delegated task runs is guarded independently.",
    )
}

/// The one tool input object. Alternate spellings must agree with it.
pub(super) fn strict_tool_input(payload: &Value) -> Option<&Map<String, Value>> {
    let root = payload.as_object()?;
    let input = root.get("tool_input")?.as_object()?;
    for alias in super::extract::EMBEDDED_ARGUMENT_KEYS {
        if alias == "tool_input" {
            continue;
        }
        if root
            .get(alias)
            .is_some_and(|value| value.as_object() != Some(input))
        {
            return None;
        }
    }
    Some(input)
}

/// Optional `path` string. `Some(None)` is an absent path (workspace root).
///
/// A search that starts where the project does spells that as an empty
/// argument: Oh My Pi's `glob` sends `path: ""`. The field is present and its
/// type is right, and it names no target, so it describes the same search as
/// a call with no `path` key at all and is read as that absent path. Blank
/// here means empty or whitespace only, exactly as extraction reads it, so
/// the agreement check below still compares the same values. Anything that is
/// not a string keeps its review.
fn input_path<'a>(
    input: &'a Map<String, Value>,
    signals: &GenericSignals,
) -> Option<Option<&'a str>> {
    let path = match input.get("path") {
        None => None,
        Some(Value::String(path)) if path.trim().is_empty() => None,
        Some(Value::String(path)) => Some(path.as_str()),
        Some(_) => return None,
    };
    let expected: Vec<&str> = path.into_iter().collect();
    (signals.path_values.len() == expected.len()
        && signals.path_values.iter().map(String::as_str).eq(expected))
    .then_some(path)
}

/// A pattern or glob can never leave the target directory.
fn contained_selector(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.starts_with(['/', '~', '\\'])
        && !value.contains(['\0', '\n', '\r', '$', '`'])
        && !value.split(['/', '\\']).any(|part| part == "..")
        && value.as_bytes().get(1) != Some(&b':')
}

/// Modeled non-string options from the host tool schemas: grep takes
/// `case`, `gitignore` and a `skip` offset; glob/ls/find take `hidden`,
/// `gitignore` and a `limit`; read takes line paging. Pi's grep adds
/// `ignoreCase`, `literal`, `context` lines and a `limit`, which only shape
/// matches inside the proven scope. Anything else may change what the host
/// touches, so it goes to review.
pub(super) fn modeled_scalar(tool: &str, key: &str, value: &Value) -> bool {
    let bounded = |value: &Value| value.as_u64().is_some_and(|count| count <= 100_000);
    match (tool, key, value) {
        // Oh My Pi's session-tool wrapper takes a bounded `timeout` beside
        // the literal intent label `i`, on every tool it wraps. It bounds how
        // long the call may run and changes nothing about what runs, so the
        // standalone form of the call is the same call. Without it every
        // bridged `tool.bash({i, command, timeout})` — the shape code mode
        // writes — fell through to the unknown-tool review.
        (_, "timeout", number @ Value::Number(_)) => bounded(number),
        // A `null` timeout is the default, like an absent key.
        (_, "timeout", Value::Null) => true,
        ("grep", "case" | "gitignore", Value::Bool(_)) => true,
        ("grep", "skip", Value::Null) => true,
        ("grep", "skip", number @ Value::Number(_)) => bounded(number),
        ("grep", "ignoreCase" | "literal", Value::Bool(_)) => true,
        ("grep", "context" | "limit", number @ Value::Number(_)) => bounded(number),
        ("ls" | "glob" | "find", "hidden" | "gitignore", Value::Bool(_)) => true,
        ("ls" | "glob" | "find", "limit", number @ Value::Number(_)) => bounded(number),
        // Older read schemas paged by line; the current one ignores them.
        ("read", "limit" | "offset", number @ Value::Number(_)) => bounded(number),
        _ => false,
    }
}

/// Scalar keys carry no path or command; strings are limited to `string_keys`
/// and other values to the tool's modeled options.
fn scalar_keys(tool: &str, input: &Map<String, Value>, string_keys: &[&str]) -> bool {
    input.iter().all(|(key, value)| match value {
        Value::String(_) => string_keys.contains(&key.as_str()),
        Value::Bool(_) | Value::Number(_) | Value::Null => modeled_scalar(tool, key, value),
        _ => false,
    })
}

fn directory_allow(context: &OmpContext<'_>, code: &str, reason: &str) -> PreToolResultV1 {
    generic_result(
        generic_action(
            context.harness,
            context.event,
            PreToolActionTypeV1::FileRead,
            PreToolOperationV1::Read,
            true,
            false,
        ),
        "allow",
        code,
        reason,
    )
}

/// Oh My Pi's `lsp` tool asks the session's language servers about code.
/// The actions its read-only sessions keep (`LSP_READONLY_ACTIONS`, checked
/// in Oh My Pi 18.4.12, 18.8.3 and 18.11.3) only report on files. Every other action
/// can change the workspace or reach the server unchecked: `rename` and
/// `code_actions` apply edits across files, `rename_file` moves a file to any
/// destination, and `request` sends a raw server request. Those go to review
/// before they run instead of reaching the generic path, which reads the
/// `file` key as a read. A proven read names one existing file inside the
/// session folder and uses only the modeled keys, so its output meets the
/// same scans and floors as a read of that file.
fn lsp_read(
    payload: &Value,
    signals: &GenericSignals,
    context: &OmpContext<'_>,
) -> Option<PreToolResultV1> {
    let input = strict_tool_input(payload)?;
    let action = input.get("action").and_then(Value::as_str);
    match action {
        Some(
            "diagnostics" | "definition" | "type_definition" | "implementation" | "references"
            | "hover" | "symbols",
        ) => {}
        // Status reports take no file and change nothing.
        Some("status" | "capabilities") => return None,
        _ => {
            return Some(generic_result(
                generic_action(
                    context.harness,
                    context.event,
                    PreToolActionTypeV1::FileWrite,
                    PreToolOperationV1::Write,
                    false,
                    false,
                ),
                "review",
                "native_omp_lsp_change_review",
                "HOL Guard needs review for this language server action because it can edit or move files or send a raw server request. Read-only actions such as references, definition, hover and diagnostics on a file in this folder run without review.",
            ))
        }
    }
    let modeled = input
        .iter()
        .all(|(key, value)| match (key.as_str(), value) {
            ("action" | "file", Value::String(_)) => true,
            ("symbol" | "query", Value::String(text)) => text.len() <= 1024,
            ("line", number) => number.as_u64().is_some_and(|line| line <= 10_000_000),
            ("timeout", number) => number
                .as_f64()
                .is_some_and(|secs| (0.0..=300.0).contains(&secs)),
            _ => false,
        });
    let file = input.get("file")?.as_str()?;
    if !modeled || signals.path_values.len() != 1 || signals.path_values[0] != file {
        return None;
    }
    let (home, cwd) = (context.path.home_dir, context.path.cwd);
    (super::super::read_paths::existing_regular_read_target(file, home, cwd)
        && walk_inside_session(file, context))
    .then(|| {
        directory_allow(
            context,
            "native_omp_lsp_read",
            "The Rust authority proved this language server query reports on one ordinary file in the session folder.",
        )
    })
}

fn grep_scope(
    payload: &Value,
    signals: &GenericSignals,
    context: &OmpContext<'_>,
) -> Option<PreToolResultV1> {
    let input = strict_tool_input(payload)?;
    if !scalar_keys("grep", input, &["path", "pattern", "glob", "type"]) {
        return None;
    }
    let pattern = input.get("pattern")?.as_str()?;
    if pattern.is_empty() || pattern.len() > 4096 {
        return None;
    }
    for key in ["glob", "type"] {
        if let Some(value) = input.get(key) {
            if !contained_selector(value.as_str()?) {
                return None;
            }
        }
    }
    let targets = search_targets(input_path(input, signals)?.unwrap_or("."), context)?;
    // A single file is proven by the ordinary bounded file-read path. An
    // entry of a list has no such fallback, so it carries the same proof here.
    // A `file:N-M` entry searches only those lines of one file, so it carries
    // the proof `read` gives the same selector.
    let list = targets.len() > 1;
    // A `glob` or `type` override can re-include a gitignored file: no ignore file narrows it.
    let gitignore = input.get("gitignore").and_then(Value::as_bool) != Some(false)
        && !input.contains_key("glob")
        && !input.contains_key("type");
    let (home, cwd) = (context.path.home_dir, context.path.cwd);
    // A plain pattern that no reachable sensitive file contains cannot print
    // a line from one, so those files need not hold the search.
    let clearance = super::super::search_pattern_clearance::PatternClearance::new(pattern);
    let globs = grep_glob::EntryProofs::default();
    let proven = |target: &str| {
        super::super::search_scope::omp_grep_scope_proven(
            target,
            home,
            cwd,
            gitignore,
            clearance.as_ref(),
        ) || (list && super::super::read_paths::existing_regular_read_target(target, home, cwd))
            || super::super::read_paths::bounded_omp_file_selector_target(target, home, cwd)
            || globs.proven(target, home, cwd, clearance.as_ref())
    };
    if targets.iter().all(|target| proven(target)) {
        return Some(directory_allow(
            context,
            "native_bounded_search_scope",
            "The Rust authority proved this directory search cannot reach a sensitive file.",
        ));
    }
    // A path that names nothing is never searched, so stopping the call costs
    // nothing. Saying why lets the agent fix the path instead of waiting on
    // an approval. The other entries of a list still need their proof.
    let missing = |target: &str| {
        super::super::read_paths::missing_read_target(target, home, cwd, true)
            && (super::super::read_paths::bounded_file_read_target(target, home, cwd)
                || missing_under_searchable_folder(target, home, cwd))
    };
    let reason = if list {
        "HOL Guard did not run this search because a path in its list does not exist. Check each path, for example by listing its parent directory, and try again with the correct ones."
    } else {
        "HOL Guard did not run this search because its path does not exist. Check the path, for example by listing its parent directory, and try again with the correct one."
    };
    // The same holds for a search: a name inside a registered linked worktree
    // with nothing behind it searches nothing, and that worktree's existing
    // files are already in scope.
    let registered = |target: &str| {
        missing(target)
            && !signals.sensitive_target
            && !super::super::sensitive_command(target)
            && !super::super::sensitive_read_path_argument(target)
            && super::super::git_routes::missing_path_in_registered_worktree(target, home, cwd)
    };
    if targets
        .iter()
        .all(|target| proven(target) || registered(target))
    {
        return Some(directory_allow(
            context,
            "native_missing_worktree_search",
            "The Rust authority proved this search names a path with nothing behind it inside a linked worktree this repository registers, so it searches nothing and the tool reports the missing path itself.",
        ));
    }
    targets
        .iter()
        .all(|target| proven(target) || missing(target))
        .then(|| {
            let mut result = generic_result(
                generic_action(
                    context.harness,
                    context.event,
                    PreToolActionTypeV1::FileRead,
                    PreToolOperationV1::Read,
                    true,
                    false,
                ),
                "block",
                super::read_decisions::MISSING_PATH,
                "",
            );
            result.reason = super::read_decisions::missing_path_reason(
                reason,
                "search",
                targets.iter().find(|target| !proven(target)).copied(),
            );
            result
        })
}

/// An absolute or `~` name that does not exist cannot resolve as a bounded
/// read. Its nearest existing folder can: when Guard would let the agent search
/// that folder, saying the name is missing tells it nothing the search would not.
/// A folder that is not searchable as a whole still qualifies when it is an
/// ordinary readable folder other than the filesystem root and the missing
/// name is not sensitive: a direct read of that name gets the same answer.
fn missing_under_searchable_folder(target: &str, home: Option<&str>, cwd: Option<&str>) -> bool {
    if target.split(['/', '\\']).any(|part| part == "..") {
        return false;
    }
    let expanded = super::super::read_paths::expand_home_read_path(target, home)
        .unwrap_or_else(|| target.to_owned());
    let path = std::path::Path::new(&expanded);
    path.is_absolute()
        && path
            .ancestors()
            .skip(1)
            .find(|folder| std::fs::symlink_metadata(folder).is_ok())
            .filter(|folder| folder.is_dir())
            .and_then(std::path::Path::to_str)
            .is_some_and(|folder| {
                super::super::search_scope::content_search_scope_proven(folder, home, cwd, None)
                    || (std::path::Path::new(folder).parent().is_some()
                        && super::super::read_paths::bounded_read_target(folder, home, cwd, true)
                        && guard_secure_fs::sensitive_path_family(path).is_none()
                        && !guard_secure_fs::credential_named_path(path))
            })
}

/// Why a content search that stays under review was not proven, for the
/// agent to act on. A search path holding a glob is walked from the folder
/// before the glob, so the note asks for separate folders. Otherwise it names
/// the first sensitive file a listed folder would reach. Only names are
/// inspected; no candidate file is opened.
pub(super) fn grep_review_note(
    payload: &Value,
    signals: &GenericSignals,
    context: &OmpContext<'_>,
) -> Option<String> {
    if context.event != "PreToolUse"
        || !matches!(context.harness, "omp" | "pi")
        || signals.tool_name.as_deref() != Some("grep")
    {
        return None;
    }
    let path = input_path(strict_tool_input(payload)?, signals)?.unwrap_or(".");
    let globbed = |entry: &str| entry.contains(['*', '?', '[', '{']);
    let Some(targets) = search_targets(path, context) else {
        return globbed(path).then(|| GLOB_PATH_NOTE.to_owned());
    };
    if targets.iter().any(|target| globbed(target)) {
        return Some(GLOB_PATH_NOTE.to_owned());
    }
    let (home, cwd) = (context.path.home_dir, context.path.cwd);
    // A file the pattern cannot match is not what holds the search.
    let clearance = strict_tool_input(payload)?
        .get("pattern")
        .and_then(Value::as_str)
        .and_then(super::super::search_pattern_clearance::PatternClearance::new);
    targets.iter().find_map(|target| {
        let blocker = super::super::search_scope::content_search_blocker(
            target,
            home,
            cwd,
            clearance.as_ref(),
        )?;
        let blocker = blocker.to_str()?;
        let shown = match target.trim_end_matches('/') {
            "" | "." => blocker.to_owned(),
            folder => format!("{folder}/{blocker}"),
        };
        (shown.len() <= 512 && !shown.contains('`') && !shown.chars().any(char::is_control))
            .then(|| {
                format!(
                    "The search would reach `{shown}`, which Guard treats as sensitive. Leave out the folder that holds it, for example by listing the folders you need as `;`-separated paths."
                )
            })
    })
}

const GLOB_PATH_NOTE: &str = "A search path with a glob is checked against everything under the folder before the glob, so list the folders you need as `;`-separated paths instead.";

/// `skill://<name>[/<relative.md>]` names a skill the host resolves from its
/// own registered skill roots; the name is a bounded token, never a path.
fn skill_reference(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("skill://") else {
        return false;
    };
    let token = |part: &str| {
        !part.is_empty()
            && part.len() <= 128
            && !part.starts_with('.')
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    rest.len() <= 512 && rest.split('/').all(token)
}

/// Reason code for host-held reference selectors, `None` for real paths.
pub(super) fn host_reference_reason(value: &str) -> Option<&'static str> {
    if artifact_reference(value) {
        Some("native_omp_artifact_read")
    } else if skill_reference(value) {
        Some("native_omp_skill_read")
    } else if proc_reference(value) {
        Some("native_omp_proc_read")
    } else if local_reference(value) {
        Some("native_omp_local_read")
    } else {
        None
    }
}

/// `local://` lists the session's scratch root and `local://<name>` reads one
/// file in it, such as the `paste-N.md` a large paste becomes or a plan the
/// session wrote. The host resolves the name under that root and refuses any
/// target outside it; the name here is also bounded tokens joined by `/`, so
/// `..`, absolute, hidden, `~` and percent-encoded names stay reviewed. An
/// optional line range or `raw` follows, as for `artifact://`.
fn local_reference(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("local://") else {
        return false;
    };
    if rest.is_empty() {
        return true;
    }
    let mut chunks = rest.split(':');
    let name = chunks.next().unwrap_or_default();
    let token = |part: &str| {
        !part.is_empty()
            && part.len() <= 128
            && !part.starts_with('.')
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    rest.len() <= 512 && name.split('/').all(token) && selector_chunks_ok(chunks)
}

/// `artifact://<digits>` names an Oh My Pi session artifact, never a path.
/// It may carry an `N-M` line range, `raw`, or one of each in either order;
/// `raw` only drops line formatting from the same artifact.
fn artifact_reference(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("artifact://") else {
        return false;
    };
    let mut chunks = rest.split(':');
    let id = chunks.next().unwrap_or_default();
    let number = |part: &str| {
        !part.is_empty() && part.len() <= 9 && part.bytes().all(|byte| byte.is_ascii_digit())
    };
    number(id) && selector_chunks_ok(chunks)
}

/// `proc://` lists the session's own background jobs and `proc://<id>` shows
/// one job's status and output, with an optional line window. The host serves
/// both from its job table, never from a path. `proc://<id>/kill` and
/// `/mode` are write targets that fail on a read, so they stay out: the id is
/// one bounded token with no `/`.
fn proc_reference(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("proc://") else {
        return false;
    };
    if rest.is_empty() {
        return true;
    }
    let mut chunks = rest.split(':');
    let id = chunks.next().unwrap_or_default();
    let token = !id.is_empty()
        && id.len() <= 128
        && !id.starts_with('.')
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    token && selector_chunks_ok(chunks)
}

/// The `:`-separated tail the host peels from a reference: at most one `N-M`
/// line range and one `raw`, in either order.
fn selector_chunks_ok<'a>(mut chunks: impl Iterator<Item = &'a str>) -> bool {
    let number = |part: &str| {
        !part.is_empty() && part.len() <= 9 && part.bytes().all(|byte| byte.is_ascii_digit())
    };
    let (mut raw, mut range) = (false, false);
    chunks.all(|chunk| {
        if chunk.eq_ignore_ascii_case("raw") && !raw {
            raw = true;
            return true;
        }
        let is_range = chunk
            .split_once('-')
            .is_some_and(|(start, end)| number(start) && number(end));
        let fresh = is_range && !range;
        range |= is_range;
        fresh
    })
}
