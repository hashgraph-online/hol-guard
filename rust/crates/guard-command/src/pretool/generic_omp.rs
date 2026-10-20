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
#[path = "generic_omp_yield.rs"]
mod yield_report;

use super::extract::GenericSignals;
use super::result::{generic_action, generic_result};
use crate::native_command_controls::CompiledNativeCommandControls;
use grep_glob::glob_directory;
use guard_contracts::{PreToolActionTypeV1, PreToolOperationV1, PreToolResultV1};
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
fn input_path<'a>(
    input: &'a Map<String, Value>,
    signals: &GenericSignals,
) -> Option<Option<&'a str>> {
    let path = match input.get("path") {
        None => None,
        Some(Value::String(path)) if !path.is_empty() => Some(path.as_str()),
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

fn listing(
    payload: &Value,
    signals: &GenericSignals,
    context: &OmpContext<'_>,
) -> Option<PreToolResultV1> {
    let input = strict_tool_input(payload)?;
    if !scalar_keys("glob", input, &["path", "pattern"]) {
        return None;
    }
    if let Some(pattern) = input.get("pattern") {
        if !contained_selector(pattern.as_str()?) {
            return None;
        }
    }
    let recursive = signals.tool_name.as_deref() == Some("find") || input.contains_key("pattern");
    let gitignore = input.get("gitignore").and_then(Value::as_bool) != Some(false);
    let targets = search_targets(input_path(input, signals)?.unwrap_or("."), context)?;
    let proven =
        |target: &str| listing_target_proven(target, signals, (recursive, gitignore), context);
    if targets.iter().all(|target| proven(target)) {
        return Some(directory_allow(
            context,
            "native_omp_directory_listing",
            "The Rust authority proved this names-only listing targets a verified ordinary directory.",
        ));
    }
    // A literal path that names nothing lists nothing, so stopping the call
    // costs nothing. A read of the same path gets the same answer, so saying
    // why reveals no more and lets the agent fix the path instead of waiting
    // on an approval. Sensitive names keep their review.
    let (home, cwd) = (context.path.home_dir, context.path.cwd);
    let missing = |target: &str| {
        !signals.sensitive_target
            && super::super::read_paths::missing_read_target(target, home, cwd, false)
            && !super::super::sensitive_command(target)
            && !super::super::sensitive_read_path_argument(target)
    };
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
                super::evaluate::MISSING_PATH,
                "",
            );
            result.reason = super::evaluate::missing_path_reason(
                "HOL Guard did not run this listing because its path does not exist. Check the path, for example by listing its parent directory, and try again with the correct one.",
                "listing",
                targets.iter().find(|target| !proven(target)).copied(),
            );
            result
        })
}

fn listing_target_proven(
    target: &str,
    signals: &GenericSignals,
    (recursive, gitignore): (bool, bool),
    context: &OmpContext<'_>,
) -> bool {
    if signals.tool_name.as_deref() == Some("glob") && target.contains(['{', '}']) {
        // Below a literal directory the host matches the alternatives
        // relative to it. Without that prefix it searches `**/<pattern>` from
        // the cwd (`parseFindPattern`), so each expansion is proven that way:
        // the same proof as an unbraced `**/*.sh`, never wider.
        let anchored = target
            .find(['*', '?', '[', '{'])
            .is_some_and(|index| target[..index].contains('/'));
        let (options, walk) = ((recursive, gitignore), (true, gitignore));
        return brace_expansions(target).is_some_and(|expansions| {
            expansions.iter().all(|expansion| {
                if anchored || expansion.starts_with("**/") {
                    return listing_target_proven(expansion, signals, options, context);
                }
                contained_selector(expansion)
                    && listing_target_proven(&format!("**/{expansion}"), signals, walk, context)
            })
        });
    }
    let has_glob_selector =
        signals.tool_name.as_deref() == Some("glob") && target.contains(['*', '?', '[', '{']);
    let selector = target;
    // OMP glob uses `path` for the complete selector, not just a directory.
    // Prove its fixed directory prefix; the tool returns names, not contents.
    let target = if signals.tool_name.as_deref() == Some("glob") {
        match glob_directory(target) {
            Some(directory) => directory,
            None => return false,
        }
    } else {
        target
    };
    // A wildcard walks below its literal prefix and, like `find`, returns
    // names only, so the walk from that prefix is held to the same rules.
    // Outside the workspace no sensitive name may be reachable below it.
    // The proof is skipped when the walk starts inside the session folder and
    // the last component is a literal ordinary name: then every name the host
    // returns ends in that name.
    // Below a literal directory the host runs the selector with recursion
    // off, so a one-segment selector such as `dir/*lock*` returns only that
    // directory's own entries: the names a listing of it returns. Outside the
    // session folder the stricter walk below still applies.
    let single_level = has_glob_selector
        && !recursive
        && single_level_selector(selector)
        && walk_inside_session(target, context);
    let recursive = (recursive || has_glob_selector) && !single_level;
    let literal_name = has_glob_selector
        && literal_name_selector(selector)
        && walk_inside_session(target, context);
    if has_glob_selector
        && !literal_name
        && !single_level
        && !super::super::search_scope::omp_glob_scope_proven(
            target,
            context.path.home_dir,
            context.path.cwd,
            gitignore,
        )
    {
        return false;
    }
    // `find` and a `pattern` walk the tree below the root and return names
    // only, so an ordinary project root is fine even with a `.env` inside;
    // reading that file stays gated. A walk from the home directory or above
    // it reaches credential stores and agent state, so it stays on review,
    // and so does a literal-name glob that skipped the tree proof.
    if (recursive || literal_name) && walk_covers_home(target, context) {
        return false;
    }
    // A glob entry without wildcards matches only itself, so the host returns
    // that one name. A file there carries the bounded file-read proof.
    let literal_glob_file = signals.tool_name.as_deref() == Some("glob")
        && !has_glob_selector
        && super::super::read_paths::existing_regular_read_target(
            target,
            context.path.home_dir,
            context.path.cwd,
        );
    let missing_glob_entry = signals.tool_name.as_deref() == Some("glob")
        && !has_glob_selector
        && missing_listing_entry(target, context);
    literal_glob_file
        || missing_glob_entry
        || super::super::safe_reads::bounded_omp_directory_read_target(
            target,
            context.path.home_dir,
            context.path.cwd,
        )
        || home_dot_directory_listing(target, has_glob_selector, recursive, context)
        || (!has_glob_selector && project_skill_listing(target, context))
}

/// A names-only listing of a dot-directory in the home directory, the same
/// one `ls ~/.nvm` already gets.
///
/// The shared screen is bounded to the directory's own entries, because a
/// walk below `~/.config` prints the names inside `~/.config/gh`. The host
/// recurses only for `find` or a `pattern`, and a selector walks below its
/// prefix, so both are left out and the entry names of one directory are
/// what remains.
fn home_dot_directory_listing(
    target: &str,
    has_glob_selector: bool,
    recursive: bool,
    context: &OmpContext<'_>,
) -> bool {
    !has_glob_selector
        && !recursive
        && super::super::read_paths::home_hidden_directory(
            target,
            context.path.home_dir,
            context.path.cwd,
        )
}

/// A names-only listing of the session's own project skill folders. Only a
/// literal path with no link component is resolved; the screens are in
/// `project_skill_listing_directory`.
fn project_skill_listing(target: &str, context: &OmpContext<'_>) -> bool {
    let (Some(home), Some(cwd)) = (context.path.home_dir, context.path.cwd) else {
        return false;
    };
    if target.is_empty()
        || target.trim() != target
        || target.len() > 4096
        || target.contains(['\\', '$', '`', '\0', '\n', '\r'])
        || target.split('/').any(|part| part == "..")
    {
        return false;
    }
    let candidate = match target.strip_prefix("~/") {
        Some(rest) => std::path::Path::new(home).join(rest),
        None if target.starts_with('~') => return false,
        None => std::path::Path::new(cwd).join(target),
    };
    if guard_secure_fs::contains_symlink_component(&candidate) {
        return false;
    }
    let (Ok(canonical), Ok(session)) = (
        std::fs::canonicalize(&candidate),
        std::fs::canonicalize(cwd),
    ) else {
        return false;
    };
    super::super::read_paths::project_skill_listing_directory(&canonical, &session)
        && super::super::read_paths::resolved_location_allowed(
            &canonical,
            context.path.home_dir,
            context.path.cwd,
            false,
        )
}

/// Whether a glob selector is a literal directory followed by one wildcard
/// segment, such as `src/*.ts`. Oh My Pi matches that segment against the
/// directory's own entries only: its glob tool passes `recursive: false` and
/// its input schema has no field that turns recursion on (checked in Oh My Pi
/// 18.4.12, 18.8.3 and 18.11.3). `listing` rejects any key outside that schema, and a
/// `pattern` key keeps the walk. A selector with no literal directory gains
/// a `**/` prefix there, and `**` crosses directories, so neither is
/// single-level.
fn single_level_selector(selector: &str) -> bool {
    let Some(index) = selector.find(['*', '?', '[', '{']) else {
        return false;
    };
    let Some(slash) = selector[..index].rfind('/') else {
        return false;
    };
    let segment = &selector[slash + 1..];
    !segment.is_empty() && !segment.contains('/') && !segment.contains("**")
}

/// Whether a glob selector ends in a literal file name, such as
/// `docs/**/AGENTS.md`, that names no credential or sensitive location.
fn literal_name_selector(selector: &str) -> bool {
    let Some((_, name)) = selector.rsplit_once('/') else {
        return false;
    };
    // The host may match case-insensitively, so judge the lowered name too.
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['*', '?', '[', ']', '{', '}', '\\'])
        && !name.chars().any(char::is_control)
        && [name.to_owned(), name.to_ascii_lowercase()]
            .iter()
            .all(|name| {
                !super::super::sensitive_read_path_argument(name)
                    && !super::super::sensitive_command(name)
            })
}

/// A glob entry that names nothing returns no names: the host skips it in a
/// list and reports it missing, or fails a single path with "not found". It
/// reveals no more than a listing of its nearest existing folder, so it
/// carries that folder's listing proof when it sits in the session folder.
/// Sensitive and hidden names keep their review.
fn missing_listing_entry(target: &str, context: &OmpContext<'_>) -> bool {
    let (home, cwd) = (context.path.home_dir, context.path.cwd);
    if !super::super::read_paths::missing_read_target(target, home, cwd, false)
        || super::super::sensitive_command(target)
        || super::super::sensitive_read_path_argument(target)
        || target.split(['/', '\\']).any(|part| part == "..")
    {
        return false;
    }
    let expand = |path: &str| {
        super::super::read_paths::expand_home_read_path(path, home)
            .unwrap_or_else(|| path.to_owned())
    };
    let Some(session) = cwd.and_then(|root| std::fs::canonicalize(expand(root)).ok()) else {
        return false;
    };
    let path = session.join(expand(target));
    let Some(folder) = path
        .ancestors()
        .skip(1)
        .find(|folder| std::fs::symlink_metadata(folder).is_ok())
    else {
        return false;
    };
    let (Ok(canonical), Ok(missing)) = (std::fs::canonicalize(folder), path.strip_prefix(folder))
    else {
        return false;
    };
    // Only an ordinary folder inside the session qualifies, and no name on
    // the way down from the session may be hidden.
    let visible = |path: &std::path::Path| {
        path.components().all(|part| {
            matches!(part, std::path::Component::Normal(name)
                if name.to_str().is_some_and(|name| !name.starts_with('.')))
        })
    };
    canonical.is_dir()
        && canonical.strip_prefix(&session).is_ok_and(visible)
        && visible(missing)
        && folder.to_str().is_some_and(|folder| {
            super::super::safe_reads::bounded_omp_directory_read_target(folder, home, cwd)
        })
}

/// Maximum patterns proven from one glob's `{a,b}` alternatives.
const MAX_BRACE_EXPANSIONS: usize = 32;

/// Every pattern a glob's `{a,b}` groups expand to. Nested, unmatched or
/// escaped groups, and expansions past the bound, return `None`.
fn brace_expansions(target: &str) -> Option<Vec<String>> {
    if target.contains('\\') {
        return None;
    }
    let mut expansions = vec![String::new()];
    let mut rest = target;
    while let Some(open) = rest.find(['{', '}']) {
        if rest.as_bytes()[open] == b'}' {
            return None;
        }
        let close = open + 1 + rest[open + 1..].find(['{', '}'])?;
        if rest.as_bytes()[close] == b'{' {
            return None;
        }
        let alternatives: Vec<&str> = rest[open + 1..close].split(',').collect();
        if expansions.len() * alternatives.len() > MAX_BRACE_EXPANSIONS {
            return None;
        }
        let literal = &rest[..open];
        expansions = expansions
            .iter()
            .flat_map(|prefix| {
                alternatives
                    .iter()
                    .map(move |alternative| format!("{prefix}{literal}{alternative}"))
            })
            .collect();
        rest = &rest[close + 1..];
    }
    for expansion in &mut expansions {
        expansion.push_str(rest);
    }
    Some(expansions)
}

/// Maximum entries proven from one semicolon-delimited `path`.
const MAX_SEARCH_TARGETS: usize = 32;

/// The entries an OMP search tool walks for one `path` string. When the whole
/// string is not an existing path, the host splits it on every top-level `;`
/// before trying any other delimiter (`splitDelimitedPathEntry`), so
/// `src; ../notes` searches both entries. Each returned entry still needs its
/// own proof. `None` keeps review when the host's split could differ from this
/// one: braces and escapes change what counts as top level, quotes are peeled
/// per entry, and an existing literal or selector base is kept whole.
fn search_targets<'a>(target: &'a str, context: &OmpContext<'_>) -> Option<Vec<&'a str>> {
    if !target.contains(';') {
        return Some(vec![target]);
    }
    if target.trim() != target
        || target.starts_with('[')
        || target.contains(['{', '}', '\\', '"', '\0', '\n', '\r'])
    {
        return None;
    }
    let literal_absent = |candidate: &str| {
        let path = match candidate.strip_prefix("~/") {
            Some(rest) => std::path::Path::new(context.path.home_dir?).join(rest),
            None => std::path::Path::new(context.path.cwd?).join(candidate),
        };
        match std::fs::symlink_metadata(path) {
            Err(error) => Some(error.kind() == std::io::ErrorKind::NotFound),
            Ok(_) => Some(false),
        }
    };
    if literal_absent(target) != Some(true) {
        return None;
    }
    if let Some((base, _)) = target.rsplit_once(':') {
        if literal_absent(base) != Some(true) {
            return None;
        }
    }
    let targets: Vec<&str> = target
        .split(';')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();
    (!targets.is_empty() && targets.len() <= MAX_SEARCH_TARGETS).then_some(targets)
}

/// True when the walk root is the home directory or one of its ancestors,
/// or when either cannot be resolved.
fn walk_covers_home(target: &str, context: &OmpContext<'_>) -> bool {
    let (Some(home), Some(cwd)) = (context.path.home_dir, context.path.cwd) else {
        return true;
    };
    let root = if target == "~" {
        std::path::PathBuf::from(home)
    } else if let Some(rest) = target.strip_prefix("~/") {
        std::path::Path::new(home).join(rest)
    } else {
        std::path::Path::new(cwd).join(target)
    };
    match (std::fs::canonicalize(root), std::fs::canonicalize(home)) {
        (Ok(root), Ok(home)) => home.starts_with(root),
        _ => true,
    }
}

fn walk_inside_session(target: &str, context: &OmpContext<'_>) -> bool {
    let Some(cwd) = context.path.cwd else {
        return false;
    };
    if target.starts_with('~') {
        return false;
    }
    match (
        std::fs::canonicalize(std::path::Path::new(cwd).join(target)),
        std::fs::canonicalize(cwd),
    ) {
        (Ok(root), Ok(cwd)) => root.starts_with(cwd),
        _ => false,
    }
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
                super::evaluate::MISSING_PATH,
                "",
            );
            result.reason = super::evaluate::missing_path_reason(
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
                super::super::search_scope::content_search_scope_proven(folder, home, cwd)
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
    } else {
        None
    }
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
