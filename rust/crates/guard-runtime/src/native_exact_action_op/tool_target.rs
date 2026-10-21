//! Identity for file tools that carry no command.

use std::path::Path;

use guard_command::secret_path_probe::is_request_secret_path;
use serde_json::{json, Value};

use super::context::Ctx;
use super::fs_path;
use super::reasons::{Proof, BROAD_SCOPE, NO_COMMAND_IDENTITY, SENSITIVE_PATH, UNPROVEN_LAUNCH};

/// Harness bookkeeping tools: they read and write no file, run no code and
/// reach no network, so no argument can widen what a remembered allow covers.
const STATE_ONLY_TOOLS: [&str; 3] = ["todo", "todo_write", "todowrite"];
const FILE_READ_TOOLS: [&str; 6] = [
    "cat_file",
    "open_file",
    "read",
    "read_file",
    "view",
    "view_file",
];
const FILE_SEARCH_TOOLS: [&str; 4] = ["glob", "grep", "ls", "list_dir"];
/// Write tools that name their target outright. `apply_patch` is not one: its
/// paths live inside the patch text, so it keeps the command hash.
const FILE_WRITE_TOOLS: [&str; 8] = [
    "delete",
    "delete_file",
    "edit",
    "edit_file",
    "multiedit",
    "strreplace",
    "write",
    "write_file",
];
const PATH_KEYS: [&str; 5] = ["path", "file_path", "filePath", "directory", "dir"];
const PATTERN_KEYS: [&str; 3] = ["pattern", "glob", "include"];
const OPTION_KEYS: [&str; 16] = [
    "limit",
    "offset",
    "type",
    "output_mode",
    "head_limit",
    "case_sensitive",
    "multiline",
    "context",
    "-i",
    "-n",
    "-A",
    "-B",
    "-C",
    "line_start",
    "line_end",
    "lines",
];
/// The bytes a write tool puts into the file it names. An approval names the
/// file, so the text going into it does not bind that approval: writing the
/// same file again is the same capability the user allowed. Each write is
/// still judged on its own content, and a saved allow cannot lift a block or
/// raise an action out of review (`hook_direct_saved_decision::approvable`).
const WRITE_CONTENT_KEYS: [&str; 12] = [
    "content",
    "contents",
    "edits",
    "new_str",
    "new_string",
    "newString",
    "old_str",
    "old_string",
    "oldString",
    "replaceAll",
    "replace_all",
    "text",
];

fn non_blank(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| !text.trim().is_empty())
}

fn is_scalar(value: &Value) -> bool {
    matches!(value, Value::String(_) | Value::Number(_) | Value::Bool(_))
}

fn sensitive(value: &str, cwd: &str, home: Option<&str>) -> bool {
    is_request_secret_path(value, Some(Path::new(cwd)), home.map(Path::new))
}

/// Whether a resolved path outside the workspace is still a scope an approval
/// can name. One file a read tool names is: a checkout beside the workspace is
/// a place the user can answer for once, and what the allow covers stays that
/// one file whose bytes the allow never changes.
///
/// Nothing else qualifies. A directory stands for everything under it, and a
/// path whose parent does not exist names nothing yet, so both keep
/// `broad_scope` and the review stays once-only. A search tool is given a
/// directory to walk, and a path of its own that is not a directory today may
/// be one by the time the remembered allow is used again. A write outside the
/// workspace is the one case where naming only the path would widen what the
/// allow covers: the file's bytes are not part of the identity, so an `Always
/// allow` on an edit to `~/.zshrc`, a launch agent or a crontab would answer
/// for every later edit of that file. Those stay `broad_scope`, and the user
/// keeps both choices on each one.
fn nameable_target(resolved: &str, reads_one_file: bool) -> bool {
    if !reads_one_file || fs_path::is_dir(resolved) {
        return false;
    }
    fs_path::is_file(resolved) || fs_path::is_dir(&fs_path::parent(resolved))
}

/// `Path(raw).expanduser()` / `_expand`: `~user` forms stay unproven.
fn expand(raw: &str, ctx: &Ctx) -> Proof<String> {
    if let Some(home) = ctx.home {
        return Ok(fs_path::expand_tilde(raw, home));
    }
    if !raw.starts_with('~') {
        return Ok(raw.to_owned());
    }
    let home = ctx
        .env
        .get("HOME")
        .filter(|value| !value.is_empty())
        .ok_or(UNPROVEN_LAUNCH)?;
    match raw.strip_prefix('~') {
        Some("") => Ok(home.clone()),
        Some(rest) if rest.starts_with(fs_path::is_sep) => Ok(fs_path::join(home, &rest[1..])),
        _ => Err(UNPROVEN_LAUNCH),
    }
}

/// `tool_target_identity`: `(launch identity, content)` for a read-style tool.
pub(super) fn tool_target_identity(
    tool_name: &str,
    tool_input: Option<&[(String, Value)]>,
    cwd: &str,
    workspace: Option<&str>,
    ctx: &Ctx,
) -> Proof<(Value, Value)> {
    let name = tool_name.trim().to_lowercase();
    if STATE_ONLY_TOOLS.contains(&name.as_str()) {
        return Ok((
            json!({"kind": "tool-target", "tool": name, "targets": []}),
            json!({}),
        ));
    }
    let is_read = FILE_READ_TOOLS.contains(&name.as_str());
    let is_write = FILE_WRITE_TOOLS.contains(&name.as_str());
    let names_one_file = is_read || is_write;
    if !names_one_file && !FILE_SEARCH_TOOLS.contains(&name.as_str()) {
        return Err(NO_COMMAND_IDENTITY);
    }
    let input = tool_input.ok_or(NO_COMMAND_IDENTITY)?;
    let mut paths: Vec<String> = Vec::new();
    let mut patterns: Vec<String> = Vec::new();
    let mut regexes: Vec<String> = Vec::new();
    for (key, value) in input {
        let key = key.as_str();
        if PATH_KEYS.contains(&key) && non_blank(value).is_some() {
            paths.push(value.as_str().unwrap_or_default().to_owned());
        } else if key == "paths"
            && value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string))
        {
            paths.extend(
                value
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_owned),
            );
        } else if key == "pattern" && name == "grep" && non_blank(value).is_some() {
            // grep's pattern is a content regex, not a path: it never names a scope.
            regexes.push(value.as_str().unwrap_or_default().to_owned());
        } else if PATTERN_KEYS.contains(&key) && non_blank(value).is_some() {
            patterns.push(value.as_str().unwrap_or_default().to_owned());
        } else if is_write && WRITE_CONTENT_KEYS.contains(&key) {
            // The bytes written do not name a scope; the path above does.
        } else if !OPTION_KEYS.contains(&key) || !is_scalar(value) {
            // Unknown fields could carry commands, preprocessors or destinations.
            return Err(NO_COMMAND_IDENTITY);
        }
    }
    if names_one_file && (paths.is_empty() || !patterns.is_empty() || !regexes.is_empty()) {
        return Err(NO_COMMAND_IDENTITY);
    }
    if !names_one_file && paths.is_empty() {
        paths.push(cwd.to_owned());
    }
    let root = fs_path::resolve(workspace.unwrap_or(cwd)).ok_or(UNPROVEN_LAUNCH)?;
    let mut targets: Vec<String> = Vec::new();
    for raw in &paths {
        ctx.check()?;
        let candidate = expand(raw, ctx)?;
        let joined = if fs_path::is_abs(&candidate) {
            candidate
        } else {
            fs_path::join(cwd, &candidate)
        };
        let resolved = fs_path::resolve(&joined).ok_or(UNPROVEN_LAUNCH)?;
        if sensitive(raw, cwd, ctx.home) || sensitive(&resolved, cwd, ctx.home) {
            return Err(SENSITIVE_PATH);
        }
        if !fs_path::is_inside(&resolved, &root) && !nameable_target(&resolved, is_read) {
            return Err(BROAD_SCOPE);
        }
        targets.push(resolved);
    }
    for pattern in &patterns {
        if sensitive(pattern, cwd, ctx.home) {
            return Err(SENSITIVE_PATH);
        }
        // A rooted or drive pattern searches outside the scope it was given.
        let escapes = fs_path::is_anchored(pattern)
            || pattern.split(fs_path::is_sep).any(|part| part == "..");
        if !names_one_file && escapes {
            return Err(BROAD_SCOPE);
        }
    }
    targets.sort();
    patterns.sort();
    regexes.sort();
    // Paging and formatting options select less of an already named target, so
    // they cannot widen what a remembered allow covers. Binding them would end
    // the approval at the next offset, which is the same read.
    Ok((
        json!({"kind": "tool-target", "tool": name, "targets": targets}),
        json!({"patterns": patterns, "regexes": regexes}),
    ))
}
