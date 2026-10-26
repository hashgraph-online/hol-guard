//! `package_json_scripts` context digest: recognize an `npm`/`pnpm`/`yarn`/
//! `bun` script run, or a pasted path to a `package.json` project, and list
//! its scripts as local CLI subcommands.
//!
//! Ports `guard/runtime/package_json_scripts.py`. Known differences from the
//! Python reference, all on inputs no package manager produces: `~user`
//! paths are not expanded, a manifest with `NaN`, `Infinity` or lone
//! surrogate escapes reads as invalid JSON, two script keys that differ only
//! in surrounding whitespace keep the later key in sorted rather than file
//! order, and fallback command ids for script names with non-ASCII letters
//! use Rust's Unicode alphanumeric class.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use guard_command::command_model::{parse_shell_command, CanonicalCommand};
use guard_contracts::{LocalCliIdentitySourceV1, PackageJsonScriptsV1, PackageScriptCommandV1};
use guard_policy_snapshot::digest_bytes;
use serde_json::{Map, Value};

use super::context_digest_local_cli::{local_cli_identity, python_path_name, python_whitespace};

const MANAGERS: &[&str] = &["npm", "pnpm", "yarn", "bun"];
const NPM_SHORTHAND: &[&str] = &["start", "test", "stop", "restart"];
const RUN_TOKENS: &[&str] = &["run", "run-script"];
const LIFECYCLE: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "uninstall",
    "postuninstall",
    "prepublish",
    "prepare",
    "preprepare",
    "postprepare",
    "prepack",
    "postpack",
    "preversion",
    "version",
    "postversion",
];
const MAX_JSON_BYTES: usize = 1_048_576;
const MAX_WALK: usize = 8;
const MAX_SCRIPTS: usize = 78;
const MAX_DESCRIPTION_CHARS: usize = 240;
const LOCKFILES: &[(&str, &str)] = &[
    ("pnpm-lock.yaml", "pnpm"),
    ("yarn.lock", "yarn"),
    ("bun.lock", "bun"),
    ("bun.lockb", "bun"),
    ("package-lock.json", "npm"),
    ("npm-shrinkwrap.json", "npm"),
];
const ROOT_COMMAND_ID: &str = "root";
const OTHER_COMMAND_ID: &str = "other";

struct Invocation {
    manifest: PathBuf,
    runner: &'static str,
    focused: Option<String>,
}

/// Recognize `command_text` and read its manifest. `Ok(None)` means the
/// command is neither a package script run nor a path to a project.
pub(crate) fn package_json_scripts(
    command_text: &str,
    cwd: &str,
    home_dir: &str,
) -> Result<Option<PackageJsonScriptsV1>, &'static str> {
    let Some(invocation) = parse_invocation(command_text, Path::new(cwd), Path::new(home_dir))
    else {
        return Ok(None);
    };
    let (payload, content_sha256) = read_package_payload(&invocation.manifest);
    let directory = invocation.manifest.parent().unwrap_or(Path::new(""));
    let source = LocalCliIdentitySourceV1::PackageJson {
        manifest_path: path_text(
            &fs::canonicalize(&invocation.manifest).unwrap_or_else(|_| invocation.manifest.clone()),
        ),
        content_sha256,
        package_name: package_name(&payload, directory),
    };
    let identity = local_cli_identity(&source)?;
    let scripts = read_scripts(&payload);
    let focused = invocation.focused;
    let command_tokens = match focused.as_deref().map(command_id_for_script) {
        Some(command_id) if command_id != OTHER_COMMAND_ID => {
            command_id.split('.').map(str::to_owned).collect()
        }
        _ => Vec::new(),
    };
    Ok(Some(PackageJsonScriptsV1 {
        manifest_path: path_text(&invocation.manifest),
        runner: invocation.runner.to_owned(),
        focused_listed: focused
            .as_deref()
            .is_some_and(|name| scripts.contains_key(name)),
        commands: commands_from_scripts(&scripts, invocation.runner, focused.as_deref()),
        focused_script: focused,
        source,
        identity,
        command_tokens,
    }))
}

/// `parse_package_script_invocation`: (manifest, runner, focused script).
fn parse_invocation(command_text: &str, cwd: &Path, home_dir: &Path) -> Option<Invocation> {
    let stripped = command_text.trim_matches(python_whitespace);
    if stripped.is_empty() {
        return None;
    }
    if let Some(manifest) = manifest_from_path(stripped, cwd, home_dir) {
        let runner = detect_runner(manifest.parent().unwrap_or(Path::new("")));
        return Some(Invocation {
            manifest,
            runner,
            focused: None,
        });
    }
    let model = parse_shell_command(
        stripped,
        Some(cwd),
        Some(home_dir),
        "posix",
        "shell_string",
        "guard-shell",
        true,
    );
    if !invocation_is_safe(&model) {
        return None;
    }
    let segment = &model.segments[0];
    let mut manager = executable_name(segment.executable.as_deref()?);
    if manager.ends_with(".cmd") || manager.ends_with(".exe") {
        manager.truncate(manager.len() - 4);
    }
    let manager = *MANAGERS.iter().find(|name| **name == manager)?;
    let (prefix, remainder) = strip_manager_options(manager, &segment.arguments);
    let search_root = match prefix {
        Some(prefix) => cwd.join(prefix),
        None => cwd.to_path_buf(),
    };
    let search_root = fs::canonicalize(search_root).ok()?;
    if !search_root.is_dir() {
        return None;
    }
    let manifest = find_nearest_package_json(&search_root, home_dir)?;
    let runner = detect_runner(manifest.parent().unwrap_or(Path::new("")));
    let head = remainder.first()?;
    let focused = focused_script_name(manager, remainder);
    if focused.is_none() && !RUN_TOKENS.contains(&head.as_str()) {
        return None;
    }
    Some(Invocation {
        manifest,
        runner,
        focused,
    })
}

/// `unlisted_cli_invocation_is_safe`: one exact top-level invocation with no
/// redirects, embedded commands, wrappers, environment or PATH override.
pub(crate) fn invocation_is_safe(command: &CanonicalCommand) -> bool {
    if command.confidence != "exact"
        || !command.redirects.is_empty()
        || !command.embedded_commands.is_empty()
        || command.path_overridden()
        || !command.wrapper_chain.is_empty()
        || command.segments.len() != 1
    {
        return false;
    }
    let segment = &command.segments[0];
    segment.execution_context == "top:0"
        && segment.pipeline_index == 0
        && segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && segment.executable.is_some()
}

/// `command_tokens.executable_name`: lowercased last path component.
fn executable_name(value: &str) -> String {
    value
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_lowercase()
}

fn focused_script_name(manager: &str, remainder: &[String]) -> Option<String> {
    let head = remainder.first()?;
    if RUN_TOKENS.contains(&head.as_str()) {
        return remainder.get(1).cloned();
    }
    (manager == "npm" && NPM_SHORTHAND.contains(&head.as_str())).then(|| head.clone())
}

fn prefix_flags(manager: &str) -> &'static [&'static str] {
    match manager {
        "npm" => &["--prefix", "-C"],
        "pnpm" => &["--dir", "-C", "--workspace-dir"],
        _ => &["--cwd"],
    }
}

/// `_strip_manager_options`: the last directory flag and the arguments after
/// the manager's own options.
fn strip_manager_options<'a>(manager: &str, args: &'a [String]) -> (Option<&'a str>, &'a [String]) {
    let flags = prefix_flags(manager);
    let mut prefix = None;
    let mut index = 0;
    while index < args.len() {
        let token = args[index].as_str();
        if token == "--" {
            index += 1;
            break;
        }
        if let Some(assigned) = assigned_prefix(token, flags) {
            prefix = Some(assigned);
            index += 1;
            continue;
        }
        if flags.contains(&token) && index + 1 < args.len() {
            prefix = Some(args[index + 1].as_str());
            index += 2;
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        break;
    }
    (prefix, &args[index..])
}

fn assigned_prefix<'a>(token: &'a str, flags: &[&str]) -> Option<&'a str> {
    flags.iter().find_map(|flag| {
        token
            .strip_prefix(flag)
            .and_then(|rest| rest.strip_prefix('='))
            .filter(|value| !value.is_empty())
    })
}

/// `_manifest_from_path`: a pasted `package.json` path or project directory.
fn manifest_from_path(command_text: &str, cwd: &Path, home_dir: &Path) -> Option<PathBuf> {
    let expanded = command_text.replace("~/", &format!("{}/", home_dir.display()));
    let expanded = match expanded.as_str() {
        "~" => home_dir.display().to_string(),
        _ => expanded,
    };
    // `pathlib.Path` drops trailing separators before resolving.
    let trimmed = expanded.trim_end_matches('/');
    let path = if trimmed.is_empty() { "/" } else { trimmed };
    let resolved = fs::canonicalize(cwd.join(path)).ok()?;
    if resolved.is_file()
        && resolved
            .file_name()
            .is_some_and(|name| name == "package.json")
    {
        return Some(resolved);
    }
    let manifest = resolved.join("package.json");
    (resolved.is_dir() && manifest.is_file()).then_some(manifest)
}

/// `find_nearest_package_json`: walk up at most eight directories, stopping
/// at the home directory.
fn find_nearest_package_json(start: &Path, home_dir: &Path) -> Option<PathBuf> {
    let home = fs::canonicalize(home_dir).unwrap_or_else(|_| home_dir.to_path_buf());
    let mut current = start.to_path_buf();
    for _ in 0..MAX_WALK {
        let candidate = current.join("package.json");
        if candidate.is_file() {
            return Some(candidate);
        }
        if current == home {
            return None;
        }
        current = current.parent()?.to_path_buf();
    }
    None
}

fn detect_runner(directory: &Path) -> &'static str {
    LOCKFILES
        .iter()
        .find(|(filename, _)| directory.join(filename).is_file())
        .map_or("npm", |(_, runner)| runner)
}

/// `_read_package_payload`: the manifest object (empty when unreadable,
/// oversized or not a JSON object) and the sha256 of its bytes.
fn read_package_payload(manifest: &Path) -> (Map<String, Value>, String) {
    let Ok(data) = fs::read(manifest) else {
        return (Map::new(), digest_bytes(b""));
    };
    let digest = digest_bytes(&data);
    if data.len() > MAX_JSON_BYTES {
        return (Map::new(), digest);
    }
    match serde_json::from_slice::<Value>(&data) {
        Ok(Value::Object(payload)) => (payload, digest),
        _ => (Map::new(), digest),
    }
}

fn package_name(payload: &Map<String, Value>, directory: &Path) -> String {
    let declared = payload
        .get("name")
        .and_then(Value::as_str)
        .map(|name| name.trim_matches(python_whitespace))
        .filter(|name| !name.is_empty());
    if let Some(name) = declared {
        return name.trim_start_matches('@').replace('/', "-");
    }
    let name = python_path_name(&path_text(directory));
    if name.is_empty() {
        "package".to_owned()
    } else {
        name
    }
}

/// `_read_scripts`: named scripts without lifecycle hooks or the `pre`/`post`
/// companions of another listed script.
fn read_scripts(payload: &Map<String, Value>) -> BTreeMap<String, String> {
    let Some(Value::Object(raw)) = payload.get("scripts") else {
        return BTreeMap::new();
    };
    let mut scripts = BTreeMap::new();
    for (key, value) in raw {
        let (name, Some(body)) = (key.trim_matches(python_whitespace), value.as_str()) else {
            continue;
        };
        if name.is_empty() || LIFECYCLE.contains(&name) {
            continue;
        }
        scripts.insert(name.to_owned(), body.to_owned());
    }
    let companions: BTreeSet<String> = scripts
        .keys()
        .filter(|name| {
            ["pre", "post"].iter().any(|prefix| {
                name.strip_prefix(prefix)
                    .is_some_and(|rest| scripts.contains_key(rest))
            })
        })
        .cloned()
        .collect();
    scripts.retain(|name, _| !companions.contains(name));
    scripts
}

/// `commands_from_package_scripts` before the root/other merge.
fn commands_from_scripts(
    scripts: &BTreeMap<String, String>,
    runner: &str,
    focused: Option<&str>,
) -> Vec<PackageScriptCommandV1> {
    let mut names: Vec<&String> = scripts.keys().collect();
    names.sort_by_key(|name| {
        let related = focused.is_some_and(|focused| {
            name.as_str() == focused
                || name
                    .strip_prefix(focused)
                    .is_some_and(|rest| rest.starts_with(':'))
                || focused
                    .strip_prefix(name.as_str())
                    .is_some_and(|rest| rest.starts_with(':'))
        });
        (!related, !name.contains(':'), name.as_str())
    });
    let mut seen: BTreeSet<String> = [ROOT_COMMAND_ID, OTHER_COMMAND_ID]
        .map(str::to_owned)
        .into();
    let mut commands = Vec::new();
    for name in names {
        let command_id = command_id_for_script(name);
        if !seen.insert(command_id.clone()) {
            continue;
        }
        let body = scripts[name]
            .split(python_whitespace)
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        commands.push(PackageScriptCommandV1 {
            command_id,
            name: name.clone(),
            usage: format!("{runner} run {name}"),
            description: body.chars().take(MAX_DESCRIPTION_CHARS).collect(),
            parent_id: parent_command_id(name),
        });
        if commands.len() >= MAX_SCRIPTS {
            break;
        }
    }
    commands
}

/// `command_id_for_script`: colon parts joined by dots, or a slug plus a
/// name digest when the name does not fit the command id grammar.
fn command_id_for_script(name: &str) -> String {
    let parts = command_id_parts(name);
    if !parts.is_empty() {
        let candidate = parts.join(".");
        if candidate != ROOT_COMMAND_ID && candidate != OTHER_COMMAND_ID {
            return candidate;
        }
    }
    let digest = &digest_bytes(name.as_bytes())[..8];
    let mut compact = String::with_capacity(name.len());
    for character in name.chars() {
        if character.is_alphanumeric() {
            compact.extend(character.to_lowercase());
        } else {
            compact.push('-');
        }
    }
    let compact = compact.trim_matches('-');
    let base: String = if compact.is_empty() {
        "script"
    } else {
        compact
    }
    .chars()
    .take(31)
    .collect();
    let candidate = format!("{base}-{digest}");
    if candidate == ROOT_COMMAND_ID
        || candidate == OTHER_COMMAND_ID
        || !is_command_part(candidate.split('.').next().unwrap_or(""))
    {
        return format!("script-{digest}");
    }
    candidate
}

fn command_id_parts(name: &str) -> Vec<&str> {
    let parts: Vec<&str> = name.split(':').collect();
    if parts.len() > 4 || !parts.iter().all(|part| is_command_part(part)) {
        return Vec::new();
    }
    parts
}

fn parent_command_id(name: &str) -> Option<String> {
    let parts = command_id_parts(name);
    (parts.len() >= 2).then(|| parts[..parts.len() - 1].join("."))
}

/// `^[A-Za-z][A-Za-z0-9_-]{0,40}$`.
fn is_command_part(part: &str) -> bool {
    let mut bytes = part.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && part.len() <= 41
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
#[path = "context_digest_package_scripts_tests.rs"]
mod tests;
