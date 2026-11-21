//! Memory pattern fingerprints and remembered-decision lookup candidates.
//!
//! A fingerprint groups repeated human decisions on the same behavior:
//! `npm install lodash` and `npm i lodash` group together, while a bare
//! capability label such as `read` or `pi:project:read` never anchors memory.
//! Each builder returns `None` when the signal is too generic to remember.
//!
//! The policy lookup probes the direct artifact first, then the shell-domain
//! exact-command ids, then `memory:<harness>:<kind>:<fingerprint>`. String
//! handling follows CPython `str` semantics (whitespace set, `lower`,
//! `casefold`, and the `re` Unicode word and digit classes) so ids match the
//! policies the retired Python builders saved.

use guard_contracts::{MemoryPatternFingerprintV1, MemoryPatternVerdictV1};
use sha2::{Digest, Sha256};

use crate::claude_guard_question::python_lower;
use crate::context_digest::{is_python_space, python_strip};
use crate::skill_identity_canon::casefold;

use self::text::{
    is_lower_hex, is_python_decimal, replace_bounded_runs, replace_env_references, replace_uuids,
};

/// Bare labels that describe a capability category, not a concrete behavior.
const GENERIC_FINGERPRINT_LABELS: &[&str] = &[
    "read",
    "write",
    "bash",
    "grep",
    "shell",
    "job",
    "task",
    "edit",
    "eval",
    "ask",
    "todo",
    "yield",
    "goal",
    "browser",
    "irc",
    "github",
    "glob",
    "tool",
    "mcp",
    "skill",
    "rg",
    "cat",
    "pi:project:read",
    "pi:project:write",
    "pi:project",
    "project:read",
    "project:write",
];
/// Commands whose only value is a single generic verb.
const BARE_COMMAND_VERBS: &[&str] = &[
    "read", "write", "bash", "grep", "shell", "edit", "eval", "ls", "echo",
];
const PACKAGE_MANAGERS: &[&str] = &[
    "npm", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "poetry", "cargo", "go", "gem", "brew",
];
const PACKAGE_INSTALL_SUBCOMMANDS: &[&str] = &["install", "i", "add", "ci", "in", "up", "upgrade"];
const TOOL_ACTION_ARTIFACT_TYPES: &[&str] = &["tool_action_request", "tool_output"];
const FILE_ARTIFACT_TYPES: &[&str] = &["file", "path", "config", "file_read", "file_read_request"];
const FILE_READ_VERBS: &[&str] = &["read", "cat", "head", "tail", "less", "more", "view"];
const TARGETED_EXECUTABLES: &[&str] = &["git", "docker", "gh", "rg", "grep", "curl", "kubectl"];
const PACKAGE_VERSION_SEPARATORS: &[&str] = &["==", ">=", "<=", "!=", "~=", ">", "<"];
/// Longest fingerprint kept verbatim; longer ones keep a head plus a digest.
const MAX_VERBATIM_CHARS: usize = 96;
const DIGEST_HEAD_CHARS: usize = 64;
const DIGEST_SUFFIX_HEX: usize = 16;

/// The fields one remembered decision is fingerprinted from.
pub(crate) struct MemoryRequest<'a> {
    pub(crate) command: Option<&'a str>,
    pub(crate) artifact_type: Option<&'a str>,
    pub(crate) artifact_id: Option<&'a str>,
    pub(crate) artifact_name: Option<&'a str>,
    pub(crate) harness: Option<&'a str>,
}

struct Candidate {
    kind: &'static str,
    components: Vec<(&'static str, String)>,
}

pub(crate) fn verdict(request: &MemoryRequest<'_>) -> MemoryPatternVerdictV1 {
    let artifact_id = request.artifact_id;
    let mut exact_artifact_ids: Vec<String> = Vec::new();
    if is_shell_command(request.artifact_type, request.artifact_name) {
        let ids = [
            exact_command_id("memory:exact-shell-command:", request.command),
            exact_command_id("memory:exact-command:", request.command),
        ];
        for id in ids.into_iter().flatten() {
            if Some(id.as_str()) != artifact_id && !exact_artifact_ids.contains(&id) {
                exact_artifact_ids.push(id);
            }
        }
    }
    let pattern = fingerprint(request);
    let memory_artifact_id = match (request.harness, &pattern) {
        (Some(harness), Some(pattern)) => Some(format!(
            "memory:{harness}:{}:{}",
            pattern.kind, pattern.fingerprint
        ))
        .filter(|id| Some(id.as_str()) != artifact_id),
        _ => None,
    };
    MemoryPatternVerdictV1 {
        pattern,
        exact_artifact_ids,
        memory_artifact_id,
    }
}

/// A policy key bound to one exact command; the bytes are not normalized.
fn exact_command_id(prefix: &str, command: Option<&str>) -> Option<String> {
    let exact = command.unwrap_or("");
    if python_strip(exact).is_empty() {
        return None;
    }
    Some(format!(
        "{prefix}{}",
        hex::encode(Sha256::digest(exact.as_bytes()))
    ))
}

fn is_shell_command(artifact_type: Option<&str>, artifact_name: Option<&str>) -> bool {
    let normalized_type = artifact_type
        .map(|value| casefold(python_strip(value)))
        .unwrap_or_default();
    if matches!(normalized_type.as_str(), "bash" | "shell" | "shell_command") {
        return true;
    }
    let Some(name) = artifact_name else {
        return false;
    };
    if normalized_type != "tool_action_request" {
        return false;
    }
    let normalized_name = casefold(python_strip(name));
    matches!(normalized_name.as_str(), "bash" | "shell")
        || normalized_name.starts_with("bash ")
        || normalized_name.starts_with("shell ")
}

fn fingerprint(request: &MemoryRequest<'_>) -> Option<MemoryPatternFingerprintV1> {
    let is_tool_action = normalize_token(request.artifact_type)
        .is_some_and(|value| TOOL_ACTION_ARTIFACT_TYPES.contains(&value.as_str()));
    let candidate = if is_tool_action {
        // Tool action/output rows use their concrete artifact identity rather
        // than reinterpreting display text as a command.
        generic_artifact(request)
    } else {
        if request
            .command
            .is_some_and(has_unquoted_shell_control_operator)
        {
            return None;
        }
        package_install(request.command, request.harness)
            .or_else(|| mcp_tool(request.command, request.harness, request.artifact_id))
            .or_else(|| file_read(request.command, request.harness, request.artifact_type))
            .or_else(|| shell_command(request.command, request.harness))
            .or_else(|| generic_artifact(request))
    }?;
    let fingerprint = digest(candidate.kind, &candidate.components);
    if is_generic_label(&fingerprint) {
        return None;
    }
    Some(MemoryPatternFingerprintV1 {
        fingerprint,
        kind: candidate.kind.to_owned(),
        components: candidate
            .components
            .into_iter()
            .map(|(name, value)| [name.to_owned(), value])
            .collect(),
    })
}

fn is_generic_label(text: &str) -> bool {
    let normalized = python_lower(python_strip(text));
    normalized.is_empty() || GENERIC_FINGERPRINT_LABELS.contains(&normalized.as_str())
}

fn has_unquoted_shell_control_operator(command: &str) -> bool {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for character in command.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote.is_none() {
                quote = Some(character);
            } else if quote == Some(character) {
                quote = None;
            }
            continue;
        }
        if quote.is_none() && matches!(character, '\n' | ';' | '&' | '|') {
            return true;
        }
    }
    false
}

fn normalize_token(value: Option<&str>) -> Option<String> {
    let token = python_lower(python_strip(value?));
    (!token.is_empty()).then_some(token)
}

/// The harness dimension: any non-empty harness, `unknown` when blank.
fn harness_component(harness: Option<&str>) -> Option<String> {
    harness
        .filter(|value| !value.is_empty())
        .map(|value| normalize_token(Some(value)).unwrap_or_else(|| "unknown".to_owned()))
}

fn candidate(
    kind: &'static str,
    mut components: Vec<(&'static str, String)>,
    harness: Option<&str>,
) -> Candidate {
    if let Some(harness) = harness_component(harness) {
        components.push(("harness", harness));
    }
    Candidate { kind, components }
}

/// `kind:value:...` over components sorted by name; long ones keep a head and
/// a stable digest so volatile detail does not leak into the fingerprint.
fn digest(kind: &str, components: &[(&'static str, String)]) -> String {
    let mut sorted: Vec<&(&'static str, String)> = components.iter().collect();
    sorted.sort_by_key(|(name, _)| *name);
    let mut joined = kind.to_owned();
    for (_, value) in sorted {
        if !value.is_empty() {
            joined.push(':');
            joined.push_str(value);
        }
    }
    if joined.chars().count() <= MAX_VERBATIM_CHARS {
        return joined;
    }
    let suffix = hex::encode(Sha256::digest(joined.as_bytes()));
    let head: String = joined.chars().take(DIGEST_HEAD_CHARS).collect();
    format!(
        "{}:{}",
        head.trim_end_matches(':'),
        &suffix[..DIGEST_SUFFIX_HEX]
    )
}

/// Whitespace tokens of the first `\n ; & |` segment.
fn split_command(command: Option<&str>) -> Vec<&str> {
    let Some(command) = command else {
        return Vec::new();
    };
    let cleaned = python_strip(command);
    let first_segment = cleaned
        .split(['\n', ';', '&', '|'])
        .next()
        .unwrap_or_default();
    python_strip(first_segment)
        .split(is_python_space)
        .filter(|token| !token.is_empty())
        .collect()
}

fn package_install(command: Option<&str>, harness: Option<&str>) -> Option<Candidate> {
    let tokens = split_command(command);
    if tokens.len() < 2 {
        return None;
    }
    let manager = python_lower(tokens[0]);
    if !PACKAGE_MANAGERS.contains(&manager.as_str()) {
        return None;
    }
    let subcommand = python_lower(tokens[1]);
    if !PACKAGE_INSTALL_SUBCOMMANDS.contains(&subcommand.as_str()) {
        return None;
    }
    // Skip flags so `npm install -g pm2` resolves the package, not the flag.
    let raw_package = tokens[2..].iter().find(|token| !token.starts_with('-'))?;
    let package = strip_package_version(raw_package);
    if package.is_empty() {
        return None;
    }
    let ecosystem = ecosystem_for_manager(&manager);
    Some(candidate(
        "package_install_pattern",
        vec![
            ("ecosystem", ecosystem),
            ("package", package),
            ("manager", manager),
        ],
        harness,
    ))
}

fn strip_package_version(raw_package: &str) -> String {
    let mut package = python_strip(python_strip(raw_package).trim_matches(['"', '\''])).to_owned();
    // A leading `@` is an npm scope; only a later `@` pins a version.
    let is_scoped = package.starts_with('@');
    for separator in PACKAGE_VERSION_SEPARATORS {
        if let Some(index) = package.find(separator) {
            package.truncate(index);
        }
    }
    let version_at = if is_scoped {
        package[1..].find('@').map(|index| index + 1)
    } else {
        package.find('@')
    };
    if let Some(index) = version_at {
        package.truncate(index);
    }
    python_lower(python_strip(&package))
}

fn ecosystem_for_manager(manager: &str) -> String {
    match manager {
        "npm" | "pnpm" | "yarn" | "bun" => "npm",
        "pip" | "pip3" | "uv" | "poetry" => "pypi",
        "go" => "goproxy",
        "gem" => "rubygems",
        "brew" => "homebrew",
        other => other,
    }
    .to_owned()
}

fn mcp_tool(
    command: Option<&str>,
    harness: Option<&str>,
    artifact_id: Option<&str>,
) -> Option<Candidate> {
    if let Some((server, tool)) = command.and_then(mcp_command_match) {
        return Some(candidate(
            "mcp_tool_pattern",
            vec![
                ("server", python_lower(&server)),
                ("tool", python_lower(&tool)),
            ],
            harness,
        ));
    }
    let artifact = normalize_token(artifact_id)?;
    if !artifact.starts_with("mcp:") {
        return None;
    }
    let parts: Vec<&str> = artifact.split(':').collect();
    if parts.len() < 3 {
        return None;
    }
    Some(candidate(
        "mcp_tool_pattern",
        vec![
            ("server", python_lower(parts[1])),
            ("tool", python_lower(parts[2])),
        ],
        harness,
    ))
}

/// CPython `re.search(r"mcp__([a-z0-9_-]+)__([a-z0-9_]+)", text, re.I)`.
fn mcp_command_match(text: &str) -> Option<(String, String)> {
    let chars: Vec<char> = text.chars().collect();
    let prefix = ['m', 'c', 'p', '_', '_'];
    for (start, window) in chars.windows(prefix.len()).enumerate() {
        let matches_prefix = window
            .iter()
            .zip(prefix)
            .all(|(actual, expected)| actual.to_ascii_lowercase() == expected);
        if !matches_prefix {
            continue;
        }
        let server_start = start + prefix.len();
        let mut server_end = server_start;
        while server_end < chars.len() && is_mcp_server_char(chars[server_end]) {
            server_end += 1;
        }
        // The server run is greedy: back off to the last `__` that a tool follows.
        while server_end > server_start {
            let separator = server_end + 2 < chars.len()
                && chars[server_end] == '_'
                && chars[server_end + 1] == '_'
                && is_mcp_tool_char(chars[server_end + 2]);
            if separator {
                let tool_start = server_end + 2;
                let mut tool_end = tool_start;
                while tool_end < chars.len() && is_mcp_tool_char(chars[tool_end]) {
                    tool_end += 1;
                }
                return Some((
                    chars[server_start..server_end].iter().collect(),
                    chars[tool_start..tool_end].iter().collect(),
                ));
            }
            server_end -= 1;
        }
    }
    None
}

/// `[a-z0-9_]` under CPython IGNORECASE, which also admits the case
/// variants U+0130, U+0131, U+017F and U+212A.
fn is_mcp_tool_char(character: char) -> bool {
    character.is_ascii_alphanumeric()
        || character == '_'
        || matches!(character, '\u{0130}' | '\u{0131}' | '\u{017f}' | '\u{212a}')
}

fn is_mcp_server_char(character: char) -> bool {
    character == '-' || is_mcp_tool_char(character)
}

fn file_read(
    command: Option<&str>,
    harness: Option<&str>,
    artifact_type: Option<&str>,
) -> Option<Candidate> {
    if !FILE_ARTIFACT_TYPES.contains(&python_lower(artifact_type?).as_str()) {
        return None;
    }
    let tokens = split_command(command);
    let verb = python_lower(tokens.first()?);
    if !FILE_READ_VERBS.contains(&verb.as_str()) || tokens.len() < 2 {
        return None;
    }
    let family = path_family(tokens[1])?;
    Some(candidate(
        "file_read_pattern",
        vec![("verb", verb), ("path_family", family)],
        harness,
    ))
}

/// The first three segments of a path with volatile identifiers collapsed.
fn path_family(raw_path: &str) -> Option<String> {
    let path = python_strip(python_strip(raw_path).trim_matches(['"', '\'']));
    if path.is_empty() || path.starts_with('-') {
        return None;
    }
    let mut collapsed = String::with_capacity(path.len());
    for character in path.chars() {
        if character != '/' || !collapsed.ends_with('/') {
            collapsed.push(character);
        }
    }
    let normalized = python_lower(&collapsed);
    let normalized = replace_bounded_runs(&normalized, is_lower_hex, 16, "<hash>");
    let normalized = replace_uuids(&normalized);
    let normalized = replace_env_references(&normalized);
    let normalized = replace_bounded_runs(&normalized, is_python_decimal, 1, "<n>");
    let segments: Vec<&str> = normalized
        .split('/')
        .filter(|segment| !segment.is_empty())
        .take(3)
        .collect();
    (!segments.is_empty()).then(|| segments.join("/"))
}

fn shell_command(command: Option<&str>, harness: Option<&str>) -> Option<Candidate> {
    let tokens = split_command(command);
    if tokens.len() < 2 {
        return None;
    }
    let executable = python_lower(tokens[0]);
    if BARE_COMMAND_VERBS.contains(&executable.as_str()) {
        return None;
    }
    let subcommand = python_lower(tokens[1]).trim_start_matches('-').to_owned();
    if subcommand.is_empty() {
        return None;
    }
    let mut components = vec![("executable", executable), ("subcommand", subcommand)];
    if TARGETED_EXECUTABLES.contains(&components[0].1.as_str()) && tokens.len() >= 3 {
        let target = python_lower(tokens[2]).trim_start_matches('-').to_owned();
        if !target.is_empty() {
            components.push(("target", target));
        }
    }
    Some(candidate("command_pattern", components, harness))
}

fn generic_artifact(request: &MemoryRequest<'_>) -> Option<Candidate> {
    let artifact =
        normalize_token(request.artifact_id).or_else(|| normalize_token(request.artifact_name))?;
    if is_generic_label(&artifact) {
        return None;
    }
    let artifact_type =
        normalize_token(request.artifact_type).unwrap_or_else(|| "artifact".to_owned());
    Some(candidate(
        "generic_artifact_pattern",
        vec![("artifact", artifact), ("artifact_type", artifact_type)],
        request.harness,
    ))
}

#[path = "memory_pattern_text.rs"]
mod text;

#[cfg(test)]
#[path = "memory_pattern_tests.rs"]
mod tests;
