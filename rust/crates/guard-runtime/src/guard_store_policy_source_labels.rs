//! Text helpers for policy decision source context: label classification,
//! remembered-command cleanup, workspace labels and scope paths. Each helper
//! keeps the exact string semantics of the Python store it replaced
//! (`str.strip`, `str.lower`, and `Path` parent and suffix on the host
//! platform).

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::guard_store_json::py_strip;

const GENERIC_POLICY_REASONS: [&str; 4] = [
    "approved in review",
    "approved in local approval center",
    "local auto-resume proof",
    "local e2e approval proof",
];

const SCANNER_GENERATED_LABEL_MARKERS: [&str; 6] = [
    "credential-looking",
    "credential looking",
    "secret-looking",
    "suspicious output",
    "looking output",
    "scanner flagged",
];

const SCOPED_HARNESS_FAMILIES: [&str; 8] = [
    "file-read",
    "mcp",
    "mcp-tool",
    "package-request",
    "prompt",
    "prompt-env-read",
    "prompt-file",
    "tool-action",
];

const SCOPED_RUNTIME_EXACT_FAMILIES: [&str; 4] =
    ["file-read", "package-request", "prompt", "tool-action"];

pub(crate) const RUNTIME_EXACT_PREFIX: &str = "runtime-exact:";

const DIRECTORY_SCOPE_SUFFIXES: [&str; 7] =
    [".json", ".toml", ".yaml", ".yml", ".lock", ".md", ".txt"];

/// Python truthiness of an optional string.
pub(crate) fn truthy(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.is_empty())
}

fn blank(value: &str) -> bool {
    py_strip(value).is_empty()
}

fn is_hex_lower(text: &str) -> bool {
    text.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f'))
}

/// A path the store treats as absolute: POSIX root, home, or a drive letter.
fn is_scope_path(path: &str) -> bool {
    path.starts_with('/') || path.starts_with('~') || path.chars().nth(1) == Some(':')
}

/// `artifact_family_key` restricted to the scoped harness families.
pub(crate) fn artifact_family_key(artifact_id: Option<&str>) -> Option<String> {
    let artifact_id = artifact_id.filter(|value| !blank(value))?;
    if let Some(family) = artifact_id.strip_prefix("family:") {
        let family = py_strip(family).to_lowercase();
        return SCOPED_HARNESS_FAMILIES
            .contains(&family.as_str())
            .then(|| artifact_id.to_owned());
    }
    let parts: Vec<&str> = artifact_id.split(':').collect();
    if parts.len() < 3 {
        return None;
    }
    let family = py_strip(parts[2]).to_lowercase();
    SCOPED_HARNESS_FAMILIES
        .contains(&family.as_str())
        .then(|| format!("family:{family}"))
}

/// The runtime-exact family of an artifact id, if its family has exact keys.
pub(crate) fn runtime_exact_family(artifact_id: Option<&str>) -> Option<String> {
    let key = artifact_family_key(artifact_id)?;
    let family = key.strip_prefix("family:").unwrap_or(&key);
    SCOPED_RUNTIME_EXACT_FAMILIES
        .contains(&family)
        .then(|| family.to_owned())
}

/// `runtime-exact:<sha256(artifact_id)>` for exact-scoped runtime artifacts.
pub(crate) fn runtime_exact_key(artifact_id: Option<&str>) -> Option<String> {
    let artifact_id = artifact_id.filter(|value| !blank(value) && !value.starts_with("family:"))?;
    runtime_exact_family(Some(artifact_id))?;
    Some(format!(
        "{RUNTIME_EXACT_PREFIX}{}",
        hex::encode(Sha256::digest(artifact_id.as_bytes()))
    ))
}

pub(crate) fn is_runtime_exact_key(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.starts_with(RUNTIME_EXACT_PREFIX))
}

/// The stored hash spellings that match one artifact hash, in a fixed order.
pub(crate) fn hash_match_variants(artifact_hash: &str) -> Vec<String> {
    let lowered = py_strip(artifact_hash).to_lowercase();
    let normalized = lowered.strip_prefix("sha256:").unwrap_or(&lowered);
    let mut variants: Vec<String> = Vec::with_capacity(3);
    for variant in [
        artifact_hash.to_owned(),
        format!("sha256:{normalized}"),
        normalized.to_owned(),
    ] {
        if !variant.is_empty() && !variants.contains(&variant) {
            variants.push(variant);
        }
    }
    variants
}

pub(crate) fn is_generic_policy_reason(reason: Option<&str>) -> bool {
    let Some(reason) = reason.filter(|value| !blank(value)) else {
        return true;
    };
    let normalized = py_strip(reason).to_lowercase();
    GENERIC_POLICY_REASONS
        .iter()
        .any(|phrase| normalized.contains(phrase))
}

fn is_scanner_generated_label(value: &str) -> bool {
    let lowered = py_strip(value).to_lowercase();
    if lowered.is_empty() {
        return true;
    }
    if SCANNER_GENERATED_LABEL_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return true;
    }
    lowered.ends_with(" review") && !value.contains('`')
}

/// A label a person wrote, not a scanner summary, family key or digest.
pub(crate) fn is_human_policy_label(value: Option<&str>) -> bool {
    let Some(value) = value.filter(|value| !blank(value)) else {
        return false;
    };
    let normalized = py_strip(value);
    let lowered = normalized.to_lowercase();
    if is_scanner_generated_label(normalized) || lowered.starts_with("family:") {
        return false;
    }
    if normalized.chars().count() >= 32 && is_hex_lower(&lowered) {
        return false;
    }
    if normalized.contains(':') {
        let tail = normalized.rsplit(':').next().unwrap_or("");
        if tail.chars().count() >= 16 && is_hex_lower(tail) {
            return false;
        }
    }
    true
}

/// Drop a trailing shell redirection fragment from a remembered command.
pub(crate) fn sanitize_remembered_command(value: &str) -> String {
    let mut cleaned = py_strip(value);
    if let Some(stripped) = cleaned.strip_suffix("'2>'") {
        cleaned = py_strip(stripped);
    }
    if let Some(stripped) = cleaned.strip_suffix("2>") {
        cleaned = py_strip(stripped);
    }
    cleaned.to_owned()
}

pub(crate) fn backtick_phrases(text: &str) -> Vec<&str> {
    let mut phrases = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('`') else {
            break;
        };
        let phrase = py_strip(&after[..close]);
        if !phrase.is_empty() {
            phrases.push(phrase);
        }
        rest = &after[close + 1..];
    }
    phrases
}

fn path_basename_label(path: &str) -> Option<String> {
    let replaced = py_strip(path).replace('\\', "/");
    let normalized = replaced.trim_end_matches('/');
    if normalized.is_empty() || normalized.starts_with("workspace:") || !is_scope_path(normalized) {
        return None;
    }
    normalized
        .split('/')
        .rfind(|segment| !segment.is_empty())
        .map(str::to_owned)
}

pub(crate) fn workspace_display_label(
    source_scope: Option<&str>,
    workspace: Option<&str>,
) -> Option<String> {
    if let Some(label) = source_scope
        .filter(|value| !blank(value))
        .and_then(path_basename_label)
    {
        return Some(label);
    }
    let workspace =
        workspace.filter(|value| !blank(value) && !py_strip(value).starts_with("workspace:"))?;
    path_basename_label(workspace).or_else(|| Some(py_strip(workspace).to_owned()))
}

/// An absolute scope path without trailing slashes. The root path comes back
/// empty, which callers treat as present but falsy, like the Python store.
pub(crate) fn normalize_policy_scope_path(path: Option<&str>) -> Option<String> {
    let normalized = py_strip(path.filter(|value| !blank(value))?);
    if normalized.starts_with("workspace:") || !is_scope_path(normalized) {
        return None;
    }
    Some(normalized.trim_end_matches('/').to_owned())
}

/// `PurePosixPath(path)` reduced to its root and non-`.` parts.
pub(crate) fn posix_parts(path: &str) -> (&'static str, Vec<&str>) {
    let root = if path.starts_with("//") && !path.starts_with("///") {
        "//"
    } else if path.starts_with('/') {
        "/"
    } else {
        ""
    };
    let parts = path
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    (root, parts)
}

/// `PurePosixPath.suffix`.
fn posix_suffix(name: &str) -> &str {
    match name.rfind('.') {
        Some(index) if index > 0 && index < name.len() - 1 => &name[index..],
        _ => "",
    }
}

/// `Path(path).parent` when the name has a config-file suffix, else the path.
/// `Path` is `PureWindowsPath` on Windows, so both separators split there.
fn directory_scope_path(path: &str) -> Option<String> {
    directory_scope_path_for(path, cfg!(windows))
}

fn directory_scope_path_for(path: &str, windows: bool) -> Option<String> {
    let normalized = path.trim_end_matches('/');
    if normalized.is_empty() {
        return None;
    }
    let (root, parts, separator) = if windows {
        let (root, parts) = windows_parts(normalized);
        (root, parts, "\\")
    } else {
        let (root, parts) = posix_parts(normalized);
        (root.to_owned(), parts, "/")
    };
    let suffix = posix_suffix(parts.last().copied().unwrap_or("")).to_lowercase();
    if !DIRECTORY_SCOPE_SUFFIXES.contains(&suffix.as_str()) {
        return Some(normalized.to_owned());
    }
    let parent_parts = &parts[..parts.len().saturating_sub(1)];
    let parent = format!("{root}{}", parent_parts.join(separator));
    if parent.is_empty() || parent == "." {
        Some(normalized.to_owned())
    } else {
        Some(parent)
    }
}

/// `PureWindowsPath(path)` reduced to its drive plus root and non-`.` parts.
pub(crate) fn windows_parts(path: &str) -> (String, Vec<&str>) {
    let bytes = path.as_bytes();
    let (drive, rest) = if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        path.split_at(2)
    } else {
        ("", path)
    };
    let root = if rest.starts_with(['/', '\\']) {
        "\\"
    } else {
        ""
    };
    let parts = rest
        .split(['/', '\\'])
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    (format!("{drive}{root}"), parts)
}

/// The directory named after "evaluated from " in a receipt provenance.
pub(crate) fn provenance_workspace_path(provenance: Option<&str>) -> Option<String> {
    let normalized = py_strip(provenance.filter(|value| !blank(value))?);
    let lowered: Vec<char> = normalized.to_lowercase().chars().collect();
    let marker: Vec<char> = "evaluated from ".chars().collect();
    let index = lowered
        .windows(marker.len())
        .position(|window| window == marker.as_slice())?;
    let tail: String = normalized.chars().skip(index + marker.len()).collect();
    let path = py_strip(&tail);
    if !is_scope_path(path) {
        return None;
    }
    directory_scope_path(path.trim_end_matches('/'))
}

/// The redacted package command and install context from scanner evidence.
pub(crate) fn scanner_evidence_fields(raw: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(raw) = raw.filter(|value| !blank(value)) else {
        return (None, None);
    };
    let Ok(payload) = serde_json::from_str::<Value>(raw) else {
        return (None, None);
    };
    let entries = match payload {
        Value::Array(items) => items,
        other => vec![other],
    };
    for entry in &entries {
        let Some(package) = entry.get("package").and_then(Value::as_object) else {
            continue;
        };
        let command = package
            .get("redactedCommand")
            .and_then(Value::as_str)
            .map(sanitize_remembered_command);
        let label = |key: &str| {
            package
                .get(key)
                .and_then(Value::as_str)
                .filter(|value| !blank(value))
                .map(|value| format!("Package install via {}", py_strip(value)))
        };
        let context = label("packageManager").or_else(|| label("ecosystem"));
        if truthy(command.as_deref()) || context.is_some() {
            return (command, context);
        }
    }
    (None, None)
}

#[cfg(test)]
mod tests {
    use super::directory_scope_path_for;

    #[test]
    fn posix_config_file_scopes_to_its_directory() {
        let scope = directory_scope_path_for("/repo/settings.json", false);
        assert_eq!(scope.as_deref(), Some("/repo"));
        let scope = directory_scope_path_for("/repo/tools", false);
        assert_eq!(scope.as_deref(), Some("/repo/tools"));
        // Backslashes are ordinary name characters in a POSIX path.
        let scope = directory_scope_path_for("C:\\repo\\settings.json", false);
        assert_eq!(scope.as_deref(), Some("C:\\repo\\settings.json"));
    }

    #[test]
    fn windows_config_file_scopes_to_its_directory() {
        let scope = directory_scope_path_for("C:\\repo\\settings.json", true);
        assert_eq!(scope.as_deref(), Some("C:\\repo"));
        let scope = directory_scope_path_for("C:/repo/sub/guard.toml", true);
        assert_eq!(scope.as_deref(), Some("C:\\repo\\sub"));
        let scope = directory_scope_path_for("C:\\settings.json", true);
        assert_eq!(scope.as_deref(), Some("C:\\"));
        let scope = directory_scope_path_for("C:\\repo\\tools", true);
        assert_eq!(scope.as_deref(), Some("C:\\repo\\tools"));
    }
}
