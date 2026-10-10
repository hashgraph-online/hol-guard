//! Port of `runtime/package_manifest_diff.py` — parse dependency changes from
//! manifests and lockfiles.
//!
//! Verbatim port: same name→version map contents, same key names, same error /
//! truncation semantics (`truncated` + `parse_errors` of
//! `"byte_limit_exceeded"` | `"deadline_exceeded"` | `"parse_error"`).
//!
//! `ManifestParseResult` / `ManifestDependencyChange` / `PackageIntentTarget` /
//! `python_target` are imported from `crate::package_intent_common` (the port
//! of `runtime/package_intent_common.py`), not redefined here.
//!
//! Divergence notes (fail-closed — differences only make Rust *reject* input
//! that Python would parse, never the reverse):
//! - `json.loads`/`dict` → `serde_json::Value`: JSON object key order is not
//!   relied on anywhere except `bun.lock` (`packages.values()` document order
//!   decides `versions[0]`); for that one case the pair-preserving
//!   `crate::jsonc::loads_jsonc_pairs` is used so ordering parity holds even
//!   when `serde_json` is built without `preserve_order`.
//! - `tomllib.loads` → `toml::Value` via `toml::from_str`: same TOML 1.0
//!   grammar; datetime scalar values that `tomllib` accepts but `toml` 0.8
//!   rejects surface as `parse_error`, matching the Python catch-all.
//! - `xml.etree.ElementTree` → `roxmltree` (chosen over quick-xml because a DOM
//!   mirrors `.//{*}dependency` descendant search + `findtext` exactly, with
//!   namespace-insensitive local-name matching like `{*}tag`). Malformed XML
//!   raises in both; `{*}` wildcard ≙ local-name comparison.
//! - `str.splitlines()` → `py_splitlines` reproduces Python's full boundary
//!   set (including \x0b\x0c\x1c-\x1e\x85\u{2028}\u{2029}); `str.strip()` →
//!   `py_strip` reproduces Python whitespace including \x1c-\x1f.
//! - `dict` iteration order (insertion) is observable only through bun
//!   `versions[0]` selection — preserved via `JsoncPairs` pair order.

use std::collections::BTreeMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use regex::Regex;
use serde_json::Value;

use crate::jsonc::{loads_jsonc_pairs_checked, JsoncPairs};
// ---------------------------------------------------------------------------
// Shared types come from `crate::package_intent_common` (canonical port of
// package_intent_common.py:28-141).
// ---------------------------------------------------------------------------

use crate::package_intent_common::{python_target, ManifestDependencyChange, ManifestParseResult};
// ---------------------------------------------------------------------------
// Regex constants (package_manifest_diff.py:26-30 +
// package_intent_common.py:21-25 for `python_target` helpers).
// ---------------------------------------------------------------------------

static GRADLE_DEP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([A-Za-z0-9+_.-]+)").unwrap()
});
static GEMFILE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        &r#"gem[PYWS]+["']([^"']+)["'](?:[PYWS]*,[PYWS]*["']([^"']+)["'])?"#
            .replace("PYWS", r"\s\x1c-\x1f"),
    )
    .unwrap()
});
static GO_REQUIRE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        &r"^[PYWS]*([A-Za-z0-9./_-]+)[PYWS]+(v[^PYWS]+)[PYWS]*$".replace("PYWS", r"\s\x1c-\x1f"),
    )
    .unwrap()
});
static YARN_CLASSIC_VERSION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&r#"^version[PYWS]+"([^"]+)"$"#.replace("PYWS", r"\s\x1c-\x1f")).unwrap()
});
static YARN_BERRY_VERSION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&r#"^version:[PYWS]*"?([^"PYWS]+)"?$"#.replace("PYWS", r"\s\x1c-\x1f")).unwrap()
});
static GEMFILE_LOCK_HEADER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Z][A-Z0-9_ ]+$").unwrap());
static GEMFILE_LOCK_SPEC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&r"^[PYWS]{4}([A-Za-z0-9_.:-]+) \(([^)]+)\)".replace("PYWS", r"\s\x1c-\x1f"))
        .unwrap()
});
static REQ_COMMENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&r"[PYWS]+#".replace("PYWS", r"\s\x1c-\x1f")).unwrap());
static REQ_HASH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&r"[PYWS]+--hash(?:=|[PYWS]+)[^PYWS]+".replace("PYWS", r"\s\x1c-\x1f")).unwrap()
});

// ---------------------------------------------------------------------------
// Deadline (package_manifest_diff.py:33-34, :639-642).
// `time.monotonic() + deadline_ms / 1000`; `_ensure_within_deadline` raises at
// every position Python calls it.
// ---------------------------------------------------------------------------

/// Internal failure channel — Python raises `_DeadlineExceededError` or any
/// `Exception`; only the deadline variant maps to `"deadline_exceeded"`,
/// everything else is `"parse_error"` (or `{}` from
#[derive(Debug)]
enum ParseFailure {
    Deadline,
    Error,
}

type ParseResult<T> = Result<T, ParseFailure>;

struct Deadline {
    instant: Instant,
}

impl Deadline {
    /// `deadline = time.monotonic() + (deadline_ms / 1000)` (:49, :73).
    fn from_ms(deadline_ms: u64) -> Self {
        Self {
            instant: Instant::now() + Duration::from_millis(deadline_ms),
        }
    }

    /// `_ensure_within_deadline` (:639-642):
    /// `if time.monotonic() > deadline: raise _DeadlineExceededError`.
    fn ensure(&self) -> ParseResult<()> {
        if Instant::now() > self.instant {
            return Err(ParseFailure::Deadline);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Python `str` helpers — verbatim semantics.
// ---------------------------------------------------------------------------

/// Python `str.isspace()` code points = Unicode whitespace + \x1c..\x1f.
fn py_ws(character: char) -> bool {
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

/// Python `str.strip()` — trims the Python-whitespace set both ends.
fn py_strip(text: &str) -> &str {
    text.trim_matches(py_ws)
}

/// Python `str.rstrip()` — trailing Python whitespace only.
fn py_rstrip(text: &str) -> &str {
    text.trim_end_matches(py_ws)
}

/// Python `str.lstrip()` — leading Python whitespace only.
fn py_lstrip(text: &str) -> &str {
    text.trim_start_matches(py_ws)
}

/// Python `str.splitlines()` — splits on \n \r \r\n \v \f \x1c-\x1e \x85
/// \u{2028} \u{2029}; Rust `str::lines` only handles \n and \r\n.
pub(crate) fn py_splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let bytes = text.as_bytes();
    let mut start = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        let boundary_end = match bytes[index] {
            b'\n' | b'\r' | 0x0b | 0x0c | 0x1c..=0x1e => {
                if bytes[index] == b'\r' && index + 1 < bytes.len() && bytes[index + 1] == b'\n' {
                    index += 1;
                }
                Some(index + 1)
            }
            0xc2 if index + 1 < bytes.len() && bytes[index + 1] == 0x85 => {
                index += 1;
                Some(index + 1)
            }
            0xe2 if index + 2 < bytes.len()
                && bytes[index + 1] == 0x80
                && (bytes[index + 2] == 0xa8 || bytes[index + 2] == 0xa9) =>
            {
                index += 2;
                Some(index + 1)
            }
            _ => None,
        };
        if let Some(end) = boundary_end {
            lines.push(&text[start..end]);
            index = end;
            start = end;
        } else {
            index += 1;
        }
    }
    if start < bytes.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// `path.rsplit("/", 1)[-1]` (:82).
fn last_path_segment(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or("")
}

/// `str.partition(sep)[0]` — head before the first occurrence (or whole).
fn partition_head<'a>(text: &'a str, sep: &str) -> &'a str {
    match text.find(sep) {
        Some(index) => &text[..index],
        None => text,
    }
}

/// `str.partition(sep)[2]` — tail after the first occurrence (or "").
fn partition_tail<'a>(text: &'a str, sep: &str) -> &'a str {
    match text.find(sep) {
        Some(index) => &text[index + sep.len()..],
        None => "",
    }
}

/// `str.rpartition(sep)` — (head, tail) around the *last* occurrence.
fn rpartition<'a>(text: &'a str, sep: &str) -> (&'a str, &'a str) {
    match text.rfind(sep) {
        Some(index) => (&text[..index], &text[index + sep.len()..]),
        None => ("", text),
    }
}

/// `str.find(needle)` → `Option<usize>` (Python returns -1; callers compare).
fn py_find(text: &str, needle: &str) -> isize {
    text.find(needle).map(|index| index as isize).unwrap_or(-1)
}

/// `str.find(needle, start)` with Python's negative-start clamping.
fn py_find_from(text: &str, needle: &str, start: isize) -> isize {
    let len = text.len() as isize;
    let start = if start < 0 {
        (len + start).max(0) as usize
    } else {
        (start as usize).min(text.len())
    };
    text[start..]
        .find(needle)
        .map(|index| (start + index) as isize)
        .unwrap_or(-1)
}

/// `value.split(sep, 1)[0]` — first field of a maxsplit-1 split.
fn split_head(text: &str, sep: char) -> &str {
    match text.find(sep) {
        Some(index) => &text[..index],
        None => text,
    }
}

/// Python `str(value)` for `toml::Value` — used by
/// `_collect_python_dependency_list` (:414 `str(value)`).
fn toml_py_str(value: &toml::Value) -> String {
    match value {
        toml::Value::String(text) => text.clone(),
        toml::Value::Integer(number) => number.to_string(),
        toml::Value::Float(number) => py_float_repr(*number),
        toml::Value::Boolean(flag) => {
            if *flag {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        toml::Value::Datetime(datetime) => datetime.to_string(),
        // `str(dict)`/`str(list)` embed Python repr() of elements.
        toml::Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(toml_py_repr).collect();
            format!("[{}]", inner.join(", "))
        }
        toml::Value::Table(table) => {
            let inner: Vec<String> = table
                .iter()
                .map(|(key, item)| format!("{}: {}", py_str_repr(key), toml_py_repr(item)))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
    }
}

/// Python `repr(value)` for `toml::Value` (elements inside containers).
fn toml_py_repr(value: &toml::Value) -> String {
    match value {
        toml::Value::String(text) => py_str_repr(text),
        _ => toml_py_str(value),
    }
}

/// Python `repr(float)` approximation: whole numbers keep the `.0` suffix.
fn py_float_repr(number: f64) -> String {
    if number.is_finite() && number.fract() == 0.0 && number.abs() < 1e16 {
        format!("{number:.1}")
    } else {
        format!("{number}")
    }
}

/// Python `repr(str)` — single-quoted with backslash/quote escapes.
fn py_str_repr(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('\'');
    out
}

// ---------------------------------------------------------------------------
// Public API (package_manifest_diff.py:37-78).
// ---------------------------------------------------------------------------

/// `parse_manifest_dependency_changes` (:37-62).
pub fn parse_manifest_dependency_changes(
    path: &str,
    before_text: Option<&str>,
    after_text: Option<&str>,
    byte_limit: usize,
    deadline_ms: u64,
) -> ManifestParseResult {
    let before_text = before_text.unwrap_or("");
    let after_text = after_text.unwrap_or("");
    if before_text.len() + after_text.len() > byte_limit {
        return ManifestParseResult {
            changes: Vec::new(),
            truncated: true,
            parse_errors: vec!["byte_limit_exceeded".to_string()],
        };
    }
    let deadline = Deadline::from_ms(deadline_ms);
    let parse = || -> ParseResult<(BTreeMap<String, String>, BTreeMap<String, String>)> {
        let before_deps = dependency_map_for_path(path, before_text, &deadline)?;
        let after_deps = dependency_map_for_path(path, after_text, &deadline)?;
        Ok((before_deps, after_deps))
    };
    let (before_deps, after_deps) = match parse() {
        Ok(maps) => maps,
        Err(ParseFailure::Deadline) => {
            return ManifestParseResult {
                changes: Vec::new(),
                truncated: true,
                parse_errors: vec!["deadline_exceeded".to_string()],
            };
        }
        Err(ParseFailure::Error) => {
            return ManifestParseResult {
                changes: Vec::new(),
                truncated: false,
                parse_errors: vec!["parse_error".to_string()],
            };
        }
    };
    let mut names: Vec<&String> = before_deps.keys().chain(after_deps.keys()).collect();
    names.sort();
    names.dedup();
    let changes = names
        .into_iter()
        .filter(|name| before_deps.get(*name) != after_deps.get(*name))
        .map(|name| ManifestDependencyChange {
            manifest_path: path.to_string(),
            package_name: name.clone(),
            before: before_deps.get(name).cloned(),
            after: after_deps.get(name).cloned(),
        })
        .collect();
    ManifestParseResult {
        changes,
        truncated: false,
        parse_errors: Vec::new(),
    }
}

/// `parse_manifest_dependencies` (:65-78) — any failure → empty map.
pub fn parse_manifest_dependencies(
    path: &str,
    text: &str,
    byte_limit: usize,
    deadline_ms: u64,
) -> BTreeMap<String, String> {
    if text.len() > byte_limit {
        return BTreeMap::new();
    }
    let deadline = Deadline::from_ms(deadline_ms);
    dependency_map_for_path(path, text, &deadline).unwrap_or_default()
}

/// Result-returning variant of `parse_manifest_dependencies` for callers that
/// must tell a parse failure from an empty manifest (complete-or-fail lockfile
/// parsing). The error is the lockfile `error_reason` the Python evaluator
/// reports: `deadline_exceeded` or `parse_error`.
pub fn try_dependency_map_for_path(
    path: &str,
    text: &str,
    deadline_ms: u64,
) -> Result<BTreeMap<String, String>, &'static str> {
    let deadline = Deadline::from_ms(deadline_ms);
    dependency_map_for_path(path, text, &deadline).map_err(|failure| match failure {
        ParseFailure::Deadline => "deadline_exceeded",
        ParseFailure::Error => "parse_error",
    })
}

// ---------------------------------------------------------------------------
// Dispatch (:81-134) — same endswith checks, same order.
// ---------------------------------------------------------------------------

fn dependency_map_for_path(
    path: &str,
    text: &str,
    deadline: &Deadline,
) -> ParseResult<BTreeMap<String, String>> {
    let lower_path = path.to_lowercase();
    let lower_name = last_path_segment(&lower_path);
    if lower_path.ends_with("package.json") {
        return json_dependency_map(
            text,
            &[
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
            ],
            deadline,
        );
    }
    if lower_path.ends_with("package-lock.json") {
        return package_lock_dependency_map(text, deadline);
    }
    if lower_path.ends_with("pnpm-lock.yaml") {
        return pnpm_lock_dependency_map(text, deadline);
    }
    if lower_path.ends_with("yarn.lock") {
        return yarn_lock_dependency_map(text, deadline);
    }
    if lower_path.ends_with("bun.lock") {
        return bun_lock_dependency_map(text, deadline);
    }
    if lower_path.ends_with("composer.json") {
        return json_dependency_map(text, &["require", "require-dev"], deadline);
    }
    if lower_path.ends_with("requirements.txt")
        || lower_path.ends_with("constraints.txt")
        || lower_name.ends_with(".requirements.txt")
    {
        return requirements_dependency_map(text, deadline);
    }
    if lower_path.ends_with("pyproject.toml") {
        return pyproject_dependency_map(text, deadline);
    }
    if lower_path.ends_with("poetry.lock") {
        return toml_lock_dependency_map(text, deadline);
    }
    if lower_path.ends_with("uv.lock") {
        return toml_lock_dependency_map(text, deadline);
    }
    if lower_path.ends_with("pipfile") {
        return toml_table_dependency_map(text, &["packages", "dev-packages"], deadline);
    }
    if lower_path.ends_with("pipfile.lock") {
        return pipfile_lock_dependency_map(text, deadline);
    }
    if lower_path.ends_with("cargo.toml") {
        return cargo_toml_dependency_map(text, deadline);
    }
    if lower_path.ends_with("cargo.lock") {
        return toml_lock_dependency_map(text, deadline);
    }
    if lower_path.ends_with("go.mod") {
        return go_mod_dependency_map(text, deadline);
    }
    if lower_path.ends_with("pom.xml") {
        return pom_dependency_map(text, deadline);
    }
    if lower_path.ends_with("build.gradle") || lower_path.ends_with("build.gradle.kts") {
        return gradle_dependency_map(text, deadline);
    }
    if lower_path.ends_with("gradle.lockfile") {
        return gradle_lockfile_dependency_map(text, deadline);
    }
    if lower_path.ends_with("composer.lock") {
        return composer_lock_dependency_map(text, deadline);
    }
    if lower_path.ends_with("gemfile") {
        return gemfile_dependency_map(text, deadline);
    }
    if lower_path.ends_with("gemfile.lock") {
        return gemfile_lock_dependency_map(text, deadline);
    }
    Ok(BTreeMap::new())
}

// ---------------------------------------------------------------------------
// JSON manifests (:137-168).
// ---------------------------------------------------------------------------

/// `_json_dependency_map` (:137-147).
fn json_dependency_map(
    text: &str,
    sections: &[&str],
    deadline: &Deadline,
) -> ParseResult<BTreeMap<String, String>> {
    deadline.ensure()?;
    let payload: Value = json_loads(text)?;
    let payload = payload.as_object().ok_or(ParseFailure::Error)?;
    let mut dependencies = BTreeMap::new();
    for section in sections {
        if let Some(values) = payload.get(*section).and_then(Value::as_object) {
            for (package_name, version) in values {
                if let Some(version) = version.as_str() {
                    dependencies.insert(package_name.clone(), version.to_string());
                }
            }
        }
    }
    Ok(dependencies)
}

/// `_package_lock_dependency_map` (:150-167) — v2 `packages/` first, then the
/// v1 `dependencies` tree only when the v2 walk produced nothing.
fn package_lock_dependency_map(
    text: &str,
    deadline: &Deadline,
) -> ParseResult<BTreeMap<String, String>> {
    let payload: Value = json_loads(text)?;
    let payload = payload.as_object().ok_or(ParseFailure::Error)?;
    let mut dependencies = BTreeMap::new();
    if let Some(packages) = payload.get("packages").and_then(Value::as_object) {
        for (package_path, value) in packages {
            deadline.ensure()?;
            if !package_path.starts_with("node_modules/") {
                continue;
            }
            let version = value
                .as_object()
                .and_then(|entry| entry.get("version"))
                .and_then(Value::as_str);
            if let Some(version) = version {
                dependencies.insert(
                    package_path["node_modules/".len()..].to_string(),
                    version.to_string(),
                );
            }
        }
    }
    if !dependencies.is_empty() {
        return Ok(dependencies);
    }
    if let Some(legacy) = payload.get("dependencies").and_then(Value::as_object) {
        walk_package_lock_v1_dependencies(legacy, &mut dependencies, deadline)?;
    }
    Ok(dependencies)
}

/// `_walk_package_lock_v1_dependencies` (:170-184) — recursive v1 tree walk.
fn walk_package_lock_v1_dependencies(
    payload: &serde_json::Map<String, Value>,
    dependencies: &mut BTreeMap<String, String>,
    deadline: &Deadline,
) -> ParseResult<()> {
    for (package_name, value) in payload {
        deadline.ensure()?;
        let Some(value) = value.as_object() else {
            continue;
        };
        if let Some(version) = value.get("version").and_then(Value::as_str) {
            dependencies.insert(package_name.clone(), version.to_string());
        }
        if let Some(nested) = value.get("dependencies").and_then(Value::as_object) {
            walk_package_lock_v1_dependencies(nested, dependencies, deadline)?;
        }
    }
    Ok(())
}

/// `json.loads(text or "{}")` — Python substitutes `"{}"` only for falsy
/// (empty) text; whitespace-only text still raises.
fn json_loads(text: &str) -> ParseResult<Value> {
    let source = if text.is_empty() { "{}" } else { text };
    serde_json::from_str(source).map_err(|_| ParseFailure::Error)
}

// ---------------------------------------------------------------------------
// pnpm-lock.yaml hand-rolled line scanner (:187-236). NOT a YAML parser.
// ---------------------------------------------------------------------------

fn pnpm_lock_dependency_map(
    text: &str,
    deadline: &Deadline,
) -> ParseResult<BTreeMap<String, String>> {
    let mut dependencies = BTreeMap::new();
    let mut package_versions: BTreeMap<String, String> = BTreeMap::new();
    let mut section: Option<String> = None;
    let mut dependency_block = false;
    for raw_line in py_splitlines(text) {
        deadline.ensure()?;
        let stripped = py_strip(raw_line);
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        // indent = len(raw_line) - len(raw_line.lstrip(" ")) — spaces only.
        let indent = raw_line.len() - raw_line.trim_start_matches(' ').len();
        if indent == 0 {
            section = Some(stripped.strip_suffix(':').unwrap_or(stripped).to_string());
            dependency_block = false;
            continue;
        }
        if section.as_deref() != Some("packages") && section.as_deref() != Some("snapshots") {
            continue;
        }
        if indent == 2 && stripped.ends_with(':') {
            dependency_block = false;
            let entry = py_strip(&stripped[..stripped.len() - 1]);
            let entry = entry.trim_matches('"').trim_matches('\'');
            if let (Some(entry_name), Some(entry_version)) = pnpm_entry_name_version(entry) {
                package_versions.insert(entry_name.clone(), entry_version.clone());
                dependencies.insert(entry_name, entry_version);
            }
            continue;
        }
        if section.as_deref() == Some("snapshots") && indent == 4 && stripped == "dependencies:" {
            dependency_block = true;
            continue;
        }
        if section.as_deref() == Some("snapshots") && indent <= 4 {
            dependency_block = false;
        }
        if !dependency_block || indent < 6 || !stripped.contains(':') {
            continue;
        }
        let normalized_name = py_strip(partition_head(stripped, ":"))
            .trim_matches('"')
            .trim_matches('\'');
        let normalized_value = py_strip(partition_tail(stripped, ":"))
            .trim_matches('"')
            .trim_matches('\'');
        let exact_version = package_versions
            .get(normalized_name)
            .cloned()
            .or_else(|| exact_dependency_version_str(normalized_value));
        if let Some(exact_version) = exact_version {
            dependencies.insert(normalized_name.to_string(), exact_version);
        }
    }
    Ok(dependencies)
}

/// `_pnpm_entry_name_version` (:227-234).
fn pnpm_entry_name_version(entry: &str) -> (Option<String>, Option<String>) {
    let normalized_entry = split_head(entry, '(').trim_start_matches('/');
    if !normalized_entry.contains('@') {
        return (None, None);
    }
    let (package_name, package_version) = rpartition(normalized_entry, "@");
    if package_name.is_empty() || package_version.is_empty() {
        return (None, None);
    }
    (
        Some(package_name.to_string()),
        Some(package_version.to_string()),
    )
}

// ---------------------------------------------------------------------------
// yarn.lock line scanner (:237-278) — classic `version "x"` + berry
// `version: x`.
// ---------------------------------------------------------------------------

fn yarn_lock_dependency_map(
    text: &str,
    deadline: &Deadline,
) -> ParseResult<BTreeMap<String, String>> {
    let mut dependencies = BTreeMap::new();
    let mut current_names: Vec<String> = Vec::new();
    for raw_line in py_splitlines(text) {
        deadline.ensure()?;
        let stripped = py_strip(raw_line);
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        if !raw_line.starts_with(' ') && !raw_line.starts_with('\t') {
            current_names = yarn_selector_names(stripped.strip_suffix(':').unwrap_or(stripped));
            continue;
        }
        if current_names.is_empty() {
            continue;
        }
        let version_match = YARN_CLASSIC_VERSION_RE
            .captures(stripped)
            .or_else(|| YARN_BERRY_VERSION_RE.captures(stripped));
        let Some(version_match) = version_match else {
            continue;
        };
        let version = version_match[1].to_string();
        for package_name in &current_names {
            dependencies.insert(package_name.clone(), version.clone());
        }
    }
    Ok(dependencies)
}

/// `_yarn_selector_names` (:259-268).
fn yarn_selector_names(selector_line: &str) -> Vec<String> {
    let mut names = Vec::new();
    for part in selector_line.split(',') {
        let selector = py_strip(part).trim_matches('"').trim_matches('\'');
        if selector.is_empty() || selector == "__metadata" {
            continue;
        }
        if let Some(package_name) = yarn_selector_name(selector) {
            if !package_name.is_empty() && !names.contains(&package_name) {
                names.push(package_name);
            }
        }
    }
    names
}

/// `_yarn_selector_name` (:271-278).
fn yarn_selector_name(selector: &str) -> Option<String> {
    if selector.contains("@npm:") && !selector.starts_with("@npm:") {
        let head = partition_head(selector, "@npm:");
        return if head.is_empty() {
            None
        } else {
            Some(head.to_string())
        };
    }
    if selector.starts_with('@') {
        let (package_name, _, _) = {
            let (name, version) = rpartition(selector, "@");
            (name, version, ())
        };
        return Some(if package_name.is_empty() {
            selector.to_string()
        } else {
            package_name.to_string()
        });
    }
    let package_name = partition_head(selector, "@");
    Some(if package_name.is_empty() {
        selector.to_string()
    } else {
        package_name.to_string()
    })
}

// ---------------------------------------------------------------------------
// bun.lock — JSONC (:281-331). Uses the pair-preserving `loads_jsonc_pairs`
// because Python iterates `packages.values()` in *document* order and keeps
// `versions[0]`; `serde_json::Map` sorts keys without `preserve_order`.
// ---------------------------------------------------------------------------

fn bun_lock_dependency_map(
    text: &str,
    deadline: &Deadline,
) -> ParseResult<BTreeMap<String, String>> {
    let versions_by_name = bun_lock_package_versions(text, deadline)?;
    let mut dependencies = BTreeMap::new();
    for (package_name, versions) in versions_by_name {
        if let Some(version) = versions.first() {
            dependencies.insert(package_name, version.clone());
        }
    }
    Ok(dependencies)
}

/// `_bun_lock_package_versions` (:290-310).
fn bun_lock_package_versions(
    text: &str,
    deadline: &Deadline,
) -> ParseResult<BTreeMap<String, Vec<String>>> {
    deadline.ensure()?;
    // loads_jsonc(text or "{}", deadline_check=...) (:292) — thread the
    // deadline into normalize_jsonc_checked so the check fires mid-pass.
    let source = if text.is_empty() { "{}" } else { text };
    let deadline_ref = deadline;
    let payload = loads_jsonc_pairs_checked(source, &mut || {
        deadline_ref
            .ensure()
            .map_err(|_| crate::jsonc::JsoncError::Deadline("deadline_exceeded".to_string()))
    })
    .map_err(|error| match error {
        crate::jsonc::JsoncError::Deadline(_) => ParseFailure::Deadline,
        crate::jsonc::JsoncError::Decode(_) => ParseFailure::Error,
    })?;
    let JsoncPairs::Object(payload_pairs) = payload else {
        // `raise ValueError("unsupported Bun lockfile shape")` (:295).
        return Err(ParseFailure::Error);
    };
    // `payload.get("packages", {})` — dict.get returns the value of the LAST
    // occurrence of a duplicated key.
    let mut versions_by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // `payload.get("packages", {})` — a missing key yields the empty-dict
    // default and iterates nothing; a non-dict value is a shape error (:298).
    if let Some(packages) = jsonc_pairs_get(&payload_pairs, "packages") {
        let JsoncPairs::Object(packages) = packages else {
            return Err(ParseFailure::Error); // "unsupported Bun packages shape" (:298)
        };
        for (_, package) in dedup_last_object(packages) {
            deadline.ensure()?;
            let JsoncPairs::Array(entries) = package else {
                return Err(ParseFailure::Error); // "unsupported Bun package entry" (:303)
            };
            let Some(JsoncPairs::String(resolution)) = entries.first() else {
                return Err(ParseFailure::Error);
            };
            let Some((package_name, version)) = bun_resolution_identity(resolution) else {
                continue;
            };
            let versions = versions_by_name.entry(package_name).or_default();
            if !versions.contains(&version) {
                versions.push(version);
            }
        }
    }
    Ok(versions_by_name)
}

/// `dict.get(key)` semantics over `JsoncPairs::Object` pairs — the value of
/// the LAST pair with `key`, mirroring Python duplicate-key collapse.
fn jsonc_pairs_get<'a>(pairs: &'a [(String, JsoncPairs)], key: &str) -> Option<&'a JsoncPairs> {
    pairs
        .iter()
        .rev()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

/// Iterate an object as `(key, value)` with Python-dict semantics: keys keep
/// first-insertion order, later duplicates overwrite the value in place.
fn dedup_last_object(pairs: &[(String, JsoncPairs)]) -> Vec<(&str, &JsoncPairs)> {
    let mut order: Vec<(&str, &JsoncPairs)> = Vec::new();
    for (name, value) in pairs {
        if let Some(existing) = order.iter_mut().find(|(seen, _)| *seen == name) {
            existing.1 = value;
        } else {
            order.push((name, value));
        }
    }
    order
}

/// `_bun_resolution_identity` (:313-331).
fn bun_resolution_identity(resolution: &str) -> Option<(String, String)> {
    let version_separator = if resolution.starts_with('@') {
        let scope_separator = py_find(resolution, "/");
        py_find_from(resolution, "@", scope_separator + 1)
    } else {
        py_find(resolution, "@")
    };
    if version_separator <= 0 {
        return None;
    }
    let version_separator = version_separator as usize;
    let package_name = &resolution[..version_separator];
    let mut version = &resolution[version_separator + 1..];
    if let Some(stripped) = version.strip_prefix("npm:") {
        version = stripped;
    }
    if package_name.is_empty()
        || version.is_empty()
        || version.starts_with("workspace:")
        || version.starts_with("root:")
        || version.starts_with("file:")
        || version.starts_with("link:")
        || version.starts_with("git:")
        || version.starts_with("git+")
        || version.starts_with("http:")
        || version.starts_with("https:")
    {
        return None;
    }
    Some((package_name.to_string(), version.to_string()))
}

// ---------------------------------------------------------------------------
// requirements.txt / constraints.txt (:334-377) + `python_target` from
// package_intent_common.py:447-493.
// ---------------------------------------------------------------------------

/// `_exact_dependency_version` (:334-342) for JSON scalar values.
fn exact_dependency_version(value: &Value) -> Option<String> {
    exact_dependency_version_str(value.as_str()?)
}

/// `_exact_dependency_version` core (:338-342).
fn exact_dependency_version_str(value: &str) -> Option<String> {
    let mut normalized = py_strip(value).trim_matches('"').trim_matches('\'');
    if normalized.is_empty() {
        return None;
    }
    while normalized.starts_with('=')
        || normalized.starts_with('^')
        || normalized.starts_with('~')
        || normalized.starts_with('v')
    {
        normalized = &normalized[1..];
    }
    if normalized.is_empty() {
        None
    } else {
        Some(normalized.to_string())
    }
}

/// `_requirements_dependency_map` (:345-358).
fn requirements_dependency_map(
    text: &str,
    deadline: &Deadline,
) -> ParseResult<BTreeMap<String, String>> {
    let mut dependencies = BTreeMap::new();
    for line in requirements_logical_lines(text, deadline)? {
        let mut stripped = py_strip(&line).to_string();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        // re.split(r"\s+#", stripped, maxsplit=1)[0].strip()
        if let Some(location) = REQ_COMMENT_RE.find(&stripped) {
            stripped = py_strip(&stripped[..location.start()]).to_string();
        }
        // re.sub(r"\s+--hash(?:=|\s+)[^\s]+", "", stripped).strip()
        stripped = py_strip(&REQ_HASH_RE.replace_all(&stripped, "")).to_string();
        if stripped.is_empty() || stripped.starts_with('-') {
            continue;
        }
        let target = python_target(&stripped, false, None, Vec::new());
        if let Some(package_name) = target.package_name {
            dependencies.insert(package_name, target.requested_specifier.unwrap_or_default());
        }
    }
    Ok(dependencies)
}

/// `_requirements_logical_lines` (:361-377) — `\`-continuation join.
fn requirements_logical_lines(text: &str, deadline: &Deadline) -> ParseResult<Vec<String>> {
    let mut logical_lines = Vec::new();
    let mut current = String::new();
    for line in py_splitlines(text) {
        deadline.ensure()?;
        let mut fragment = py_rstrip(line).to_string();
        if !current.is_empty() {
            fragment = format!("{} {}", current, py_lstrip(&fragment));
        }
        if let Some(without_backslash) = fragment.strip_suffix('\\') {
            current = py_rstrip(without_backslash).to_string();
            continue;
        }
        logical_lines.push(fragment);
        current = String::new();
    }
    if !current.is_empty() {
        logical_lines.push(current);
    }
    Ok(logical_lines)
}

// ---------------------------------------------------------------------------
// TOML manifests (:379-533). `tomllib.loads` → `toml::from_str` (both TOML
// 1.0; `tomllib` returns a dict, `toml::Value::Table` mirrors it).
// ---------------------------------------------------------------------------

/// `tomllib.loads(text or "")` — Python substitutes "" only for falsy text.
fn toml_loads(text: &str) -> ParseResult<toml::Value> {
    let source = if text.is_empty() { "" } else { text };
    source
        .parse::<toml::Table>()
        .map(toml::Value::Table)
        .map_err(|_| ParseFailure::Error)
}

/// `_pyproject_dependency_map` (:379-403).
fn pyproject_dependency_map(
    text: &str,
    deadline: &Deadline,
) -> ParseResult<BTreeMap<String, String>> {
    deadline.ensure()?;
    let payload = toml_loads(text)?;
    let payload = payload.as_table().ok_or(ParseFailure::Error)?;
    let mut dependencies = BTreeMap::new();
    if let Some(project) = payload.get("project").and_then(toml::Value::as_table) {
        collect_python_dependency_list(&mut dependencies, project.get("dependencies"), deadline)?;
        if let Some(optional_dependencies) = project
            .get("optional-dependencies")
            .and_then(toml::Value::as_table)
        {
            for values in optional_dependencies.values() {
                collect_python_dependency_list(&mut dependencies, Some(values), deadline)?;
            }
        }
    }
    if let Some(tool) = payload.get("tool").and_then(toml::Value::as_table) {
        if let Some(poetry) = tool.get("poetry").and_then(toml::Value::as_table) {
            collect_poetry_dependency_table(
                &mut dependencies,
                poetry.get("dependencies"),
                deadline,
            )?;
            collect_poetry_dependency_table(
                &mut dependencies,
                poetry.get("dev-dependencies"),
                deadline,
            )?;
            if let Some(groups) = poetry.get("group").and_then(toml::Value::as_table) {
                for group in groups.values() {
                    let Some(group) = group.as_table() else {
                        continue;
                    };
                    collect_poetry_dependency_table(
                        &mut dependencies,
                        group.get("dependencies"),
                        deadline,
                    )?;
                }
            }
        }
    }
    Ok(dependencies)
}

/// `_collect_python_dependency_list` (:405-416).
fn collect_python_dependency_list(
    dependencies: &mut BTreeMap<String, String>,
    values: Option<&toml::Value>,
    deadline: &Deadline,
) -> ParseResult<()> {
    let Some(toml::Value::Array(values)) = values else {
        return Ok(());
    };
    for value in values {
        deadline.ensure()?;
        let target = python_target(&toml_py_str(value), false, None, Vec::new());
        if let Some(package_name) = target.package_name {
            dependencies.insert(package_name, target.requested_specifier.unwrap_or_default());
        }
    }
    Ok(())
}

/// `_collect_poetry_dependency_table` (:419-435) — `python` key skipped.
fn collect_poetry_dependency_table(
    dependencies: &mut BTreeMap<String, String>,
    values: Option<&toml::Value>,
    deadline: &Deadline,
) -> ParseResult<()> {
    let Some(toml::Value::Table(values)) = values else {
        return Ok(());
    };
    for (package_name, value) in values {
        deadline.ensure()?;
        let normalized_name = package_name.to_string();
        if normalized_name == "python" {
            continue;
        }
        match value {
            toml::Value::String(version) => {
                dependencies.insert(normalized_name, version.clone());
            }
            toml::Value::Table(table) => {
                if let Some(toml::Value::String(version)) = table.get("version") {
                    dependencies.insert(normalized_name, version.clone());
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// `_toml_lock_dependency_map` (:438-453) — shared by poetry.lock, uv.lock,
//  cargo.lock (:456-458 aliases).
fn toml_lock_dependency_map(
    text: &str,
    deadline: &Deadline,
) -> ParseResult<BTreeMap<String, String>> {
    deadline.ensure()?;
    let payload = toml_loads(text)?;
    let payload = payload.as_table().ok_or(ParseFailure::Error)?;
    let mut dependencies = BTreeMap::new();
    let Some(toml::Value::Array(packages)) = payload.get("package") else {
        return Ok(dependencies);
    };
    for package in packages {
        deadline.ensure()?;
        let Some(package) = package.as_table() else {
            continue;
        };
        let name = package.get("name").and_then(toml::Value::as_str);
        let version = package.get("version").and_then(toml::Value::as_str);
        if let (Some(name), Some(version)) = (name, version) {
            dependencies.insert(name.to_string(), version.to_string());
        }
    }
    Ok(dependencies)
}

/// `_pipfile_lock_dependency_map` (:461-476) — JSON `default`/`develop`
/// sections with `_exact_dependency_version` normalization.
fn pipfile_lock_dependency_map(
    text: &str,
    deadline: &Deadline,
) -> ParseResult<BTreeMap<String, String>> {
    deadline.ensure()?;
    let payload: Value = json_loads(text)?;
    let payload = payload.as_object().ok_or(ParseFailure::Error)?;
    let mut dependencies = BTreeMap::new();
    for section in ["default", "develop"] {
        let Some(values) = payload.get(section).and_then(Value::as_object) else {
            continue;
        };
        for (package_name, package_value) in values {
            deadline.ensure()?;
            let Some(package_value) = package_value.as_object() else {
                continue;
            };
            if let Some(exact_version) = package_value
                .get("version")
                .and_then(exact_dependency_version)
            {
                dependencies.insert(package_name.clone(), exact_version);
            }
        }
    }
    Ok(dependencies)
}

/// `_toml_table_dependency_map` (:479-493) — Pipfile `packages`/`dev-packages`.
fn toml_table_dependency_map(
    text: &str,
    sections: &[&str],
    deadline: &Deadline,
) -> ParseResult<BTreeMap<String, String>> {
    deadline.ensure()?;
    let payload = toml_loads(text)?;
    let payload = payload.as_table().ok_or(ParseFailure::Error)?;
    let mut dependencies = BTreeMap::new();
    for section in sections {
        let Some(values) = payload.get(*section).and_then(toml::Value::as_table) else {
            continue;
        };
        for (package_name, value) in values {
            deadline.ensure()?;
            match value {
                toml::Value::String(version) => {
                    dependencies.insert(package_name.clone(), version.clone());
                }
                toml::Value::Table(table) => {
                    if let Some(toml::Value::String(version)) = table.get("version") {
                        dependencies.insert(package_name.clone(), version.clone());
                    }
                }
                _ => {}
            }
        }
    }
    Ok(dependencies)
}

/// `_cargo_toml_dependency_map` (:496-513).
fn cargo_toml_dependency_map(
    text: &str,
    deadline: &Deadline,
) -> ParseResult<BTreeMap<String, String>> {
    deadline.ensure()?;
    let payload = toml_loads(text)?;
    let payload = payload.as_table().ok_or(ParseFailure::Error)?;
    let mut dependencies = BTreeMap::new();
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        collect_toml_dependency_table(&mut dependencies, payload.get(section), deadline)?;
    }
    if let Some(workspace) = payload.get("workspace").and_then(toml::Value::as_table) {
        collect_toml_dependency_table(&mut dependencies, workspace.get("dependencies"), deadline)?;
    }
    if let Some(target) = payload.get("target").and_then(toml::Value::as_table) {
        for section_payload in target.values() {
            deadline.ensure()?;
            let Some(section_payload) = section_payload.as_table() else {
                continue;
            };
            for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
                collect_toml_dependency_table(
                    &mut dependencies,
                    section_payload.get(section),
                    deadline,
                )?;
            }
        }
    }
    Ok(dependencies)
}

/// `_collect_toml_dependency_table` (:516-529).
fn collect_toml_dependency_table(
    dependencies: &mut BTreeMap<String, String>,
    values: Option<&toml::Value>,
    deadline: &Deadline,
) -> ParseResult<()> {
    let Some(toml::Value::Table(values)) = values else {
        return Ok(());
    };
    for (package_name, value) in values {
        deadline.ensure()?;
        match value {
            toml::Value::String(version) => {
                dependencies.insert(package_name.clone(), version.clone());
            }
            toml::Value::Table(table) => {
                if let Some(toml::Value::String(version)) = table.get("version") {
                    dependencies.insert(package_name.clone(), version.clone());
                }
            }
            _ => {}
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// go.mod (:532-551) — `require` block + single-line requires via regex.
// ---------------------------------------------------------------------------

fn go_mod_dependency_map(text: &str, deadline: &Deadline) -> ParseResult<BTreeMap<String, String>> {
    let mut dependencies = BTreeMap::new();
    let mut in_require_block = false;
    for raw_line in py_splitlines(text) {
        deadline.ensure()?;
        let line = py_strip(raw_line);
        if line.starts_with("require (") {
            in_require_block = true;
            continue;
        }
        if in_require_block && line == ")" {
            in_require_block = false;
            continue;
        }
        let line = if let Some(rest) = line.strip_prefix("require ") {
            py_strip(rest)
        } else {
            if !in_require_block {
                continue;
            }
            line
        };
        if let Some(matched) = GO_REQUIRE_RE.captures(line) {
            dependencies.insert(matched[1].to_string(), matched[2].to_string());
        }
    }
    Ok(dependencies)
}

// ---------------------------------------------------------------------------
// pom.xml (:554-566) — ElementTree `.//{*}dependency` + `{*}groupId`/
// `{*}artifactId`/`{*}version` findtext. Ported with roxmltree: DOM descendant
// search + namespace-insensitive local-name matching = `{*}` wildcard.
// ---------------------------------------------------------------------------

fn pom_dependency_map(text: &str, deadline: &Deadline) -> ParseResult<BTreeMap<String, String>> {
    deadline.ensure()?;
    let source = if text.is_empty() { "<project />" } else { text };
    let document = roxmltree::Document::parse(source).map_err(|_| ParseFailure::Error)?;
    let mut dependencies = BTreeMap::new();
    // `.//{*}dependency` — descendants of the root element only (ElementTree
    // `findall` does not include the context element itself).
    for dependency in document.root_element().descendants() {
        deadline.ensure()?;
        if !dependency.is_element() || dependency.tag_name().name() != "dependency" {
            continue;
        }
        let findtext = |name: &str| -> Option<String> {
            dependency
                .children()
                .find(|child| child.is_element() && child.tag_name().name() == name)
                .map(|child| child.text().unwrap_or("").to_string())
        };
        let group_id = findtext("groupId").unwrap_or_default();
        let artifact_id = findtext("artifactId").unwrap_or_default();
        let version = findtext("version").unwrap_or_default();
        if !group_id.is_empty() && !artifact_id.is_empty() && !version.is_empty() {
            dependencies.insert(format!("{group_id}:{artifact_id}"), version);
        }
    }
    Ok(dependencies)
}

// ---------------------------------------------------------------------------
// build.gradle / build.gradle.kts (:568-574), gradle.lockfile (:577-587),
// composer.lock (:590-606), Gemfile (:609-616), Gemfile.lock (:619-636).
// ---------------------------------------------------------------------------

fn gradle_dependency_map(text: &str, deadline: &Deadline) -> ParseResult<BTreeMap<String, String>> {
    let mut dependencies = BTreeMap::new();
    for line in py_splitlines(text) {
        deadline.ensure()?;
        for matched in GRADLE_DEP_RE.captures_iter(line) {
            dependencies.insert(
                format!("{}:{}", &matched[1], &matched[2]),
                matched[3].to_string(),
            );
        }
    }
    Ok(dependencies)
}

fn gradle_lockfile_dependency_map(
    text: &str,
    deadline: &Deadline,
) -> ParseResult<BTreeMap<String, String>> {
    let mut dependencies = BTreeMap::new();
    for raw_line in py_splitlines(text) {
        deadline.ensure()?;
        let line = py_strip(raw_line);
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with("empty=")
            || !line.contains('=')
        {
            continue;
        }
        let (package_name, version) = rpartition(line, ":");
        if !package_name.is_empty() && !version.is_empty() {
            dependencies.insert(package_name.to_string(), version.to_string());
        }
    }
    Ok(dependencies)
}

/// `_composer_lock_dependency_map` (:590-606) — `packages` + `packages-dev`
/// list entries with string `name`/`version`.
fn composer_lock_dependency_map(
    text: &str,
    deadline: &Deadline,
) -> ParseResult<BTreeMap<String, String>> {
    deadline.ensure()?;
    let payload: Value = json_loads(text)?;
    let payload = payload.as_object().ok_or(ParseFailure::Error)?;
    let mut dependencies = BTreeMap::new();
    for section in ["packages", "packages-dev"] {
        let Some(packages) = payload.get(section).and_then(Value::as_array) else {
            continue;
        };
        for package in packages {
            deadline.ensure()?;
            let Some(package) = package.as_object() else {
                continue;
            };
            let name = package.get("name").and_then(Value::as_str);
            let version = package.get("version").and_then(Value::as_str);
            if let (Some(name), Some(version)) = (name, version) {
                dependencies.insert(name.to_string(), version.to_string());
            }
        }
    }
    Ok(dependencies)
}

/// `_gemfile_dependency_map` (:609-616) — `_GEMFILE_RE.search` per line.
fn gemfile_dependency_map(
    text: &str,
    deadline: &Deadline,
) -> ParseResult<BTreeMap<String, String>> {
    let mut dependencies = BTreeMap::new();
    for line in py_splitlines(text) {
        deadline.ensure()?;
        if let Some(matched) = GEMFILE_RE.captures(line) {
            let version = matched
                .get(2)
                .map(|group| group.as_str())
                .unwrap_or("")
                .to_string();
            dependencies.insert(matched[1].to_string(), version);
        }
    }
    Ok(dependencies)
}

/// `_gemfile_lock_dependency_map` (:619-636) — `GEM` `specs:` block only.
fn gemfile_lock_dependency_map(
    text: &str,
    deadline: &Deadline,
) -> ParseResult<BTreeMap<String, String>> {
    let mut dependencies = BTreeMap::new();
    let mut in_specs_block = false;
    for raw_line in py_splitlines(text) {
        deadline.ensure()?;
        let stripped = py_strip(raw_line);
        if stripped == "specs:" {
            in_specs_block = true;
            continue;
        }
        if GEMFILE_LOCK_HEADER_RE.is_match(stripped) {
            in_specs_block = false;
            continue;
        }
        if !in_specs_block {
            continue;
        }
        if let Some(matched) = GEMFILE_LOCK_SPEC_RE.captures(raw_line) {
            dependencies.insert(matched[1].to_string(), matched[2].to_string());
        }
    }
    Ok(dependencies)
}

// ---------------------------------------------------------------------------
// Tests — Python oracle outputs are asserted verbatim. Oracle generated via:
//   PYTHONPATH=src python3 -c \
//     'from codex_plugin_scanner.guard.runtime.package_manifest_diff import _dependency_map_for_path as f; ...'
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const GENEROUS: u64 = 60_000;

    /// Oracle:
    /// `_dependency_map_for_path("package.json", TEXT, deadline=inf)`
    /// → {'left-pad': '1.3.0', 'react': '^18.2.0', 'jest': '^29.0.0',
    ///    'lodash': '4.17.21'}
    #[test]
    fn package_json_sections_map() {
        let text = r#"{
            "dependencies": {"react": "^18.2.0", "left-pad": "1.3.0"},
            "devDependencies": {"jest": "^29.0.0"},
            "optionalDependencies": {"lodash": "4.17.21"},
            "peerDependenciesMeta": {"ignored": true}
        }"#;
        let deadline = Deadline::from_ms(GENEROUS);
        let map = dependency_map_for_path("package.json", text, &deadline).unwrap();
        let expected: BTreeMap<String, String> = [
            ("left-pad", "1.3.0"),
            ("react", "^18.2.0"),
            ("jest", "^29.0.0"),
            ("lodash", "4.17.21"),
        ]
        .into_iter()
        .map(|(name, version)| (name.to_string(), version.to_string()))
        .collect();
        assert_eq!(map, expected);
    }

    /// Oracle package-lock v2 (`packages` wins over v1 `dependencies`):
    /// → {'@scope/tool': '2.0.0', 'react': '18.2.0'}
    #[test]
    fn package_lock_v2_packages() {
        let text = r#"{
            "packages": {
                "": {"version": "0.0.0"},
                "node_modules/react": {"version": "18.2.0"},
                "node_modules/@scope/tool": {"version": "2.0.0"},
                "node_modules/missing": {}
            },
            "dependencies": {"legacy": {"version": "9.9.9"}}
        }"#;
        let deadline = Deadline::from_ms(GENEROUS);
        let map = dependency_map_for_path("package-lock.json", text, &deadline).unwrap();
        let expected: BTreeMap<String, String> = [("@scope/tool", "2.0.0"), ("react", "18.2.0")]
            .into_iter()
            .map(|(name, version)| (name.to_string(), version.to_string()))
            .collect();
        assert_eq!(map, expected);
        // v1 subtree must be ignored once v2 produced entries.
        assert!(!map.contains_key("legacy"));
    }

    /// Oracle package-lock v1 fallback (no `packages` / empty `packages`):
    /// → {'nested': '2.0.0', 'outer': '1.0.0'}
    #[test]
    fn package_lock_v1_fallback() {
        let text = r#"{
            "dependencies": {
                "outer": {
                    "version": "1.0.0",
                    "dependencies": {"nested": {"version": "2.0.0"}}
                },
                "noversion": {}
            }
        }"#;
        let deadline = Deadline::from_ms(GENEROUS);
        let map = dependency_map_for_path("package-lock.json", text, &deadline).unwrap();
        let expected: BTreeMap<String, String> = [("nested", "2.0.0"), ("outer", "1.0.0")]
            .into_iter()
            .map(|(name, version)| (name.to_string(), version.to_string()))
            .collect();
        assert_eq!(map, expected);
    }

    /// Oracle requirements.txt (via `python_target`):
    /// → {'requests': '2.28.0', 'flask': '>=2.0', 'numpy': '',
    ///    'uvicorn': '0.20.0'}
    #[test]
    fn requirements_map() {
        let text = "# comment\n\
                    requests==2.28.0\n\
                    flask>=2.0  # inline\n\
                    numpy --hash=sha256:abc\n\
                    -r other.txt\n\
                    uvicorn[standard]==0.20.0 \\\n\
                        ; python_version > \"3.8\"\n";
        let deadline = Deadline::from_ms(GENEROUS);
        let map = dependency_map_for_path("requirements.txt", text, &deadline).unwrap();
        let expected: BTreeMap<String, String> = [
            ("requests", "2.28.0"),
            ("flask", ">=2.0"),
            ("numpy", ""),
            ("uvicorn", "0.20.0 ; python_version > \"3.8\""),
        ]
        .into_iter()
        .map(|(name, version)| (name.to_string(), version.to_string()))
        .collect();
        assert_eq!(map, expected);
    }

    #[test]
    fn byte_limit_truncates() {
        let result = parse_manifest_dependency_changes(
            "package.json",
            Some(r#"{"dependencies": {"a": "1"}}"#),
            Some("{}"),
            4,
            GENEROUS,
        );
        assert!(result.truncated);
        assert_eq!(result.parse_errors, vec!["byte_limit_exceeded"]);
        assert!(result.changes.is_empty());
    }

    #[test]
    fn unknown_path_empty_map() {
        let result = parse_manifest_dependency_changes(
            "README.md",
            Some("anything"),
            Some("other"),
            4096,
            GENEROUS,
        );
        assert!(!result.truncated);
        assert!(result.parse_errors.is_empty());
        assert!(result.changes.is_empty());
        assert!(parse_manifest_dependencies("README.md", "anything", 4096, GENEROUS).is_empty());
    }

    #[test]
    fn diff_rows_sorted_by_name() {
        let before = r#"{"dependencies": {"a-pkg": "1.0.0", "b-pkg": "2.0.0", "c-pkg": "3.0.0"}}"#;
        let after = r#"{"dependencies": {"b-pkg": "2.1.0", "c-pkg": "3.0.0", "d-pkg": "4.0.0"}}"#;
        let result = parse_manifest_dependency_changes(
            "package.json",
            Some(before),
            Some(after),
            4096,
            GENEROUS,
        );
        assert!(!result.truncated);
        assert!(result.parse_errors.is_empty());
        let rows: Vec<(String, Option<String>, Option<String>)> = result
            .changes
            .iter()
            .map(|change| {
                (
                    change.package_name.clone(),
                    change.before.clone(),
                    change.after.clone(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            vec![
                ("a-pkg".to_string(), Some("1.0.0".to_string()), None),
                (
                    "b-pkg".to_string(),
                    Some("2.0.0".to_string()),
                    Some("2.1.0".to_string())
                ),
                ("d-pkg".to_string(), None, Some("4.0.0".to_string())),
            ]
        );
        for change in &result.changes {
            assert_eq!(change.manifest_path, "package.json");
        }
    }

    #[test]
    fn malformed_json_parse_error() {
        let result = parse_manifest_dependency_changes(
            "package.json",
            Some("{not json"),
            Some("{}"),
            4096,
            GENEROUS,
        );
        assert!(!result.truncated);
        assert_eq!(result.parse_errors, vec!["parse_error"]);
    }

    #[test]
    fn deadline_exceeded_truncates() {
        // deadline_ms=0 → Instant::now() + 0ms already elapsed at ensure time.
        let result = parse_manifest_dependency_changes(
            "package.json",
            Some(r#"{"dependencies": {"a": "1"}}"#),
            Some(r#"{"dependencies": {"a": "1"}}"#),
            4096,
            0,
        );
        assert!(result.truncated);
        assert_eq!(result.parse_errors, vec!["deadline_exceeded"]);
    }

    /// Oracle pnpm-lock.yaml — packages + snapshots dependencies block:
    /// → {'react': '18.2.0', '@scope/tool': '2.0.0', 'loose': '1.0.0'}
    #[test]
    fn pnpm_lock_scanner() {
        let text = concat!(
            "lockfileVersion: '9.0'\n",
            "packages:\n",
            "  react@18.2.0:\n",
            "    resolution: {integrity: sha512-x}\n",
            "  /@scope/tool@2.0.0:\n",
            "    resolution: {}\n",
            "snapshots:\n",
            "  react@18.2.0:\n",
            "    dependencies:\n",
            "      loose: ^1.0.0\n",
            "      shared: react@18.2.0\n",
        );
        let deadline = Deadline::from_ms(GENEROUS);
        let map = dependency_map_for_path("pnpm-lock.yaml", text, &deadline).unwrap();
        assert_eq!(map.get("react"), Some(&"18.2.0".to_string()));
        assert_eq!(map.get("@scope/tool"), Some(&"2.0.0".to_string()));
        // `loose` is not in `package_versions` → `_exact_dependency_version`
        // strips leading `=^~v` → `1.0.0`.
        assert_eq!(map.get("loose"), Some(&"1.0.0".to_string()));
        // `shared` is not in `package_versions` → `_exact_dependency_version`
        // has nothing to strip, returns the value verbatim.
        assert_eq!(map.get("shared"), Some(&"react@18.2.0".to_string()));
    }

    /// Oracle yarn.lock classic + berry version lines.
    #[test]
    fn yarn_lock_scanner() {
        let text = concat!(
            "# yarn lockfile v1\n",
            "\n",
            "\"left-pad@^1.0.0\", left-pad@^1.1.0:\n",
            "  version \"1.3.0\"\n",
            "\n",
            "\"@scope/tool@npm:2.0.0\":\n",
            "  version: 2.0.0\n",
        );
        let deadline = Deadline::from_ms(GENEROUS);
        let map = dependency_map_for_path("yarn.lock", text, &deadline).unwrap();
        assert_eq!(map.get("left-pad"), Some(&"1.3.0".to_string()));
        assert_eq!(map.get("@scope/tool"), Some(&"2.0.0".to_string()));
    }

    /// Oracle cargo.toml — dependencies + dev-dependencies + workspace +
    /// target tables; `{version = "x"}` inline tables resolved.
    #[test]
    fn cargo_toml_map() {
        let text = "[dependencies]\n\
                    serde = \"1.0\"\n\
                    regex = { version = \"1.11\", features = [\"unicode\"] }\n\
                    \n\
                    [dev-dependencies]\n\
                    tempfile = \"3\"\n\
                    \n\
                    [workspace.dependencies]\n\
                    shared = \"0.1\"\n\
                    \n\
                    [target.'cfg(unix)'.dependencies]\n\
                    nix = \"0.31\"\n";
        let deadline = Deadline::from_ms(GENEROUS);
        let map = dependency_map_for_path("cargo.toml", text, &deadline).unwrap();
        assert_eq!(map.get("serde"), Some(&"1.0".to_string()));
        assert_eq!(map.get("regex"), Some(&"1.11".to_string()));
        assert_eq!(map.get("tempfile"), Some(&"3".to_string()));
        assert_eq!(map.get("shared"), Some(&"0.1".to_string()));
        assert_eq!(map.get("nix"), Some(&"0.31".to_string()));
    }

    /// Oracle pom.xml — namespace-default project + namespaced children.
    #[test]
    fn pom_xml_map() {
        let text = "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n\
                      <dependencies>\n\
                        <dependency>\n\
                          <groupId>com.google.guava</groupId>\n\
                          <artifactId>guava</artifactId>\n\
                          <version>33.0.0</version>\n\
                        </dependency>\n\
                      </dependencies>\n\
                    </project>";
        let deadline = Deadline::from_ms(GENEROUS);
        let map = dependency_map_for_path("pom.xml", text, &deadline).unwrap();
        assert_eq!(
            map.get("com.google.guava:guava"),
            Some(&"33.0.0".to_string())
        );
    }

    /// Temporary Python-oracle check (RTM-026): compare `_dependency_map_for_path`
    /// output against the Rust port for package.json, package-lock.json
    /// (v1 + v2) and requirements.txt. Marked #[ignore]d-env — skip when the
    /// Python worktree is not importable.
    #[test]
    fn python_oracle_parity() {
        use std::process::Command;
        let fixtures: &[(&str, &str)] = &[
            ("package.json", r#"{"dependencies":{"a":"1.0"},"devDependencies":{"b":"~2"},"peerDependencies":{"c":"3"},"other":{"d":"x"}}"#),
            ("package-lock.json", r#"{"packages":{"node_modules/x":{"version":"1.2.3"},"node_modules/@s/y":{"version":"0.1"}},"dependencies":{"x":{"version":"9.9.9"}}}"#),
            ("package-lock.json", r#"{"dependencies":{"left":{"version":"1.0","dependencies":{"nested":{"version":"2.0"}}},"right":{"version":"3.0"}}}"#),
            ("requirements.txt", "flask==2.0 # comment\nrequests>=2\n-e ./local\n-r other.txt\nurllib3 @ https://example.com/u.whl --hash=sha256:ab\n"),
        ];
        let python_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../src");
        for (path, text) in fixtures {
            let output = Command::new("python3")
                .env("PYTHONPATH", python_path.as_os_str())
                .args(["-c", ORACLE_SCRIPT, path, text])
                .output()
                .expect("python3 must exist for oracle test");
            assert!(
                output.status.success(),
                "oracle failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let oracle: BTreeMap<String, String> = serde_json::from_slice(&output.stdout).unwrap();
            let deadline = Deadline::from_ms(GENEROUS);
            let rust = dependency_map_for_path(path, text, &deadline).unwrap();
            assert_eq!(rust, oracle, "mismatch for {path}");
        }
    }

    const ORACLE_SCRIPT: &str = r#"
import json, sys
from codex_plugin_scanner.guard.runtime.package_manifest_diff import _dependency_map_for_path
path, text = sys.argv[1], sys.argv[2]
print(json.dumps(_dependency_map_for_path(path, text, deadline=float("inf")), sort_keys=True))
"#;
}
