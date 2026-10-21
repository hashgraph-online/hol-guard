//! The credential-looking prompt-file artifact
//! (`_codex_prompt_credential_file_artifact`): the prompt names a local
//! dotfile and asks the harness to read it, and the first 64 KiB of that file
//! scan as credential material.
//!
//! Python sends the prompt text, the working directory relative names resolve
//! against and the configuration path; everything between — which tokens look
//! like paths, which of them resolve to a readable dotfile, whether the
//! content is credential-looking, and the artifact copy and fingerprint — runs
//! here.

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use fancy_regex::{Regex, RegexBuilder};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::codex_output_env::Ctx;
use crate::codex_output_py::{is_py_space, py_rstrip, py_strip, PyPath};
use crate::prompt_analysis::GuardRunPromptArtifact;
use crate::sfrs_json::dumps_sorted;

/// `_PROMPT_CONTENT_SCAN_MAX_BYTES`.
const CONTENT_SCAN_MAX_BYTES: usize = 64 * 1024;
/// `_CODEX_PROMPT_FILE_FINGERPRINT_LENGTH`.
pub(crate) const FINGERPRINT_LENGTH: usize = 24;
/// `_truncate_codex_display_text(..., limit=320)` at the one call site.
const DISPLAY_LIMIT: usize = 320;
/// `_PROMPT_CONTENT_SCAN_SKIP_BASENAMES`: names a dedicated sensitive-path
/// rule already covers, so the content scan leaves them to it.
const SKIP_BASENAMES: [&str; 5] = [".env", ".npmrc", ".pypirc", ".netrc", ".git-credentials"];
/// `_PROMPT_CONTENT_SCAN_SECRET_BASENAME_MARKERS`.
const SECRET_BASENAME_MARKERS: [&str; 7] = [
    "auth",
    "credential",
    "env",
    "key",
    "pass",
    "secret",
    "token",
];
/// `_CODEX_PROMPT_SECRET_KEY_MARKERS`.
const SECRET_KEY_MARKERS: [&str; 8] = [
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASS",
    "API_KEY",
    "API-KEY",
    "AUTH",
    "CREDENTIAL",
];
/// `_redact_codex_prompt_secret_assignments` assignment terminators.
const ASSIGNMENT_BREAKS: [char; 6] = [' ', '\t', '\n', '\r', ',', ';'];
/// Longest content-scan budget the op grants, whatever the caller asks for.
const MAX_DEADLINE_MS: u64 = 60_000;

/// `classify_secret_content(content)` with its default
/// `suppress_samples=True`: documentation samples do not make a dotfile
/// credential-looking. A scan that cannot finish reports no finding, which
/// leaves the prompt un-flagged rather than inventing one.
fn credential_content_found(content: &str, deadline: Instant) -> bool {
    let body = json!({
        "text": content,
        "suppress_samples": true,
        "documentation_sample_context": false,
    });
    crate::content_sensitivity::evaluate("content", &body, deadline)
        .ok()
        .and_then(|result| result["ok"].as_array().map(|found| !found.is_empty()))
        .unwrap_or(false)
}

/// Compile a prompt-file pattern. Both prompt scans walk whatever the user
/// pasted, and a harness hands over as much as a megabyte of it. These
/// patterns carry a one-character negative lookbehind, so matching runs on the
/// backtracking engine and costs a few steps per character scanned: the
/// default million-step budget runs out part-way through an ordinary long
/// prompt, which would end the walk early. Hold them to a ceiling that a
/// prompt-sized input cannot reach while still stopping a runaway.
pub(crate) fn compile(pattern: &str) -> Regex {
    RegexBuilder::new(pattern)
        .backtrack_limit(100_000_000)
        .build()
        .expect("prompt-file pattern is a compile-time constant")
}

/// Every path-shaped token a prompt can name. The attachment scan builds its
/// own pattern around this one.
pub(crate) const PATH_TOKEN_PATTERN: &str =
    r#"(?<![\w/.-])\.[A-Za-z0-9][A-Za-z0-9_.-]{0,255}|(?:~|\.{1,2}|/)[^\s'"`<>|;(){}\[\]]{0,255}"#;

static PATH_TOKEN: LazyLock<Regex> = LazyLock::new(|| compile(PATH_TOKEN_PATTERN));

/// The verbs that make a prompt a request to read something.
static READ_VERB: LazyLock<Regex> = LazyLock::new(|| {
    compile(r"(?i)\b(?:read|open|print|show|dump|cat|head|tail|less|view|display)\b")
});

/// Both prompt scans start by asking whether the prompt asks for a read at
/// all, and leave a prompt that names no read verb alone.
pub(crate) fn has_read_verb(prompt_text: &str) -> bool {
    READ_VERB.is_match(prompt_text).unwrap_or(false)
}

/// Guard's own retry copy, removed before the intent hash so a retried prompt
/// hashes to the first attempt.
static RETRY_BOILERPLATE: LazyLock<[Regex; 2]> = LazyLock::new(|| {
    [
        compile(
            r"(?i)Warning:\s*HOL Guard flagged this prompt because it asks for direct local secret access and is protecting your local secrets\. If that is intentional, continue and Guard will ask again on the actual tool call\. Open HOL Guard to approve or keep this blocked:\s*\S+\. After you choose, retry the same the harness action\.?",
        ),
        compile(
            r"(?i)HOL Guard stopped this Codex prompt before Codex could open (?:a credential-looking local file|a sensitive local file)\. Codex does not expose native approval prompts for Read-tool file reads, so Guard blocks this request at prompt time\. Open HOL Guard to approve or keep this blocked:\s*\S+\. After you choose, retry the same Codex action\.?",
        ),
    ]
});

/// `/(?:Users|home)/[^/\s]+` and `[A-Za-z]:\\Users\\[^\\\s]+`, the home
/// directories `_sanitize_codex_display_text` replaces with `~`.
static POSIX_HOME: LazyLock<Regex> = LazyLock::new(|| compile(r"/(?:Users|home)/[^/\s]+"));
static WINDOWS_HOME: LazyLock<Regex> = LazyLock::new(|| compile(r"[A-Za-z]:\\Users\\[^\\\s]+"));

/// `" ".join(value.split())`.
fn collapse(value: &str) -> String {
    value
        .split(is_py_space)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `_redact_codex_prompt_secret_assignments`: replace the value of every
/// secret-looking `KEY=value` assignment with `[redacted]`.
pub(crate) fn redact_secret_assignments(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut output = String::with_capacity(value.len());
    let mut index = 0usize;
    while index < chars.len() {
        let Some(offset) = chars[index..].iter().position(|c| *c == '=') else {
            output.extend(&chars[index..]);
            break;
        };
        let equals = index + offset;
        let mut key_start = equals;
        while key_start > index && !ASSIGNMENT_BREAKS.contains(&chars[key_start - 1]) {
            key_start -= 1;
        }
        let key: String = chars[key_start..equals].iter().collect();
        let key = py_strip(&key).to_uppercase();
        if !key.is_empty() && SECRET_KEY_MARKERS.iter().any(|marker| key.contains(marker)) {
            let mut value_start = equals + 1;
            while value_start < chars.len() && is_py_space(chars[value_start]) {
                value_start += 1;
            }
            let mut value_end = value_start;
            while value_end < chars.len() && !ASSIGNMENT_BREAKS.contains(&chars[value_end]) {
                value_end += 1;
            }
            output.extend(&chars[index..value_start]);
            output.push_str("[redacted]");
            index = value_end;
            continue;
        }
        output.extend(&chars[index..=equals]);
        index = equals + 1;
    }
    output
}

/// `_sanitize_codex_display_text`.
fn sanitize_display(value: &str) -> String {
    let redacted = redact_secret_assignments(&collapse(value));
    let posix = POSIX_HOME.replace_all(&redacted, "~");
    WINDOWS_HOME.replace_all(&posix, "~").into_owned()
}

/// `_truncate_codex_display_text`.
fn truncate(value: &str, limit: usize) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= limit {
        return value.to_owned();
    }
    let head: String = chars[..limit - 1].iter().collect();
    format!("{}…", py_rstrip(&head))
}

/// `_codex_prompt_display_text`.
pub(crate) fn display_text(prompt_text: &str, requested_path: Option<&str>) -> String {
    let suffix = match requested_path {
        Some(path) if !py_strip(path).is_empty() => {
            format!(" for `{}`", sanitize_display(py_strip(path)))
        }
        _ => String::new(),
    };
    format!(
        "Codex prompt{suffix}: {}",
        truncate(&sanitize_display(prompt_text), DISPLAY_LIMIT)
    )
}

/// What the prompt asks for, with Guard's own retry copy and the display
/// redactions taken out, so the same request hashes the same way twice.
fn intent_text(prompt_text: &str) -> String {
    let mut normalized = sanitize_display(prompt_text);
    for pattern in RETRY_BOILERPLATE.iter() {
        normalized = pattern.replace_all(&normalized, " ").into_owned();
    }
    collapse(&normalized)
}

/// `_prompt_path_looks_secret_bearing`.
fn looks_secret_bearing(name: &str) -> bool {
    let lowered = name.to_lowercase();
    SECRET_BASENAME_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
}

/// `_expand_prompt_scan_path`.
fn expand(ctx: &Ctx, requested_path: &str, cwd: Option<&PyPath>) -> PyPath {
    let Some(expanded) = ctx.expanduser(requested_path) else {
        return PyPath::new(requested_path);
    };
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        cwd.unwrap_or(&ctx.process_cwd).join(&expanded.to_string())
    };
    match ctx.host.real_path(&absolute.to_string()) {
        Some(resolved) => PyPath::new(&resolved),
        None => absolute,
    }
}

/// `_resolve_prompt_scan_path`.
fn resolve_scan_path(ctx: &Ctx, requested_path: &str, cwd: Option<&PyPath>) -> Option<PyPath> {
    let stripped = py_strip(requested_path).trim_matches(|c| c == '\'' || c == '"');
    if stripped.is_empty() {
        return None;
    }
    let exact = expand(ctx, stripped, cwd);
    if ctx.host.is_regular_file(&exact.to_string()) {
        return Some(exact);
    }
    let normalized = stripped.trim_end_matches(|c| ".,;:!?)]}".contains(c));
    if normalized.is_empty() || normalized == stripped {
        return Some(exact);
    }
    Some(expand(ctx, normalized, cwd))
}

/// `_codex_prompt_credential_file_artifact`: the first token of the prompt
/// that names a readable credential-looking dotfile, as a prompt-request
/// artifact; `None` when the prompt names no such file.
pub(crate) fn review_prompt_credential_file(
    ctx: &Ctx,
    prompt_text: &str,
    cwd: Option<&str>,
    config_path: &str,
    deadline_ms: u64,
) -> Option<GuardRunPromptArtifact> {
    if !has_read_verb(prompt_text) {
        return None;
    }
    let deadline = Instant::now() + Duration::from_millis(deadline_ms.min(MAX_DEADLINE_MS));
    let cwd = cwd.map(PyPath::new);
    for found in PATH_TOKEN.find_iter(prompt_text) {
        // A pattern that runs out of its backtracking budget ends the walk, as
        // the deadline below does. This scan has no artifact for a prompt it
        // could not finish reading, and inventing a credential-file review for
        // a path it never resolved would name a file the prompt may not carry.
        let Ok(found) = found else { break };
        // Past the deadline the caller has already given up on this answer, so
        // nothing further is resolved or opened on its behalf. A prompt that
        // names thousands of ordinary paths resolves every one of them, and
        // those lookups are the slow part on a cold filesystem.
        if Instant::now() >= deadline {
            break;
        }
        let requested_path = found.as_str();
        let Some(path) = resolve_scan_path(ctx, requested_path, cwd.as_ref()) else {
            continue;
        };
        let name = path.name();
        if SKIP_BASENAMES.contains(&name) || !name.starts_with('.') || !looks_secret_bearing(name) {
            continue;
        }
        let normalized_path = path.to_string();
        if !ctx.host.is_regular_file(&normalized_path) {
            continue;
        }
        let Some(content) = ctx
            .host
            .file_text_prefix(&normalized_path, CONTENT_SCAN_MAX_BYTES)
        else {
            continue;
        };
        if !credential_content_found(&content, deadline) {
            continue;
        }
        return Some(artifact(
            prompt_text,
            requested_path,
            name,
            &normalized_path,
            config_path,
        ));
    }
    None
}

fn hex_digest(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}

fn artifact(
    prompt_text: &str,
    requested_path: &str,
    name: &str,
    normalized_path: &str,
    config_path: &str,
) -> GuardRunPromptArtifact {
    let fingerprint: String = hex_digest(&dumps_sorted(&json!({
        "harness": "codex",
        "prompt_path": normalized_path,
        "content_class": "credential-looking local file",
    })))
    .chars()
    .take(FINGERPRINT_LENGTH)
    .collect();
    let display = display_text(prompt_text, Some(requested_path));
    let intent_hash = hex_digest(&intent_text(prompt_text));
    let mut metadata = Map::new();
    metadata.insert(
        "prompt_signals".to_owned(),
        json!(["requested file content contains credential-looking material"]),
    );
    metadata.insert(
        "prompt_summary".to_owned(),
        json!("Prompt asks Codex to read a credential-looking local file."),
    );
    metadata.insert("prompt_matched_text".to_owned(), json!(requested_path));
    metadata.insert("prompt_intent_hash".to_owned(), json!(intent_hash));
    metadata.insert("prompt_display_text".to_owned(), json!(display));
    metadata.insert("prompt_request_class".to_owned(), json!("secret_read"));
    metadata.insert("prompt_request_classes".to_owned(), json!(["secret_read"]));
    metadata.insert("request_summary".to_owned(), json!(display));
    metadata.insert("runtime_request_summary".to_owned(), json!(display));
    metadata.insert(
        "runtime_request_reason".to_owned(),
        json!("Guard scanned a small local dotfile before Codex read it and found credential-looking text."),
    );
    metadata.insert("normalized_path".to_owned(), json!(normalized_path));
    GuardRunPromptArtifact {
        artifact_id: format!("codex:project:prompt-file:{fingerprint}"),
        name: format!("credential-looking local file {name}"),
        harness: "codex".to_owned(),
        artifact_type: "prompt_request".to_owned(),
        source_scope: "project".to_owned(),
        config_path: config_path.to_owned(),
        metadata,
    }
}

/// `bytes.decode("utf-8", errors="ignore")`: undecodable sequences are
/// dropped rather than replaced, and a multi-byte character the read cut in
/// half at the byte limit is dropped with them.
pub fn decode_ignoring_errors(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len());
    let mut rest = bytes;
    loop {
        match std::str::from_utf8(rest) {
            Ok(tail) => {
                text.push_str(tail);
                return text;
            }
            Err(error) => {
                let (good, bad) = rest.split_at(error.valid_up_to());
                text.push_str(std::str::from_utf8(good).unwrap_or_default());
                let Some(skip) = error.error_len() else {
                    return text;
                };
                rest = &bad[skip..];
            }
        }
    }
}

/// Serialized answer for the wire: the artifact, or JSON `null`.
pub(crate) fn answer(artifact: Option<GuardRunPromptArtifact>) -> Value {
    artifact.map_or(Value::Null, |found| found.to_dict())
}

#[cfg(all(test, unix))]
#[path = "codex_prompt_credential_file_tests.rs"]
mod tests;
