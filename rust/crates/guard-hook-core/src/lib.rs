#![forbid(unsafe_code)]

use guard_contracts::{
    HookReviewResponseV1, HookSourceFileRefV1, NativeHookRequestV1, NATIVE_PROTOCOL_VERSION,
};
use guard_rules::{
    MAX_CONTENT_ITEMS, MAX_DEPTH, MAX_OBJECT_KEYS, MAX_OUTPUT_CHARS, MAX_SCAN_BYTES,
    OUTPUT_TEXT_KEYS, PAYLOAD_OUTPUT_KEYS, REVIEWED_EXCERPT_CHARS,
};
use guard_scanner::{scan_match_spans, scan_text};
use guard_secure_fs::{classify_scannable_source_path, read_bounded, sensitive_path_family};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;
use std::time::{Duration, Instant};

mod source_slice;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedOutput {
    pub text: String,
    pub chars: usize,
    pub truncated: bool,
}

fn collect_output_text(value: &Value) -> ExtractedOutput {
    fn append(parts: &mut Vec<String>, chars: &mut usize, truncated: &mut bool, text: &str) {
        if *truncated || text.is_empty() {
            return;
        }
        let remaining = MAX_OUTPUT_CHARS.saturating_sub(*chars);
        if text.chars().count() > remaining {
            parts.push(text.chars().take(remaining).collect());
            *chars = MAX_OUTPUT_CHARS;
            *truncated = true;
            return;
        }
        parts.push(text.to_owned());
        *chars += text.chars().count();
    }

    fn traverse(
        value: &Value,
        depth: usize,
        parts: &mut Vec<String>,
        chars: &mut usize,
        truncated: &mut bool,
        seen: &mut HashSet<usize>,
    ) {
        if *truncated {
            return;
        }
        if depth > MAX_DEPTH {
            *truncated = true;
            return;
        }
        match value {
            Value::String(text) => append(parts, chars, truncated, text),
            Value::Array(items) => {
                let id = value as *const Value as usize;
                if !seen.insert(id) {
                    *truncated = true;
                    return;
                }
                for item in items.iter().take(MAX_CONTENT_ITEMS) {
                    traverse(item, depth + 1, parts, chars, truncated, seen);
                    if *truncated {
                        break;
                    }
                }
                if items.len() > MAX_CONTENT_ITEMS {
                    *truncated = true;
                }
                seen.remove(&id);
            }
            Value::Object(record) => {
                if record.get("type").and_then(Value::as_str) == Some("text") {
                    if let Some(text) = record.get("text").and_then(Value::as_str) {
                        append(parts, chars, truncated, text);
                        return;
                    }
                }
                let id = value as *const Value as usize;
                if !seen.insert(id) {
                    *truncated = true;
                    return;
                }
                let mut keys_seen = 0usize;
                for key in OUTPUT_TEXT_KEYS {
                    let Some(child) = record.get(*key) else {
                        continue;
                    };
                    if keys_seen >= MAX_OBJECT_KEYS {
                        *truncated = true;
                        break;
                    }
                    keys_seen += 1;
                    traverse(child, depth + 1, parts, chars, truncated, seen);
                    if *truncated {
                        break;
                    }
                }
                seen.remove(&id);
            }
            _ => {}
        }
    }

    let mut parts = Vec::new();
    let mut chars = 0usize;
    let mut truncated = false;
    let mut seen = HashSet::new();
    traverse(value, 0, &mut parts, &mut chars, &mut truncated, &mut seen);
    ExtractedOutput {
        text: parts.concat(),
        chars,
        truncated,
    }
}

pub fn extract_payload_output(payload: &Value) -> ExtractedOutput {
    let Some(record) = payload.as_object() else {
        return ExtractedOutput {
            text: String::new(),
            chars: 0,
            truncated: false,
        };
    };
    let mut parts = Vec::new();
    let mut truncated = false;
    for key in PAYLOAD_OUTPUT_KEYS {
        if let Some(value) = record.get(*key) {
            let result = collect_output_text(value);
            truncated |= result.truncated;
            if !result.text.is_empty() {
                parts.push(result.text);
            }
        }
    }
    let joined = parts.join("\n");
    let chars = joined.chars().count();
    if chars > MAX_OUTPUT_CHARS {
        truncated = true;
    }
    ExtractedOutput {
        text: joined.chars().take(MAX_OUTPUT_CHARS).collect(),
        chars: chars.min(MAX_OUTPUT_CHARS),
        truncated,
    }
}

fn deadline(request: &NativeHookRequestV1) -> Option<Instant> {
    request
        .deadline_budget_ms
        .map(|budget| Instant::now() + Duration::from_millis(budget.min(9_000)))
}

fn source_ref(payload: &Value) -> Option<HookSourceFileRefV1> {
    payload
        .get("guard_source_ref")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
}

fn envelope_target(payload: &Value) -> Option<String> {
    let input = payload
        .get("tool_input")
        .or_else(|| payload.get("toolInput"))?
        .as_object()?;
    for key in ["file_path", "path", "filePath"] {
        if let Some(value) = input.get(key).and_then(Value::as_str) {
            if !value.trim().is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}

/// A listing target that resolves inside the session's workspace with no
/// hidden component below it. PreToolUse already admitted the read against the
/// workspace, and an ordinary source folder such as `src/lib/auth` holds
/// feature code rather than credential material, so denying its names-only
/// listing stops real work without protecting anything. The recheck still
/// refuses a target that resolves outside the workspace, or through a link
/// into a dot-directory such as `.aws`, which is the post-PreToolUse swap it
/// exists to catch. Only directories qualify, and every component of the
/// resolved path has to name either no credential at all or one of the feature
/// folders in `FEATURE_FOLDER_NAMES`: a credential-named file such as
/// `deploy/id_rsa`, or a store such as `secrets` or `prod-secrets`, keeps its
/// review even inside the workspace, including when an admitted folder is
/// swapped for a link into one.
fn workspace_visible_target(target: &Path, request: &NativeHookRequestV1) -> bool {
    let Some(cwd) = request.cwd.as_deref() else {
        return false;
    };
    let Ok(workspace) = std::fs::canonicalize(cwd) else {
        return false;
    };
    let candidate = if target.is_absolute() {
        target.to_path_buf()
    } else {
        workspace.join(target)
    };
    let Ok(resolved) = std::fs::canonicalize(candidate) else {
        return false;
    };
    if !resolved.is_dir() {
        return false;
    }
    let Ok(relative) = resolved.strip_prefix(&workspace) else {
        return false;
    };
    relative.components().all(|component| {
        let name = component.as_os_str().to_string_lossy();
        !name.starts_with('.')
            && (!guard_secure_fs::credential_directory_path(Path::new(name.as_ref()))
                || FEATURE_FOLDER_NAMES.contains(&name.to_ascii_lowercase().as_str()))
    })
}

/// Credential-marker names that, as a workspace directory, hold feature code
/// rather than stored credentials.
const FEATURE_FOLDER_NAMES: [&str; 2] = ["auth", "authorization"];

fn sensitive_envelope_target(request: &NativeHookRequestV1) -> bool {
    let payload = &request.payload;
    let target = envelope_target(payload);
    let resolved_directory_target = payload
        .get("resolved_directory_target")
        .and_then(Value::as_str);
    let is_sensitive = |target: &str| {
        let path = Path::new(target.trim());
        sensitive_path_family(path).is_some()
            || (guard_secure_fs::credential_named_path(path)
                && !workspace_visible_target(path, request))
    };
    // A `file.json?q=<filter>` read queries the file before the `?`.
    let is_sensitive_entry = |entry: &str| {
        is_sensitive(entry)
            || entry
                .split_once('?')
                .is_some_and(|(base, _)| is_sensitive(base))
    };
    target.as_deref().is_some_and(|target| {
        search_entries(target, request)
            .iter()
            .any(|entry| is_sensitive_entry(entry))
    }) || resolved_directory_target.is_some_and(is_sensitive)
}

/// The paths an OMP search `path` names. When the whole string is not an
/// existing path, OMP splits it on `;` and searches each entry, so each entry
/// is judged on its own: joining them would let one entry's directory names
/// and another's file name read as a single credential path. A string that
/// exists, or cannot be resolved, is also judged whole.
fn search_entries<'a>(target: &'a str, request: &NativeHookRequestV1) -> Vec<&'a str> {
    if !target.contains(';') {
        return vec![target];
    }
    let mut entries: Vec<&str> = target
        .split(';')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();
    let literal = match target.strip_prefix("~/") {
        Some(rest) => Some(Path::new(&request.home_dir).join(rest)),
        None if Path::new(target).is_absolute() => Some(Path::new(target).to_path_buf()),
        None => request
            .cwd
            .as_deref()
            .map(|cwd| Path::new(cwd).join(target)),
    };
    let literal_absent = literal.is_some_and(|path| {
        std::fs::symlink_metadata(path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    });
    if !literal_absent {
        entries.push(target);
    }
    entries
}

fn inline_local_content(payload: &Value) -> bool {
    let Some(input) = payload
        .get("tool_input")
        .or_else(|| payload.get("toolInput"))
    else {
        return false;
    };
    let Some(input) = input.as_object() else {
        return true;
    };
    let may_be_local = |value: &Value| {
        value
            .as_str()
            .map(local_samples_should_be_unsuppressed)
            .unwrap_or(true)
    };
    ["file_path", "path", "filePath"]
        .iter()
        .filter_map(|key| input.get(*key))
        .any(may_be_local)
        || ["file_paths", "filePaths"]
            .iter()
            .filter_map(|key| input.get(*key))
            .any(|value| {
                value
                    .as_array()
                    .map(|paths| paths.iter().any(may_be_local))
                    .unwrap_or(true)
            })
}

pub fn sha256_text(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}

fn has_output_key(payload: &Value) -> bool {
    payload
        .as_object()
        .is_some_and(|record: &Map<String, Value>| {
            PAYLOAD_OUTPUT_KEYS
                .iter()
                .any(|key| record.contains_key(*key))
        })
}

fn allow_inline_output(reason_code: &str, text: &str) -> HookReviewResponseV1 {
    let mut response = HookReviewResponseV1::allow(reason_code);
    response.reviewed_output_sha256 = Some(sha256_text(text));
    response
}

fn canonical_hex_digest(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?;
    if text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        // Receipt validation canonicalizes digests to lowercase hex.
        Some(text.to_ascii_lowercase())
    } else {
        None
    }
}

/// Canonical proof digest for a post-tool payload: a validated
/// `guard_source_ref.output_sha256`, then `tool_response_summary.output_sha256`,
/// then a sha256 over complete inline `tool_response` output. Truncated or
/// excerpt-only output gets no fabricated proof.
pub fn canonical_observed_output_sha256(payload: &Value) -> Option<String> {
    let record = payload.as_object()?;
    if let Some(digest) = canonical_hex_digest(
        record
            .get("guard_source_ref")
            .and_then(|value| value.get("output_sha256")),
    ) {
        return Some(digest);
    }
    if let Some(digest) = canonical_hex_digest(
        record
            .get("tool_response_summary")
            .and_then(|value| value.get("output_sha256")),
    ) {
        return Some(digest);
    }
    // Hash the same output surface `review_inline` scans: every supported
    // output key, not just `tool_response`. A secret in `stdout`/`stderr` must
    // still yield a proof digest so observe mode can record the decision.
    let extracted = extract_payload_output(payload);
    if extracted.truncated || !has_output_key(payload) {
        return None;
    }
    // A payload that declares excerpted output only proves the excerpt —
    // never fabricate a digest for truncated output.
    if record
        .get("tool_response_summary")
        .and_then(|value| value.get("excerpt_truncated"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return None;
    }
    Some(sha256_text(&extracted.text))
}

fn output_equivalent(text: &str, output_sha256: &str, output_chars: i64) -> bool {
    if output_chars < 0 {
        return false;
    }
    if sha256_text(text) == output_sha256 && text.chars().count() == output_chars as usize {
        return true;
    }
    if let Some(stripped) = text.strip_suffix('\n') {
        return sha256_text(stripped) == output_sha256
            && stripped.chars().count() == output_chars as usize;
    }
    false
}

fn local_samples_should_be_unsuppressed(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let parts: Vec<&str> = normalized.split('/').collect();
    let docs = [
        "__fixtures__",
        "__tests__",
        "docs",
        "documentation",
        "examples",
        "fixtures",
        "samples",
        "spec",
        "test",
        "tests",
    ];
    if parts.iter().any(|part| docs.contains(part)) {
        return false;
    }
    ![".adoc", ".md", ".mdx", ".rst", ".txt"]
        .iter()
        .any(|suffix| normalized.ends_with(suffix))
}

fn sensitive_reason(family: &str) -> &'static str {
    match family {
        "local .env file" => "Guard treats .env files as sensitive because they commonly store local secrets.",
        "npm registry credentials" => "Guard treats .npmrc as sensitive because it may contain registry tokens.",
        "Python package credentials" => "Guard treats .pypirc as sensitive because it may contain package credentials.",
        "netrc credentials" => "Guard treats .netrc as sensitive because it may contain login secrets.",
        "Git credential store" => "Guard treats .git-credentials as sensitive because it may contain repository credentials.",
        "AWS shared credentials file" => "Guard treats AWS shared credentials as sensitive because they contain cloud access keys.",
        "AWS shared config file" => "Guard treats AWS shared config as sensitive because it may contain credential profiles.",
        "Docker client config" => "Guard treats Docker client config as sensitive because it may contain registry auth.",
        "Kubernetes config" => "Guard treats Kubernetes config as sensitive because it may include cluster credentials.",
        "SSH private key" => "Guard treats SSH private keys as sensitive because they provide direct host access.",
        "SSH client config" => "Guard treats SSH config as sensitive because it may reveal or shape host credentials.",
        "GnuPG key material" => "Guard treats GnuPG key material as sensitive because it can unlock encrypted assets.",
        "Terraform variable secrets" => "Guard treats Terraform variable files as sensitive because they often contain secrets.",
        _ => "Guard treats wallet and private-key files as sensitive because they can authorize account control.",
    }
}

fn inconclusive_source() -> HookReviewResponseV1 {
    // Python's source fast path retains detailed internal reason codes, but
    // every non-risky proof failure falls back to the standard PostToolUse
    // path. With a source-ref-only payload that public contract is a safe
    // deny/block with `no_output_to_review`. Keep the Rust classifier details
    // internal so native mode does not change observable reason semantics.
    HookReviewResponseV1::deny(
        "no_output_to_review",
        "HOL Guard could not complete local hook review safely.",
    )
}

fn review_source(
    request: &NativeHookRequestV1,
    source: &HookSourceFileRefV1,
) -> HookReviewResponseV1 {
    if source.version != 1 {
        return inconclusive_source();
    }
    if source.output_chars < 0 || source.output_chars > MAX_SCAN_BYTES as i64 {
        return inconclusive_source();
    }
    if source.output_sha256.len() != 64
        || !source
            .output_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return inconclusive_source();
    }
    let Some(target) = envelope_target(&request.payload) else {
        return inconclusive_source();
    };
    let candidate = source.tool_input_path.as_deref().unwrap_or(&source.path);
    let cwd = request
        .cwd
        .as_deref()
        .map(Path::new)
        .unwrap_or_else(|| Path::new("."));
    let home = Path::new(&request.home_dir);
    if let Some((family, _)) = sensitive_path_family(Path::new(candidate)) {
        return HookReviewResponseV1::deny("sensitive_path", sensitive_reason(family));
    }
    // A failed read of a missing file returns the host's error text, not file
    // content. No file backs the reference, so the presented text is reviewed
    // on its own, as for any inline output.
    if host_reported_error(&request.payload)
        && source_missing(candidate, cwd, home)
        && source_missing(&target, cwd, home)
    {
        return review_presented_output(request, source);
    }
    let allow_external =
        matches!(request.harness.as_str(), "pi" | "omp") && request.source_ref_external_allowed;
    let candidate_decision =
        classify_scannable_source_path(candidate, cwd, Some(home), allow_external);
    if !candidate_decision.allowed {
        return inconclusive_source();
    }
    let target_decision = classify_scannable_source_path(&target, cwd, Some(home), allow_external);
    if !target_decision.allowed {
        return inconclusive_source();
    }
    let Some(path) = candidate_decision.resolved_path else {
        return inconclusive_source();
    };
    let Some(target_path) = target_decision.resolved_path else {
        return inconclusive_source();
    };
    if path != target_path {
        return inconclusive_source();
    }
    let read = match read_bounded(&path, MAX_SCAN_BYTES) {
        Ok(read) => read,
        Err(_) => return inconclusive_source(),
    };
    if read.bytes.contains(&0) {
        return inconclusive_source();
    }
    let Ok(text) = std::str::from_utf8(&read.bytes) else {
        return inconclusive_source();
    };
    let raw_output_matches = output_equivalent(text, &source.output_sha256, source.output_chars);
    let scan = scan_text(
        text,
        local_samples_should_be_unsuppressed(&source.path),
        true,
        MAX_SCAN_BYTES,
        deadline(request),
    );
    if scan.budget_exhausted {
        // Name the real exit, as the inline path does. An exhausted scan budget
        // is not a failed proof, and reporting it as `no_output_to_review` hid
        // a load problem behind a classifier problem.
        return HookReviewResponseV1::deny(
            "scanner_budget_exhausted",
            "HOL Guard could not complete local hook review safely.",
        );
    }
    if !scan.matches.is_empty() && (raw_output_matches || !clean_slice(request, text, &source.path))
    {
        return HookReviewResponseV1::deny(
            "source_secret_match",
            "HOL Guard blocked this output because it contains sensitive content.",
        );
    }
    if !raw_output_matches {
        // A logical skill URI claims this exact installed document, rather
        // than a host-formatted ordinary file presentation.
        if source.path.starts_with("skill://") {
            return inconclusive_source();
        }
        // Hosts may add line anchors or headers. Scan the entire presentation
        // independently, but never promote a partial excerpt to original output.
        return review_presented_output(request, source);
    }
    let mut response = HookReviewResponseV1::allow("source_full_scan_allow");
    response.reviewed_output_sha256 = Some(source.output_sha256.clone());
    response
}

/// Review the text the host presented on its own. Only complete output whose
/// digest matches the reference is reviewed; a partial excerpt is never
/// promoted to original output.
fn review_presented_output(
    request: &NativeHookRequestV1,
    source: &HookSourceFileRefV1,
) -> HookReviewResponseV1 {
    let output = extract_payload_output(&request.payload);
    let excerpt_truncated = request
        .payload
        .get("tool_response_summary")
        .and_then(|summary| summary.get("excerpt_truncated"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if output.truncated
        || excerpt_truncated
        || output.text.chars().count() != source.output_chars as usize
        || sha256_text(&output.text) != source.output_sha256
    {
        return inconclusive_source();
    }
    review_inline(request)
}

/// Whether the host reported the tool call as failed.
fn host_reported_error(payload: &Value) -> bool {
    ["is_error", "isError"]
        .iter()
        .any(|key| payload.get(*key).and_then(Value::as_bool) == Some(true))
}

/// Whether nothing exists at `target`. Oh My Pi's `path:selector` form
/// counts as missing only when the base path before the selector is missing
/// too. Any error other than "not found" leaves the path treated as present.
fn source_missing(target: &str, cwd: &Path, home: &Path) -> bool {
    let missing = |candidate: &str| {
        guard_secure_fs::resolve_candidate(candidate, Some(cwd), home).is_ok_and(|path| {
            std::fs::symlink_metadata(path)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        })
    };
    if !missing(target) {
        return false;
    }
    let name_start = target.rfind(['/', '\\']).map_or(0, |index| index + 1);
    match target[name_start..].rfind(':') {
        Some(colon) => missing(&target[..name_start + colon]),
        None => true,
    }
}

/// Whether the output is a line-numbered slice of `file` that no whole-file
/// match overlaps and whose runs of lines, each with the context above it,
/// match no secret rule (see [`source_slice`]). The presented text is still verified
/// and scanned on its own afterwards.
fn clean_slice(request: &NativeHookRequestV1, file: &str, path: &str) -> bool {
    let output = extract_payload_output(&request.payload);
    if output.truncated {
        return false;
    }
    let Some(runs) = source_slice::covered_runs(&output.text, file) else {
        return false;
    };
    if runs
        .iter()
        .any(|&(first, last)| source_slice::key_block_overlaps(file, first, last))
    {
        return false;
    }
    let local = local_samples_should_be_unsuppressed(path);
    let Some(spans) = scan_match_spans(file, local, true, deadline(request)) else {
        return false;
    };
    runs.iter().all(|&(first, last)| {
        if source_slice::spans_overlap(file, first, last, &spans) {
            return false;
        }
        let start = first.saturating_sub(source_slice::CONTEXT_LINES).max(1);
        let scan = scan_text(
            &source_slice::lines(file, start, last),
            local,
            true,
            MAX_SCAN_BYTES,
            deadline(request),
        );
        !scan.budget_exhausted && scan.matches.is_empty()
    })
}

fn review_inline(request: &NativeHookRequestV1) -> HookReviewResponseV1 {
    let extracted = extract_payload_output(&request.payload);
    if extracted.text.is_empty() {
        if extracted.truncated {
            return HookReviewResponseV1::deny("output_too_large", "HOL Guard blocked this output because it could not be safely excerpted within local limits.");
        }
        if has_output_key(&request.payload) {
            return allow_inline_output("output_empty_allow", &extracted.text);
        }
        return HookReviewResponseV1::deny(
            "no_output_to_review",
            "HOL Guard could not complete local hook review safely.",
        );
    }
    let local_content = inline_local_content(&request.payload);
    if extracted.truncated {
        let excerpt: String = extracted
            .text
            .chars()
            .take(REVIEWED_EXCERPT_CHARS)
            .collect();
        let scan = scan_text(
            &excerpt,
            local_content,
            true,
            MAX_SCAN_BYTES,
            deadline(request),
        );
        if scan.budget_exhausted || !scan.matches.is_empty() {
            return HookReviewResponseV1::deny("output_too_large", "HOL Guard blocked this output because it could not be fully scanned within local limits.");
        }
        return HookReviewResponseV1::reviewed_excerpt("output_too_large", "HOL Guard returned a reviewed excerpt because the output was too large to scan in full within local limits.", excerpt);
    }
    let scan = scan_text(
        &extracted.text,
        local_content,
        true,
        MAX_SCAN_BYTES,
        deadline(request),
    );
    if scan.budget_exhausted {
        return HookReviewResponseV1::deny(
            "scanner_budget_exhausted",
            "HOL Guard could not complete local hook review safely.",
        );
    }
    if !scan.matches.is_empty() {
        return HookReviewResponseV1::deny(
            "output_secret_match",
            "HOL Guard blocked this output because it contains sensitive content.",
        );
    }
    allow_inline_output("output_scan_allow", &extracted.text)
}

pub fn review_post_tool(request: &NativeHookRequestV1) -> HookReviewResponseV1 {
    if request.protocol_version != NATIVE_PROTOCOL_VERSION {
        return HookReviewResponseV1::deny(
            "protocol_version_mismatch",
            "HOL Guard could not complete local hook review safely.",
        );
    }
    if request.event_name != "PostToolUse" {
        return HookReviewResponseV1::deny(
            "not_post_tool",
            "HOL Guard could not complete local hook review safely.",
        );
    }
    // OMP directory reads are names-only and intentionally have no source-file
    // proof. Recheck the host-resolved target here so a directory swapped after
    // PreToolUse cannot make a sensitive root's listing model-visible.
    if request.harness == "omp"
        && source_ref(&request.payload).is_none()
        && sensitive_envelope_target(request)
    {
        return HookReviewResponseV1::deny(
            "sensitive_path",
            "HOL Guard blocked this output because the resolved tool target is sensitive.",
        );
    }
    let source = source_ref(&request.payload);
    let response = if let Some(source) = source.as_ref() {
        review_source(request, source)
    } else {
        review_inline(request)
    };
    if request.observe_mode {
        let output_hash = canonical_observed_output_sha256(&request.payload);
        if let Some(output_hash) = output_hash {
            response.observed(Some(output_hash))
        } else {
            // Truncated inline output cannot prove the original bytes. Keep
            // the fail-closed decision instead of allowing it without proof.
            response
        }
    } else {
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request(payload: Value) -> NativeHookRequestV1 {
        NativeHookRequestV1 {
            protocol_version: 1,
            request_id: Some("test".into()),
            harness: "claude-code".into(),
            event_name: "PostToolUse".into(),
            payload,
            cwd: None,
            home_dir: "/tmp".into(),
            guard_home: "/tmp/guard".into(),
            source_ref_external_allowed: false,
            observe_mode: false,
            deadline_budget_ms: Some(750),
        }
    }

    fn github_like_token() -> String {
        let prefix = ["gh", "p_"].concat();
        format!("{prefix}{}", "b".repeat(30))
    }

    fn aws_like_access_key() -> String {
        let prefix = ["AK", "IA"].concat();
        format!("{prefix}{}", "A".repeat(16))
    }

    #[test]
    fn clean_inline_output_is_allowed() {
        let response = review_post_tool(&request(
            json!({"tool_response": [{"type": "text", "text": "hello"}]}),
        ));
        assert_eq!(response.decision, "allow");
        assert_eq!(response.reason_code, "output_scan_allow");
        assert_eq!(response.reviewed_output_sha256, Some(sha256_text("hello")));
    }

    #[test]
    fn structured_edit_source_is_scanned_instead_of_treated_as_empty() {
        let payload = json!({
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/ordinary.ts"},
            "tool_response": {
                "originalFile": "export const value = 1;",
                "oldString": "value = 1",
                "newString": "value = 2",
                "structuredPatch": [{"lines": ["-value = 1", "+value = 2"]}]
            }
        });
        let extracted = extract_payload_output(&payload);
        assert!(extracted.text.contains("export const value = 1;"));
        assert!(extracted.text.contains("+value = 2"));
        let response = review_post_tool(&request(payload));
        assert_eq!(response.decision, "allow");
        assert_eq!(response.reason_code, "output_scan_allow");
        assert_eq!(
            response.reviewed_output_sha256,
            Some(sha256_text(&extracted.text))
        );
        for key in [
            "originalFile",
            "original_file",
            "oldString",
            "old_string",
            "newString",
            "new_string",
        ] {
            let mut output = serde_json::Map::new();
            output.insert(key.into(), json!(github_like_token()));
            let response = review_post_tool(&request(json!({"tool_response": output})));
            assert_eq!(response.decision, "deny", "{key}");
            assert_eq!(response.reason_code, "output_secret_match");
        }
        let response = review_post_tool(&request(json!({
            "tool_response": {"structuredPatch": [{"lines": [github_like_token()]}]}
        })));
        assert_eq!(response.decision, "deny");
    }

    #[test]
    fn empty_inline_output_is_allowed_with_digest() {
        let response = review_post_tool(&request(json!({"tool_response": ""})));
        assert_eq!(response.decision, "allow");
        assert_eq!(response.reason_code, "output_empty_allow");
        assert_eq!(response.reviewed_output_sha256, Some(sha256_text("")));
    }

    #[test]
    fn secret_inline_output_is_blocked() {
        let response = review_post_tool(&request(json!({"tool_response": github_like_token()})));
        assert_eq!(response.decision, "deny");
        assert_eq!(response.reason_code, "output_secret_match");
    }

    #[test]
    fn observe_inline_secret_preserves_original_with_digest() {
        let output = github_like_token();
        let expected_hash = sha256_text(&output);
        let mut observe_request = request(json!({"tool_response": output}));
        observe_request.observe_mode = true;

        let response = review_post_tool(&observe_request);

        assert_eq!(response.decision, "allow");
        assert_eq!(response.reason_code, "observe_output_secret_match");
        assert_eq!(response.model_output_action, "allow_original");
        assert_eq!(response.reviewed_output_sha256, Some(expected_hash));
        assert_eq!(response.observed_policy_action.as_deref(), Some("block"));
        assert!(response.observe_mode);
    }

    #[test]
    fn observe_truncated_inline_secret_remains_blocked_without_digest() {
        let output = format!("{}{}", github_like_token(), "x".repeat(MAX_OUTPUT_CHARS));
        let mut observe_request = request(json!({"tool_response": output}));
        observe_request.observe_mode = true;

        let response = review_post_tool(&observe_request);

        assert_eq!(response.decision, "deny");
        assert_eq!(response.reason_code, "output_too_large");
        assert_eq!(response.reviewed_output_sha256, None);
        assert!(!response.observe_mode);
    }

    #[test]
    fn stderr_is_scanned_even_when_stdout_exists() {
        let response = review_post_tool(&request(
            json!({"stdout": "ok", "stderr": aws_like_access_key()}),
        ));
        assert_eq!(response.reason_code, "output_secret_match");
    }

    #[test]
    fn mixed_documentation_and_source_paths_unsuppress_credential() {
        let response = review_post_tool(&request(json!({
            "tool_input": {"file_paths": ["docs/security-review.md", "src/config.py"]},
            "tool_response": [{"type": "text", "text": "credential = 'fixture-only'\n"}]
        })));
        assert_eq!(response.decision, "deny");
        assert_eq!(response.reason_code, "output_secret_match");
    }

    #[test]
    fn documentation_only_multi_paths_keep_fixture_suppression() {
        let response = review_post_tool(&request(json!({
            "tool_input": {"file_paths": ["docs/security-review.md", "tests/fixture.txt"]},
            "tool_response": [{"type": "text", "text": "credential = 'fixture-only'\n"}]
        })));
        assert_eq!(response.decision, "allow");
        assert_eq!(response.reason_code, "output_scan_allow");
    }
}
