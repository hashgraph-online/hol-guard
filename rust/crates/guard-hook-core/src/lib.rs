#![forbid(unsafe_code)]

use guard_contracts::{
    HookReviewResponseV1, HookSourceFileRefV1, NativeHookRequestV1, NATIVE_PROTOCOL_VERSION,
};
use guard_rules::{
    MAX_CONTENT_ITEMS, MAX_DEPTH, MAX_OBJECT_KEYS, MAX_OUTPUT_CHARS, MAX_SCAN_BYTES,
    OUTPUT_TEXT_KEYS, PAYLOAD_OUTPUT_KEYS, REVIEWED_EXCERPT_CHARS,
};
use guard_scanner::scan_text;
use guard_secure_fs::{classify_source_path, read_bounded, sensitive_path_family};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;
use std::time::{Duration, Instant};

mod target_paths;

use target_paths::{envelope_target, envelope_targets};

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

fn sha256_text(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
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

fn local_samples_should_be_unsuppressed(path: &str, cwd: Option<&Path>) -> bool {
    let raw = path.trim();
    if raw.is_empty() {
        return true;
    }
    let slash_normalized = raw.replace('\\', "/");
    let bytes = slash_normalized.as_bytes();
    let has_windows_drive = bytes.len() >= 3
        && bytes[1] == b':'
        && bytes[0].is_ascii_alphabetic()
        && bytes[2] == b'/';
    let is_absolute = slash_normalized.starts_with('/') || has_windows_drive;
    let context_path = if !is_absolute {
        slash_normalized
    } else if let Some(cwd) = cwd {
        if !has_windows_drive {
            match Path::new(raw).strip_prefix(cwd) {
                Ok(relative) if !relative.as_os_str().is_empty() => {
                    relative.to_string_lossy().replace('\\', "/")
                }
                _ => Path::new(raw)
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| slash_normalized.clone()),
            }
        } else {
            let cwd_normalized = cwd.to_string_lossy().replace('\\', "/");
            let path_lower = slash_normalized.to_ascii_lowercase();
            let cwd_lower = cwd_normalized.trim_end_matches('/').to_ascii_lowercase();
            let prefix = format!("{cwd_lower}/");
            if path_lower.starts_with(&prefix) {
                slash_normalized[prefix.len()..].to_owned()
            } else {
                slash_normalized
                    .rsplit('/')
                    .next()
                    .unwrap_or(&slash_normalized)
                    .to_owned()
            }
        }
    } else {
        slash_normalized
            .rsplit('/')
            .next()
            .unwrap_or(&slash_normalized)
            .to_owned()
    };
    let normalized = context_path.to_ascii_lowercase();
    let parts: Vec<&str> = normalized.split('/').filter(|part| !part.is_empty()).collect();
    if parts.iter().any(|part| *part == "..") {
        return true;
    }
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
    let allow_external =
        matches!(request.harness.as_str(), "pi" | "omp") && request.source_ref_external_allowed;
    let candidate_decision = classify_source_path(candidate, cwd, Some(home), allow_external);
    if !candidate_decision.allowed {
        return inconclusive_source();
    }
    let target_decision = classify_source_path(&target, cwd, Some(home), allow_external);
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
    if !output_equivalent(text, &source.output_sha256, source.output_chars) {
        return inconclusive_source();
    }
    let scan = scan_text(
        text,
        local_samples_should_be_unsuppressed(&source.path, Some(cwd)),
        true,
        MAX_SCAN_BYTES,
        deadline(request),
    );
    if scan.budget_exhausted {
        return inconclusive_source();
    }
    if !scan.matches.is_empty() {
        return HookReviewResponseV1::deny(
            "source_secret_match",
            "HOL Guard blocked this output because it contains sensitive content.",
        );
    }
    let mut response = HookReviewResponseV1::allow("source_full_scan_allow");
    response.reviewed_output_sha256 = Some(source.output_sha256.clone());
    response
}

fn review_inline(request: &NativeHookRequestV1) -> HookReviewResponseV1 {
    let extracted = extract_payload_output(&request.payload);
    let has_output_key = request
        .payload
        .as_object()
        .is_some_and(|record: &Map<String, Value>| {
            PAYLOAD_OUTPUT_KEYS
                .iter()
                .any(|key| record.contains_key(*key))
        });
    if extracted.text.is_empty() {
        if extracted.truncated {
            return HookReviewResponseV1::deny("output_too_large", "HOL Guard blocked this output because it could not be safely excerpted within local limits.");
        }
        if has_output_key {
            return HookReviewResponseV1::allow("output_empty_allow");
        }
        return HookReviewResponseV1::deny(
            "no_output_to_review",
            "HOL Guard could not complete local hook review safely.",
        );
    }
    let targets = envelope_targets(&request.payload);
    let local_content = targets
        .iter()
        .any(|path| local_samples_should_be_unsuppressed(path, request.cwd.as_deref().map(Path::new)));
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
    HookReviewResponseV1::allow("output_scan_allow")
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
    let source = source_ref(&request.payload);
    let response = if let Some(source) = source.as_ref() {
        review_source(request, source)
    } else {
        review_inline(request)
    };
    if request.observe_mode {
        let output_hash = source.map(|value| value.output_sha256);
        response.observed(output_hash)
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
            policy_snapshot_digest: None,
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
    }

    #[test]
    fn secret_inline_output_is_blocked() {
        let response = review_post_tool(&request(json!({"tool_response": github_like_token()})));
        assert_eq!(response.decision, "deny");
        assert_eq!(response.reason_code, "output_secret_match");
    }

    #[test]
    fn stderr_is_scanned_even_when_stdout_exists() {
        let response = review_post_tool(&request(
            json!({"stdout": "ok", "stderr": aws_like_access_key()}),
        ));
        assert_eq!(response.reason_code, "output_secret_match");
    }

    #[test]
    fn external_absolute_docs_component_does_not_suppress_local_scanning() {
        assert!(local_samples_should_be_unsuppressed(
            "/tmp/docs/secret.py",
            Some(Path::new("/workspace")),
        ));
    }

    #[test]
    fn in_workspace_docs_component_suppresses_sample_retry() {
        assert!(!local_samples_should_be_unsuppressed(
            "/workspace/docs/example.py",
            Some(Path::new("/workspace")),
        ));
    }

    #[test]
    fn external_array_target_keeps_sample_assignment_protected() {
        let mut request = request(json!({
            "tool_input": {"file_paths": ["/tmp/docs/secret.py"]},
            "tool_response": "api_key = \"test-example-value-here\"",
        }));
        request.cwd = Some("/workspace".into());
        let response = review_post_tool(&request);
        assert_eq!(response.decision, "deny");
        assert_eq!(response.reason_code, "output_secret_match");
    }

}
