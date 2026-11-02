//! `approval_copy` runner-authority kind: routes a blocked action's review copy
//! to the local approval center. Ported from the CLI's
//! `_native_approval_center_context`, `_localize_decision_v2_review_copy` and
//! `_approval_center_routed_message` with the cloud-inbox, legacy-sentence and
//! review-evidence strippers they apply.
//!
//! Display only: the caller picks the review link and writes the returned
//! strings back, so a refused call leaves the original copy in place. Python
//! ships each decision as its string `harness_message`, `action` and
//! `retry_instruction`, with `null` for one that is not a mapping, so returned
//! entries line up with the caller's list.

use serde_json::{json, Map, Value};

use crate::cloud_request_text::optional_string;
use crate::daemon_lifecycle_text::{py_isspace, py_strip};
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const LEGACY_SENTENCE: &str = "open hol guard to approve or keep this blocked:";
const LEGACY_RETRY: &str = "after you choose, retry the same ";
const LEGACY_END: &str = " action.";
const RETRY_SENTENCE: &str = "Review this request in HOL Guard, then retry.";
const REVIEW_EVIDENCE_TAILS: [&str; 3] = [
    "Review evidence: .",
    "Review evidence:.",
    "Review evidence:",
];
const PACKAGE_MANAGERS: [&str; 19] = [
    "npm", "npx", "pnpm", "yarn", "bun", "pip", "pip3", "pipenv", "pipx", "poetry", "uv", "uvx",
    "cargo", "go", "composer", "bundle", "mvn", "gradle", "brew",
];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let text = |key: &str| args.get(key).and_then(Value::as_str);
    let (Some(harness), Some(review_url)) = (text("harness"), text("review_url")) else {
        return Err(ERR_INVALID);
    };
    let decisions = match args.get("decisions") {
        Some(Value::Array(items)) => items.as_slice(),
        None | Some(Value::Null) => &[],
        Some(_) => return Err(ERR_INVALID),
    };
    let context = review_context(harness, review_url);
    let decisions: Vec<Value> = decisions
        .iter()
        .map(|decision| {
            decision.as_object().map_or(Value::Null, |decision| {
                localize_decision(decision, &context)
            })
        })
        .collect();
    let user_copy_message = optional_string(args.get("user_copy_message"))
        .map(|message| routed_message(message, &context));
    Ok(json!({
        "review_context": context,
        "decisions": decisions,
        "user_copy_message": user_copy_message,
    }))
}

fn harness_label(harness: &str) -> &'static str {
    if PACKAGE_MANAGERS.contains(&harness) {
        return "package install";
    }
    match harness {
        "claude-code" => "Claude Code",
        "codex" => "Codex",
        "copilot" => "Copilot",
        "cursor" => "Cursor",
        "devin" => "Devin",
        "muse" => "Muse",
        "guard-cli" => "package install",
        "opencode" => "OpenCode",
        "kimi" => "Kimi",
        "grok" => "Grok",
        "pi" => "Pi",
        "omp" => "Oh My Pi",
        _ => "the harness",
    }
}

fn review_context(harness: &str, review_url: &str) -> String {
    format!(
        "Open HOL Guard to approve or keep this blocked: {review_url}. \
         After you choose, retry the same {} action.",
        harness_label(harness)
    )
}

/// The rewritten fields of one decision; untouched fields are omitted.
fn localize_decision(decision: &Map<String, Value>, context: &str) -> Value {
    let mut patch = Map::new();
    if let Some(message) = optional_string(decision.get("harness_message")) {
        patch.insert(
            "harness_message".into(),
            json!(routed_message(message, context)),
        );
    }
    let action = optional_string(decision.get("action"));
    if matches!(action, Some("ask" | "block")) {
        let retry = optional_string(decision.get("retry_instruction"));
        let instruction = match retry {
            Some(retry) if retry.contains("hol-guard connect") => routed_message(retry, context),
            _ => context.to_owned(),
        };
        patch.insert("retry_instruction".into(), json!(instruction));
    }
    Value::Object(patch)
}

fn routed_message(message: &str, context: &str) -> String {
    let normalized = strip_cloud_inbox_urls(message);
    let normalized = py_strip(&normalized.replace(RETRY_SENTENCE, "")).to_owned();
    let normalized = strip_legacy_sentence(&normalized);
    let normalized = py_split(&normalized).join(" ");
    let normalized = strip_review_evidence_tail(&normalized);
    if normalized.is_empty() {
        return context.to_owned();
    }
    format!("{} {context}", ensure_terminal_punctuation(&normalized))
}

/// `str.split()` with no separator.
fn py_split(text: &str) -> Vec<&str> {
    text.split(py_isspace)
        .filter(|word| !word.is_empty())
        .collect()
}

/// `str.lower()` as code points, so indexes found in it are applied to the
/// original text the way Python slices it.
fn py_lower(chars: &[char]) -> Vec<char> {
    chars
        .iter()
        .flat_map(|character| character.to_lowercase())
        .collect()
}

fn find_from(haystack: &[char], needle: &str, start: usize) -> Option<usize> {
    let needle: Vec<char> = needle.chars().collect();
    (start..=haystack.len().checked_sub(needle.len())?)
        .find(|&at| haystack[at..at + needle.len()] == needle[..])
}

/// `text[start:end]` by code points, clamped like Python slicing.
fn char_slice(chars: &[char], start: usize, end: usize) -> String {
    let end = end.min(chars.len());
    chars[start.min(end)..end].iter().collect()
}

fn strip_legacy_sentence(message: &str) -> String {
    let chars: Vec<char> = message.chars().collect();
    let lower = py_lower(&chars);
    let Some(start) = find_from(&lower, LEGACY_SENTENCE, 0) else {
        return py_strip(message).to_owned();
    };
    let head = char_slice(&chars, 0, start);
    let end = find_from(&lower, LEGACY_RETRY, start)
        .and_then(|retry| find_from(&lower, LEGACY_END, retry));
    let Some(end) = end else {
        return py_strip(&head).to_owned();
    };
    let tail = char_slice(&chars, end + LEGACY_END.len(), chars.len());
    py_strip(&format!("{head} {tail}")).to_owned()
}

fn strip_review_evidence_tail(message: &str) -> String {
    let chars: Vec<char> = py_strip(message).chars().collect();
    let lower = py_lower(&chars);
    for suffix in REVIEW_EVIDENCE_TAILS {
        let suffix_lower: Vec<char> = suffix.to_lowercase().chars().collect();
        if lower.ends_with(&suffix_lower) {
            let kept = chars.len().saturating_sub(suffix.chars().count());
            return char_slice(&chars, 0, kept)
                .trim_end_matches(py_isspace)
                .to_owned();
        }
    }
    chars.iter().collect()
}

fn ensure_terminal_punctuation(message: &str) -> String {
    let trimmed = py_strip(message);
    if trimmed.is_empty() || trimmed.ends_with(['.', '!', '?']) {
        return trimmed.to_owned();
    }
    format!("{trimmed}.")
}

fn strip_cloud_inbox_urls(message: &str) -> String {
    let kept: Vec<&str> = py_split(message)
        .into_iter()
        .filter(|token| {
            let candidate = token
                .trim_matches(|c: char| "([{<'\"".contains(c))
                .trim_end_matches(|c: char| ")]}>'\".,;:!?".contains(c));
            !is_cloud_inbox_url(candidate)
        })
        .collect();
    py_strip(&kept.join(" ")).to_owned()
}

/// `urlparse(value)` has an `http`/`https` scheme and the path
/// `/guard/inbox`, ignoring trailing slashes. A netloc Python rejects as an
/// invalid IPv6 literal is not an inbox link.
fn is_cloud_inbox_url(value: &str) -> bool {
    let value = value.trim_start_matches(|c: char| c <= ' ');
    let Some((scheme, rest)) = value.split_once(':') else {
        return false;
    };
    let scheme_ok = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c));
    if !scheme_ok || !["http", "https"].contains(&scheme.to_ascii_lowercase().as_str()) {
        return false;
    }
    let mut rest = rest;
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        let netloc = &after[..end];
        if netloc.contains('[') != netloc.contains(']') {
            return false;
        }
        rest = &after[end..];
    }
    let rest = rest.split('#').next().unwrap_or(rest);
    let mut url_path = rest.split('?').next().unwrap_or(rest);
    let params_at = match url_path.rfind('/') {
        Some(slash) => url_path[slash..].find(';').map(|at| slash + at),
        None => url_path.find(';'),
    };
    if let Some(at) = params_at {
        url_path = &url_path[..at];
    }
    url_path.trim_end_matches('/') == "/guard/inbox"
}

#[cfg(test)]
#[path = "approval_copy_tests.rs"]
mod tests;
