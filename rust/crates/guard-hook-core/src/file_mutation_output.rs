//! What Claude Code's file-mutation results put in front of the model.
//!
//! PostToolUse output review catches content entering the model's context
//! for the first time. Claude Code's `Edit` and `Write` report their result
//! in `tool_response`, which also carries the whole pre-edit file as
//! `originalFile`. Current Claude Code returns one confirmation line to the
//! model for these tools, never that file, so scanning `originalFile` flags
//! secret-shaped text the edit did not touch and the model never sees.
//!
//! For these two tools the review scans the edit itself: the old and new
//! strings, a `Write`'s content and every `structuredPatch` line. The patch is
//! still scanned because its context lines are file content beside the edit,
//! which a host could render as a snippet. It is joined into one text, so a
//! hunk longer than the generic walk's 24-item cap is scanned in full instead
//! of becoming a "too large" excerpt.
//!
//! Only what is scanned narrows. An allow records the same whole-result
//! digest the generic path defines, `canonical_observed_output_sha256`, so
//! receipts and delivery checks keep one output identity. That function has
//! no digest for a result its walk cannot read in full, such as a patch hunk
//! over 24 lines, so such an allow carries none. The generic path never had
//! one there either: it answered with a reviewed excerpt. No second digest
//! is invented that nothing else could recompute.
//!
//! Every other harness, tool and response shape, and an edit whose own text
//! cannot be read in full, keeps the generic review.

use guard_contracts::{HookReviewResponseV1, NativeHookRequestV1};
use guard_rules::{MAX_OUTPUT_CHARS, MAX_SCAN_BYTES, OUTPUT_TEXT_KEYS, PAYLOAD_OUTPUT_KEYS};
use guard_scanner::scan_text;
use serde_json::Value;

use super::{
    canonical_observed_output_sha256, collect_output_text, deadline, inline_local_content,
};

const FILE_MUTATION_TOOLS: [&str; 2] = ["Edit", "Write"];
/// The pre-edit file, which the host never shows the model.
const UNSHOWN_KEYS: [&str; 2] = ["originalFile", "original_file"];
const PATCH_KEYS: [&str; 2] = ["structuredPatch", "structured_patch"];

/// The review of a Claude Code `Edit` or `Write` result, or `None` when the
/// request is anything else or its edit text cannot be read in full.
pub(crate) fn review_file_mutation(request: &NativeHookRequestV1) -> Option<HookReviewResponseV1> {
    let text = file_mutation_text(request)?;
    let scan = scan_text(
        &text,
        inline_local_content(&request.payload),
        true,
        MAX_SCAN_BYTES,
        deadline(request),
    );
    if scan.budget_exhausted {
        return Some(HookReviewResponseV1::deny(
            "scanner_budget_exhausted",
            "HOL Guard could not complete local hook review safely.",
        ));
    }
    if !scan.matches.is_empty() {
        return Some(HookReviewResponseV1::deny(
            "output_secret_match",
            "HOL Guard blocked this output because it contains sensitive content.",
        ));
    }
    let reason_code = if text.is_empty() {
        "output_empty_allow"
    } else {
        "output_scan_allow"
    };
    let mut response = HookReviewResponseV1::allow(reason_code);
    response.reviewed_output_sha256 = canonical_observed_output_sha256(&request.payload);
    Some(response)
}

/// The text a Claude Code `Edit` or `Write` result can show the model: every
/// output key but `originalFile`, with the patch joined into one text.
fn file_mutation_text(request: &NativeHookRequestV1) -> Option<String> {
    if request.harness != "claude-code" {
        return None;
    }
    let payload = request.payload.as_object()?;
    let tool = payload.get("tool_name").and_then(Value::as_str)?;
    if !FILE_MUTATION_TOOLS.contains(&tool) {
        return None;
    }
    let response = payload.get("tool_response")?.as_object()?;
    let mut parts: Vec<String> = Vec::new();
    let mut truncated = false;
    let mut collect = |value: &Value| {
        let extracted = collect_output_text(value);
        truncated |= extracted.truncated;
        if !extracted.text.is_empty() {
            parts.push(extracted.text);
        }
    };
    for key in PAYLOAD_OUTPUT_KEYS
        .iter()
        .filter(|key| **key != "tool_response")
    {
        if let Some(value) = payload.get(*key) {
            collect(value);
        }
    }
    for key in OUTPUT_TEXT_KEYS {
        let Some(value) = response.get(*key) else {
            continue;
        };
        if UNSHOWN_KEYS.contains(key) {
            continue;
        }
        if PATCH_KEYS.contains(key) {
            // A patch this function cannot read in full is an unfamiliar
            // result shape. Scanning what it can reach would keep the narrower
            // review for a response nobody has modelled, so the whole request
            // goes back to the generic one, which reads `originalFile` too.
            collect(&Value::String(patch_text(value)?));
            continue;
        }
        collect(value);
    }
    let text = parts.join("\n");
    if truncated || text.chars().count() > MAX_OUTPUT_CHARS {
        return None;
    }
    Some(text)
}

/// Every line of a `structuredPatch` as one text, or `None` for a shape that
/// is not a list of hunks whose `lines` are strings. Its caller turns that
/// `None` into the generic review of the whole result.
fn patch_text(value: &Value) -> Option<String> {
    let mut lines: Vec<&str> = Vec::new();
    for hunk in value.as_array()? {
        for line in hunk.get("lines")?.as_array()? {
            lines.push(line.as_str()?);
        }
    }
    Some(lines.join("\n"))
}
