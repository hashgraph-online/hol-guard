//! A provider's answer mapped onto Guard's closed signal vocabulary.
//!
//! The manifest names, per capability, a pointer to the verdict and a table from the provider's
//! verdict strings onto `ok`, `caution`, `danger` and `unknown`. Optional pointers name reason codes
//! and the answer's lifetime. Everything else in the body is never read. The mapping only narrows:
//!
//! - a verdict value the table does not list, a missing verdict or a non-string one reads `unknown`,
//!   which carries no effect;
//! - a reason code the manifest does not declare, or one that is not lowercase snake case, is
//!   dropped, duplicates collapse, and at most `PROVIDER_SIGNAL_MAX_REASON_CODES` are kept in the
//!   order the provider sent them;
//! - a lifetime is clamped into the manifest's bounds, and a missing or non-integer one is the
//!   manifest's minimum.
//!
//! A body that is not strict JSON (duplicate keys, trailing bytes, oversize) is refused outright, so
//! the caller records the provider as unavailable instead of guessing.

use std::collections::BTreeMap;

use guard_contracts::{
    provider_reason_code_is_valid, ProviderVerdictV1, PROVIDER_REASON_CODE_MAX_BYTES,
    PROVIDER_SIGNAL_MAX_REASON_CODES,
};

use crate::parse::{parse_strict, read_pointer, read_string, read_strings};

/// The longest provider verdict string the table is consulted for.
pub const MAX_VERDICT_BYTES: usize = 64;

/// Where reason codes are read and which ones are kept.
#[derive(Debug, Clone, Copy)]
pub struct ReasonCodeMapping<'a> {
    pub pointer: &'a str,
    pub allow: &'a [String],
}

/// Where the lifetime is read, in seconds, and the bounds it is clamped to.
#[derive(Debug, Clone, Copy)]
pub struct TtlMapping<'a> {
    pub pointer: &'a str,
    pub min_seconds: u64,
    pub max_seconds: u64,
}

/// One capability's declared answer mapping.
#[derive(Debug, Clone, Copy)]
pub struct AnswerMapping<'a> {
    pub verdict_pointer: &'a str,
    pub verdict_map: &'a BTreeMap<String, ProviderVerdictV1>,
    pub reason_codes: Option<ReasonCodeMapping<'a>>,
    pub ttl: Option<TtlMapping<'a>>,
}

/// The mapped answer. Holds only closed values and declared codes, never provider text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedAnswer {
    pub verdict: ProviderVerdictV1,
    pub reason_codes: Vec<String>,
    pub ttl_seconds: Option<u64>,
}

/// Why an answer could not be mapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerError {
    /// The body is not strict JSON within the size cap.
    BodyInvalid,
}

impl AnswerError {
    pub fn code(self) -> &'static str {
        match self {
            Self::BodyInvalid => "provider_answer_invalid",
        }
    }
}

fn verdict(document: &serde_json::Value, mapping: &AnswerMapping<'_>) -> ProviderVerdictV1 {
    read_string(document, mapping.verdict_pointer, MAX_VERDICT_BYTES)
        .and_then(|value| mapping.verdict_map.get(value).copied())
        .unwrap_or(ProviderVerdictV1::Unknown)
}

fn reason_codes(
    document: &serde_json::Value,
    mapping: Option<ReasonCodeMapping<'_>>,
) -> Vec<String> {
    let Some(mapping) = mapping else {
        return Vec::new();
    };
    // The body is already size-capped, so the whole array is scanned: undeclared entries ahead of
    // a declared one never crowd it out.
    let Some(sent) = read_strings(
        document,
        mapping.pointer,
        usize::MAX,
        PROVIDER_REASON_CODE_MAX_BYTES,
    ) else {
        return Vec::new();
    };
    let mut kept: Vec<String> = Vec::new();
    for code in sent {
        if kept.len() == PROVIDER_SIGNAL_MAX_REASON_CODES {
            break;
        }
        if provider_reason_code_is_valid(code)
            && mapping.allow.iter().any(|allowed| allowed == code)
            && !kept.iter().any(|seen| seen == code)
        {
            kept.push(code.to_owned());
        }
    }
    kept
}

fn ttl_seconds(document: &serde_json::Value, mapping: Option<TtlMapping<'_>>) -> Option<u64> {
    let mapping = mapping?;
    let low = mapping.min_seconds.min(mapping.max_seconds);
    let Some(serde_json::Value::Number(sent)) = read_pointer(document, mapping.pointer) else {
        return Some(low);
    };
    if let Some(seconds) = sent.as_u64() {
        return Some(seconds.clamp(low, mapping.max_seconds));
    }
    // A positive integer too large for `u64` is still above the bound. Negative and fractional
    // values fall back to the minimum.
    let text = sent.to_string();
    let positive_integer = !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    Some(if positive_integer {
        mapping.max_seconds.max(low)
    } else {
        low
    })
}

/// Map a provider response body through `mapping`.
pub fn map_answer(body: &[u8], mapping: &AnswerMapping<'_>) -> Result<MappedAnswer, AnswerError> {
    let document = parse_strict(body).ok_or(AnswerError::BodyInvalid)?;
    Ok(MappedAnswer {
        verdict: verdict(&document, mapping),
        reason_codes: reason_codes(&document, mapping.reason_codes),
        ttl_seconds: ttl_seconds(&document, mapping.ttl),
    })
}

#[cfg(test)]
#[path = "answer_tests.rs"]
mod tests;
