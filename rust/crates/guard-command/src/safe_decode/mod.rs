//! Port of `codex_plugin_scanner.guard.runtime.safe_decode` (`safe-decode.v2`).
//!
//! Decodes layered encodings (base64, hex, URL, ...) without executing anything and
//! enforces input-size, decoded-size, recursion and wall-clock limits.
//!
//! Python strings may hold lone surrogates (produced by `unicode_escape`); Rust strings
//! cannot, so they are carried internally as private-use sentinels (see
//! [`surrogate_char`]) and projected back to `U+FFFD` for any externally visible text.
//! The decode cache is intentionally omitted; behaviour never depended on it.

use std::borrow::Cow;
use std::sync::LazyLock;
use std::time::Instant;

use fancy_regex::{Regex, RegexBuilder};
use sha2::{Digest, Sha256};

use crate::detectors::{DecodeLayerView, DecodeResultView, SafeDecodeApi};

mod codecs;
mod inflate;

/// Bounded gzip read for other guard-command modules. Gzip failures stay inside this module.
pub(crate) fn read_gzip(raw: &[u8], limit: usize) -> Result<Vec<u8>, &'static str> {
    inflate::gzip_read(raw, limit).map_err(|_| "content_input_invalid")
}
#[cfg(test)]
mod tests;

pub const MAX_INPUT_BYTES: usize = 256 * 1024;
pub const MAX_DECODED_BYTES: usize = 512 * 1024;
pub const MAX_RECURSION_DEPTH: usize = 3;
pub const MAX_DECODE_TIME_MS: f64 = 50.0;
pub const SAFE_DECODE_DETECTOR_VERSION: &str = "safe-decode.v2";

/// First sentinel code point (plane-16 private use, U+10E000..U+10E7FF) standing in for
/// the lone surrogate U+D800. Input that itself contains these code points would be
/// misread as surrogates, which is a documented, vanishingly unlikely divergence.
const SURROGATE_SENTINEL_BASE: u32 = 0x10_e000;

/// Maps a lone surrogate (U+D800..=U+DFFF) to its internal sentinel character.
pub(crate) fn surrogate_char(surrogate: u32) -> char {
    char::from_u32(SURROGATE_SENTINEL_BASE + (surrogate - 0xd800)).unwrap_or('\u{fffd}')
}

fn is_sentinel(ch: char) -> bool {
    (SURROGATE_SENTINEL_BASE..SURROGATE_SENTINEL_BASE + 0x800).contains(&(ch as u32))
}

/// Python `text.encode("utf-8", errors="replace")` rendered as a lossless-length string.
fn py_utf8_replace_len(text: &str) -> usize {
    text.chars()
        .map(|c| if is_sentinel(c) { 1 } else { c.len_utf8() })
        .sum()
}

fn externalize(text: &str) -> String {
    text.chars()
        .map(|c| if is_sentinel(c) { '\u{fffd}' } else { c })
        .collect()
}

/// Python exceptions that escape `decode_layers`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// `EOFError` from a truncated gzip stream.
    Eof,
    /// A pattern ran past its backtrack budget. Reported as a detector error so a
    /// crafted input cannot turn a stalled match into a silent "no candidate".
    RegexBudget,
}

/// Backtracking steps one pattern may take per match attempt.
const REGEX_BACKTRACK_LIMIT: usize = 1_000_000;

/// `DecodedLayer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedLayer {
    pub encoding: &'static str,
    pub input_length: usize,
    pub output_length: usize,
    pub content_hash: String,
    pub preview_redacted: String,
    pub depth: usize,
}

/// `DecodeResult`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecodeResult {
    pub layers: Vec<DecodedLayer>,
    pub final_text: String,
    pub truncated: bool,
    pub timed_out: bool,
    pub depth_exceeded: bool,
    pub size_exceeded: bool,
    pub eval_signals: Vec<String>,
    pub exec_signals: Vec<String>,
    pub marshal_signals: Vec<String>,
}

/// Keyword limits of `decode_layers`.
#[derive(Debug, Clone, Copy)]
pub struct DecodeLimits {
    pub max_input_bytes: usize,
    pub max_decoded_bytes: usize,
    pub max_depth: usize,
    pub max_time_ms: f64,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        DecodeLimits {
            max_input_bytes: MAX_INPUT_BYTES,
            max_decoded_bytes: MAX_DECODED_BYTES,
            max_depth: MAX_RECURSION_DEPTH,
            max_time_ms: MAX_DECODE_TIME_MS,
        }
    }
}

// Python `\w` is `[\p{L}\p{N}_]`, `\s` additionally covers U+001C..U+001F, and `\b`
// is the boundary between `\w` and `\W`.
const WORD: &str = r"[\p{L}\p{N}_]";
const SP: &str = r"[\s\x1c-\x1f]";
const NSP: &str = r"[^\s\x1c-\x1f]";

fn build(pattern: &str) -> Regex {
    let expanded = pattern
        .replace(
            "<WB>",
            &format!("(?:(?<={WORD})(?!{WORD})|(?<!{WORD})(?={WORD}))"),
        )
        .replace("<W>", WORD)
        .replace("<SP>", SP)
        .replace("<NSP>", NSP);
    RegexBuilder::new(&expanded)
        .backtrack_limit(REGEX_BACKTRACK_LIMIT)
        .build()
        .expect("safe_decode regex is valid")
}

static B64_CANDIDATE: LazyLock<Regex> = LazyLock::new(|| {
    build(
        r"(?=[A-Za-z0-9+/]*(?:[+/]|(?=[A-Za-z0-9+/]*[A-Z])[A-Za-z0-9+/]*[a-z]))(?:(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)|(?:[A-Za-z0-9+/]{4}){4,})",
    )
});
static B64_URLSAFE_CANDIDATE: LazyLock<Regex> = LazyLock::new(|| {
    build(
        r"(?=[A-Za-z0-9\-_]*[\-_])(?:[A-Za-z0-9\-_]{4}){5,}(?:[A-Za-z0-9\-_]{2}==|[A-Za-z0-9\-_]{3}=)?",
    )
});
static B32_CANDIDATE: LazyLock<Regex> =
    LazyLock::new(|| build(r"(?=[A-Za-z2-7]*(?:[A-Z]|[2-7]))[A-Za-z2-7]{16,}={0,6}"));
static HEX_CANDIDATE: LazyLock<Regex> = LazyLock::new(|| build(r"(?:0x)?[0-9a-fA-F]{16,}"));
static URL_PERCENT: LazyLock<Regex> = LazyLock::new(|| build(r"(?:%[0-9a-fA-F]{2}){3,}"));
static UNICODE_ESCAPE: LazyLock<Regex> = LazyLock::new(|| build(r"(?:\\u[0-9a-fA-F]{4}){3,}"));
static POWERSHELL_ENCODED: LazyLock<Regex> =
    LazyLock::new(|| build(r"(?i)-(?:En(?:c(?:oded(?:Command)?)?)?)<SP>+([A-Za-z0-9+/=]{8,})"));
static PYTHON_C: LazyLock<Regex> = LazyLock::new(|| {
    build(r#"(?is)<WB>python(?:3)?<WB>[^\r\n;&|]*<SP>-c<SP>*(['"])((?:\\.|(?!\1).)*)\1"#)
});
static NODE_E: LazyLock<Regex> =
    LazyLock::new(|| build(r#"(?is)<WB>node<WB>[^\r\n;&|]*<SP>-e<SP>*(['"])((?:\\.|(?!\1).)*)\1"#));
static HEREDOC: LazyLock<Regex> =
    LazyLock::new(|| build(r"(?s)<<-?<SP>*'?(<W>+)'?<SP>*\n(.*?)\n\1<WB>"));
static JS_ATOB: LazyLock<Regex> =
    LazyLock::new(|| build(r#"(?i)atob\(<SP>*['"]([A-Za-z0-9+/=]{4,})['"]"#));
static JS_EVAL: LazyLock<Regex> = LazyLock::new(|| build(r"(?i)<WB>eval<SP>*\("));
static PY_EXEC: LazyLock<Regex> = LazyLock::new(|| build(r"(?i)<WB>exec<SP>*\("));
static PY_MARSHAL: LazyLock<Regex> =
    LazyLock::new(|| build(r"(?i)<WB>marshal<SP>*\.<SP>*loads<SP>*\("));
static REDACT_TOKENS: LazyLock<Regex> = LazyLock::new(|| {
    build(r"(?i)<WB>(?:password|token|secret|key|aws_|npm_token|node_auth)<W>*<SP>*=<SP>*<NSP>+")
});

/// Capture groups (index 0 is the whole match) of the leftmost match, if any.
fn first_match(re: &Regex, text: &str) -> Result<Option<Vec<String>>, DecodeError> {
    let Some(caps) = re.captures(text).map_err(|_| DecodeError::RegexBudget)? else {
        return Ok(None);
    };
    Ok(Some(
        (0..caps.len())
            .map(|i| {
                caps.get(i)
                    .map_or_else(String::new, |m| m.as_str().to_string())
            })
            .collect(),
    ))
}

fn signals(re: &Regex, text: &str) -> Result<Vec<String>, DecodeError> {
    re.find_iter(text)
        .map(|m| {
            m.map(|m| m.as_str().chars().take(40).collect())
                .map_err(|_| DecodeError::RegexBudget)
        })
        .collect()
}

fn unescape_command_argument(value: &str) -> String {
    value
        .replace("\\\\", "\\")
        .replace("\\\"", "\"")
        .replace("\\'", "'")
}

fn find_encoded_candidate(text: &str) -> Result<Option<(&'static str, String)>, DecodeError> {
    if let Some(c) = first_match(&POWERSHELL_ENCODED, text)? {
        return Ok(Some(("powershell-encoded", c[1].clone())));
    }
    if let Some(c) = first_match(&PYTHON_C, text)? {
        return Ok(Some(("python-c", c[2].clone())));
    }
    if let Some(c) = first_match(&NODE_E, text)? {
        return Ok(Some(("node-e", c[2].clone())));
    }
    if let Some(c) = first_match(&JS_ATOB, text)? {
        return Ok(Some(("js-atob", c[1].clone())));
    }
    if let Some(c) = first_match(&HEREDOC, text)? {
        return Ok(Some(("shell-heredoc", c[2].clone())));
    }
    if first_match(&URL_PERCENT, text)?.is_some() {
        return Ok(Some(("url-percent", text.to_string())));
    }
    if first_match(&UNICODE_ESCAPE, text)?.is_some() {
        return Ok(Some(("unicode-escape", text.to_string())));
    }
    let simple: [(&Regex, &'static str); 4] = [
        (&B64_URLSAFE_CANDIDATE, "base64-urlsafe"),
        (&B64_CANDIDATE, "base64"),
        (&B32_CANDIDATE, "base32"),
        (&HEX_CANDIDATE, "hex"),
    ];
    for (re, name) in simple {
        if let Some(c) = first_match(re, text)? {
            return Ok(Some((name, c[0].clone())));
        }
    }
    Ok(None)
}

fn hash_preview(text: &str) -> (String, String) {
    let mut bytes: Vec<u8> = Vec::with_capacity(text.len());
    for ch in text.chars() {
        if is_sentinel(ch) {
            bytes.push(b'?');
        } else {
            let mut buf = [0u8; 4];
            bytes.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
    }
    let digest = hex::encode(Sha256::digest(&bytes));
    let preview_raw: String = text.chars().take(120).collect();
    let preview = REDACT_TOKENS
        .replace_all(&preview_raw, "[REDACTED]")
        .into_owned();
    (digest[..16].to_string(), externalize(&preview))
}

fn decode_candidate(encoding: &str, data: &str) -> Result<Option<String>, DecodeError> {
    Ok(match encoding {
        "base64" | "js-atob" => codecs::try_base64(data)?,
        "base64-urlsafe" => codecs::try_base64_urlsafe(data)?,
        "base32" => codecs::try_base32(data),
        "hex" => codecs::try_hex(data),
        "url-percent" => Some(codecs::try_url_percent(data)),
        "unicode-escape" => Some(codecs::try_unicode_escape(data)),
        "powershell-encoded" => match codecs::try_base64_utf16le(data) {
            Some(text) if !text.is_empty() => Some(text),
            _ => codecs::try_base64(data)?,
        },
        "python-c" | "node-e" => Some(unescape_command_argument(data)),
        "shell-heredoc" => Some(data.to_string()),
        _ => None,
    })
}

/// `decode_layers(content)` with the default limits.
pub fn decode_layers(content: &str) -> Result<DecodeResult, DecodeError> {
    decode_layers_with(content, &DecodeLimits::default())
}

/// `decode_layers(content, **limits)`.
pub fn decode_layers_with(
    content: &str,
    limits: &DecodeLimits,
) -> Result<DecodeResult, DecodeError> {
    let mut result = DecodeResult::default();
    // Python compiles its patterns at import time; do the equivalent before the clock starts.
    warm_regexes();
    let start = Instant::now();
    if py_utf8_replace_len(content) > limits.max_input_bytes {
        result.size_exceeded = true;
        result.final_text = content.to_string();
        return Ok(result);
    }
    let mut current = content.to_string();
    record_signals(&mut result, &current)?;
    let mut depth_limited = false;
    for depth in 0..limits.max_depth {
        if start.elapsed().as_secs_f64() * 1000.0 > limits.max_time_ms {
            result.timed_out = true;
            break;
        }
        let Some((encoding, candidate)) = find_encoded_candidate(&current)? else {
            break;
        };
        let decoded = decode_candidate(encoding, &candidate)?;
        let Some(mut decoded) = decoded else {
            break;
        };
        if decoded == current {
            break;
        }
        if py_utf8_replace_len(&decoded) > limits.max_decoded_bytes {
            result.size_exceeded = true;
            result.truncated = true;
            decoded = decoded.chars().take(limits.max_decoded_bytes / 4).collect();
        }
        let (content_hash, preview_redacted) = hash_preview(&decoded);
        result.layers.push(DecodedLayer {
            encoding,
            input_length: candidate.chars().count(),
            output_length: decoded.chars().count(),
            content_hash,
            preview_redacted,
            depth,
        });
        current = decoded;
        record_signals(&mut result, &current)?;
        if result.size_exceeded {
            break;
        }
        if depth + 1 == limits.max_depth {
            depth_limited = true;
        }
    }
    if depth_limited && !result.timed_out {
        result.depth_exceeded = true;
    }
    result.final_text = externalize(&current);
    Ok(result)
}

fn warm_regexes() {
    for re in [
        &*B64_CANDIDATE,
        &*B64_URLSAFE_CANDIDATE,
        &*B32_CANDIDATE,
        &*HEX_CANDIDATE,
        &*URL_PERCENT,
        &*UNICODE_ESCAPE,
        &*POWERSHELL_ENCODED,
        &*PYTHON_C,
        &*NODE_E,
        &*HEREDOC,
        &*JS_ATOB,
        &*JS_EVAL,
        &*PY_EXEC,
        &*PY_MARSHAL,
        &*REDACT_TOKENS,
    ] {
        let _ = re.as_str();
    }
}

fn record_signals(result: &mut DecodeResult, text: &str) -> Result<(), DecodeError> {
    result.eval_signals.extend(signals(&JS_EVAL, text)?);
    result.exec_signals.extend(signals(&PY_EXEC, text)?);
    result.marshal_signals.extend(signals(&PY_MARSHAL, text)?);
    Ok(())
}

/// Zero-sized native implementation of the detector seam.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeSafeDecode;

impl SafeDecodeApi for NativeSafeDecode {
    fn safe_decode_detector_version(&self) -> &str {
        SAFE_DECODE_DETECTOR_VERSION
    }

    fn decode_layers<'a>(&self, content: &'a str) -> Result<DecodeResultView<'a>, String> {
        let result = decode_layers(content).map_err(|error| match error {
            DecodeError::Eof => "EOFError".to_owned(),
            DecodeError::RegexBudget => "RegexBudgetExceeded".to_owned(),
        })?;
        let final_text = if result.final_text == content {
            Cow::Borrowed(content)
        } else {
            Cow::Owned(result.final_text)
        };
        Ok(DecodeResultView {
            layers: result
                .layers
                .iter()
                .map(|layer| DecodeLayerView {
                    encoding: layer.encoding,
                })
                .collect(),
            final_text,
            eval_signals: result.eval_signals,
            exec_signals: result.exec_signals,
            marshal_signals: result.marshal_signals,
        })
    }
}
