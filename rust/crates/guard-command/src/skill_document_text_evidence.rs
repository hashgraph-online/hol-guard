//! Rust port of the text half of `guard/skill_document_evidence.py`.
//!
//! The Python module derived bounded, non-content evidence from a primary
//! `SKILL.md`: how many lines and headings it has, whether it opens with
//! frontmatter, and whether its prose documents network egress. Everything
//! here is a pure function of the document text, so the parity vectors in
//! `tests/fixtures/skill-document-text-evidence-parity.v1.json` pin it
//! against the behaviour the scanner shipped.
//!
//! Path checks, the `O_NOFOLLOW` open and the bounded read stay in
//! `guard-runtime`, which owns filesystem access.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::LazyLock;

use fancy_regex::Regex;

use crate::codex_output_py::{py_lstrip, py_rstrip, py_splitlines, py_strip};
use crate::persistence_rules::{py_regex, re_search};

/// Evidence code for a literal HTTP client invocation next to a remote URL.
pub const EXPLICIT_HTTP_CLIENT: &str = "explicit_http_client";
/// Evidence code for prose that states the skill itself reaches a remote API.
pub const EXPLICIT_REMOTE_API_STATEMENT: &str = "explicit_remote_api_statement";

static HEADING: LazyLock<Regex> = LazyLock::new(|| py_regex(r"^#{1,6}\s+\S", ""));

static NEGATION: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"\b(?:avoid|do\s+not|does\s+not|don't|doesn't|must\s+not|never|no\s+need\s+to|without)\b",
        "i",
    )
});

static COUNTEREXAMPLE: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"\b(?:counterexample|non-example|not\s+an?\s+example)\b",
        "i",
    )
});

static EXAMPLE_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"^\s*(?:for\s+example|example)\s*:", "i"));

static INLINE_QUOTED: LazyLock<Regex> = LazyLock::new(|| py_regex(r#"(?:"[^"]*"|'[^']*')"#, ""));

static HTTP_CLIENT: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        concat!(
            r"(?:",
            r"\b(?:curl|wget)\b[^\n]*",
            r"|\b(?:fetch|axios(?:\.(?:get|post|put|patch|delete))?|requests\.(?:get|post|put|patch|delete)|",
            r"httpx\.(?:get|post|put|patch|delete)|urllib\.request\.urlopen)\s*\([^\n]*",
            r"|\bInvoke-WebRequest\b[^\n]*",
            r")",
        ),
        "i",
    )
});

static URL: LazyLock<Regex> = LazyLock::new(|| py_regex(r"https?://[^\s)'\x22<>`]+", "i"));

static ACTIVE_REMOTE_BEHAVIOR: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        concat!(
            r"\b(?:this\s+skill|the\s+skill|this\s+workflow|the\s+workflow|the\s+agent|",
            r"this\s+tool|the\s+tool|the\s+client|it)\s+",
            r"(?:calls?|contacts?|connects?\s+to|fetches?(?:\s+\w+){0,3}\s+from|queries|",
            r"requests?(?:\s+\w+){0,3}\s+from|sends?(?:\s+\w+){0,3}\s+to|",
            r"uploads?(?:\s+\w+){0,3}\s+to)\b",
            r"[^.!?\n]{0,160}\b(?:api|endpoint|remote\s+service|external\s+service|cloud\s+service)\b",
        ),
        "i",
    )
});

/// What a readable skill document says about itself, without keeping its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillDocumentTextEvidence {
    /// `len(text.splitlines())`.
    pub line_count: usize,
    /// Lines that open an ATX heading with a non-blank title.
    pub heading_count: usize,
    /// A `---` fence on the first line with a closing `---` below it.
    pub frontmatter_present: bool,
    /// The evidence code of the first documented network capability, if any.
    pub documented_network_capability: Option<&'static str>,
}

/// Read a skill document's text evidence.
pub fn analyze_skill_document_text(text: &str) -> SkillDocumentTextEvidence {
    let lines = py_splitlines(text);
    SkillDocumentTextEvidence {
        line_count: lines.len(),
        heading_count: lines.iter().filter(|line| is_heading(line)).count(),
        frontmatter_present: has_frontmatter(&lines),
        documented_network_capability: documented_network_capability(&lines),
    }
}

fn is_heading(line: &str) -> bool {
    re_search(&HEADING, line)
}

fn has_frontmatter(lines: &[String]) -> bool {
    lines.first().is_some_and(|first| py_strip(first) == "---")
        && lines[1..].iter().any(|line| py_strip(line) == "---")
}

/// The first line whose prose or shell text documents network egress.
///
/// A heading carries into the lines under it, a blockquote or an `Example:`
/// prefix is quotation rather than behaviour, and a negated sentence ("never
/// calls the API") is the opposite of a capability claim.
fn documented_network_capability(lines: &[String]) -> Option<&'static str> {
    let mut section_heading = "";
    for (index, line) in lines.iter().enumerate() {
        if is_heading(line) {
            section_heading = line;
            continue;
        }
        if py_lstrip(line).starts_with('>') {
            continue;
        }
        if re_search(&EXAMPLE_PREFIX, line) {
            continue;
        }
        let behavior_line = INLINE_QUOTED.replace_all(line, "");
        let mut context = if index > 0 && py_rstrip(&lines[index - 1]).ends_with(':') {
            format!("{} {line}", lines[index - 1])
        } else {
            line.clone()
        };
        if !section_heading.is_empty() {
            context = format!("{section_heading} {context}");
        }
        if is_negative_context(&context) {
            continue;
        }
        if let Some(start) = search_start(&HTTP_CLIENT, line) {
            if !is_inside_prose_quote(line, start) && line_has_remote_url(line) {
                return Some(EXPLICIT_HTTP_CLIENT);
            }
        }
        if re_search(&ACTIVE_REMOTE_BEHAVIOR, &behavior_line) {
            return Some(EXPLICIT_REMOTE_API_STATEMENT);
        }
    }
    None
}

/// The byte offset of the first match, treating an exhausted backtrack budget
/// as a match at the start so crafted input cannot hide behind a stalled search.
fn search_start(re: &Regex, text: &str) -> Option<usize> {
    match re.find(text) {
        Ok(found) => found.map(|m| m.start()),
        Err(_) => Some(0),
    }
}

fn is_negative_context(value: &str) -> bool {
    re_search(&NEGATION, value) || re_search(&COUNTEREXAMPLE, value)
}

fn line_has_remote_url(line: &str) -> bool {
    let mut from = 0usize;
    while from <= line.len() {
        match URL.find_from_pos(line, from) {
            Ok(Some(found)) => {
                if is_remote_url(found.as_str()) {
                    return true;
                }
                from = if found.end() > found.start() {
                    found.end()
                } else {
                    found.start() + 1
                };
            }
            Ok(None) => return false,
            // A stalled search is treated as a hit, matching `re_search`.
            Err(_) => return true,
        }
    }
    false
}

/// Whether the match at `offset` sits inside a prose quotation.
///
/// An apostrophe between two alphanumerics is part of a word, not a quote, so
/// the single-quote state only moves when one side of the mark is a boundary.
fn is_inside_prose_quote(value: &str, offset: usize) -> bool {
    let chars: Vec<char> = value.chars().collect();
    let prefix_len = value[..offset].chars().count();
    let mut double_open = false;
    let mut single_open = false;
    for index in 0..prefix_len {
        let character = chars[index];
        if index > 0 && chars[index - 1] == '\\' {
            continue;
        }
        if character == '"' && !single_open {
            double_open = !double_open;
            continue;
        }
        if character != '\'' || double_open {
            continue;
        }
        let previous_alnum = index > 0 && chars[index - 1].is_alphanumeric();
        let following_alnum = chars
            .get(index + 1)
            .is_some_and(|next| next.is_alphanumeric());
        if previous_alnum && following_alnum {
            continue;
        }
        if previous_alnum {
            if single_open {
                single_open = false;
            }
            continue;
        }
        if following_alnum {
            single_open = true;
        }
    }
    double_open || single_open
}

/// Whether a URL names a host other than this device.
fn is_remote_url(value: &str) -> bool {
    let Ok(Some(host)) = url_hostname(value) else {
        return false;
    };
    let normalized = host
        .trim_matches(|c| c == '[' || c == ']')
        .trim_end_matches('.');
    if normalized == "localhost" || normalized.ends_with(".localhost") {
        return false;
    }
    match IpAddr::from_str(normalized) {
        Ok(address) => !address.is_loopback() && !address.is_unspecified(),
        Err(_) => true,
    }
}

/// `urllib.parse._check_bracketed_host`: what may stand between `[` and `]`.
///
/// Brackets in an authority carry an IPv6 literal or an IPvFuture address and
/// nothing else, so `https://[api.example.com]/x` is a `ValueError` for the
/// reader this replaces rather than a URL naming `api.example.com`. Reading it
/// as a host would make a document remote that the scanner read as local.
fn bracketed_host_is_an_address(host: &str) -> Result<(), ()> {
    if let Some(version) = host.strip_prefix('v') {
        // `\Av[a-fA-F0-9]+\..+\Z`: a hex version, a dot, then a body.
        let (digits, body) = version.split_once('.').ok_or(())?;
        let hex = !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit());
        return (hex && !body.is_empty()).then_some(()).ok_or(());
    }
    match IpAddr::from_str(host) {
        Ok(IpAddr::V6(_)) => Ok(()),
        // An IPv4 address in brackets is rejected by name there, and anything
        // that is not an address at all never parsed to begin with.
        Ok(IpAddr::V4(_)) | Err(_) => Err(()),
    }
}

/// `urlsplit(value).hostname` for the `http(s)` URLs this module matches.
///
/// `Err` is the `ValueError` Python raises for an unbalanced IPv6 bracket;
/// `Ok(None)` is its empty hostname.
fn url_hostname(value: &str) -> Result<Option<String>, ()> {
    let cleaned: String = value
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let cleaned = cleaned.trim_matches(|c: char| c <= ' ');
    let rest = match cleaned.find(':') {
        Some(index) => &cleaned[index + 1..],
        None => cleaned,
    };
    let Some(after) = rest.strip_prefix("//") else {
        return Ok(None);
    };
    let netloc = match after.find(['/', '?', '#']) {
        Some(index) => &after[..index],
        None => after,
    };
    if netloc.contains('[') != netloc.contains(']') {
        return Err(());
    }
    if netloc.contains('[') && netloc.contains(']') {
        // The bracket belongs to the hostname, which is what stands after the
        // last `@`, and nothing may stand in front of it or between its close
        // and the port delimiter. Reading the first bracket in the whole
        // netloc instead let `api.example.com[2606:4700::1111]` keep the
        // address as its host, which `urlsplit` refuses outright.
        let hostname_and_port = match netloc.rfind('@') {
            Some(index) => &netloc[index + 1..],
            None => netloc,
        };
        let host = match hostname_and_port.split_once('[') {
            Some((before, bracketed)) => {
                if !before.is_empty() {
                    return Err(());
                }
                let (host, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
                if !port.is_empty() && !port.starts_with(':') {
                    return Err(());
                }
                host
            }
            // A bracket that stands only in the credentials leaves the
            // hostname unbracketed, and a name there is not an address.
            None => match hostname_and_port.split_once(':') {
                Some((host, _)) => host,
                None => hostname_and_port,
            },
        };
        bracketed_host_is_an_address(host)?;
    }
    let host = match netloc.rfind('@') {
        Some(index) => &netloc[index + 1..],
        None => netloc,
    };
    let host = match host.find('[') {
        Some(open) => {
            let bracketed = &host[open + 1..];
            match bracketed.find(']') {
                Some(close) => &bracketed[..close],
                None => bracketed,
            }
        }
        None => match host.find(':') {
            Some(index) => &host[..index],
            None => host,
        },
    };
    if host.is_empty() {
        return Ok(None);
    }
    Ok(Some(host.to_lowercase()))
}

#[cfg(test)]
#[path = "skill_document_text_evidence_tests.rs"]
mod tests;
