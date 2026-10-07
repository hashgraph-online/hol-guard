//! Byte-exact Rust port of the cloud-audit request/response helpers from
//! `src/codex_plugin_scanner/guard/local_supply_chain.py` (RTM-019 / RTM-026).
//!
//! Ported helpers (all pure, no daemon/IO coupling beyond explicit seams):
//!   * `_normalized_supply_chain_batch_url` (:4276-4299)
//!   * `_normalized_supply_chain_batch_job_url` (:4073-4094)
//!   * `_build_cloud_audit_payload` (:3976-4034) — plus the private helpers it
//!     closes over: `_build_workspace_context_payload` (:3958-3968),
//!     `_workspace_audit_lockfile_context` (:4153-4175),
//!     `_workspace_audit_fingerprint` (:4178-4197),
//!     `_hash_existing_paths` (:4200-4208), `_read_git_origin_codebase`
//!     (:3926-3944), `_codebase_label_from_remote` (:3906-3923),
//!     `_safe_machine_name` (:3947-3954), `_redacted_workspace_folder_path`
//!     (:3812-3819), `_read_workspace_audit_text` (:653-656),
//!     `_package_manager_for_scan` (reused from `workspace_inventory`).
//!   * `_normalize_cloud_audit_response` (:4211-4226)
//!   * `_resolve_next_refresh_at` (:4626-4638)
//!   * `_should_use_cloud_workspace_audit` (:3781-3792)
//!
//! Seam design: store reads go through the shared `SupplyChainStore` trait
//! (`get_sync_payload`, `get_cloud_sync_profile`, `get_cloud_workspace_id`),
//! workspace file reads through `PathSupportApi`, and the
//! environment-dependent surfaces (`socket.gethostname`,
//! `redact_local_path`) through `CloudAuditWorkspaceContextApi` so the
//! functions stay pure and testable.
//!
//! URL handling reimplements `urllib.parse.urlsplit`/`urlunsplit`/
//! `parse_qsl`/`urlencode`/`quote` at CPython 3.14 fidelity — including the
//! C0-control stripping, `uses_netloc` netloc re-insertion in `urlunsplit`,
//! bracketed-IPv6 validation, and the `_checknetloc` NFKC probe (expressed as
//! the closed set of code points whose NFKC form introduces `/ ? # @ :`).
//!
//! `ValueError`-raising paths are surfaced as `Err(String)` carrying the
//! Python exception message; `KeyError` on missing `ecosystem`/`name`
//! inventory fields surfaces the same way (`"'ecosystem'"`).

use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Map, Value};

// `_LOCAL_SUPPLY_CHAIN_HARNESS` is imported from
// `.runtime.package_protect_projection` in the oracle (`"guard-cli"`) — NOT
// the divergent `local_supply_chain::LOCAL_SUPPLY_CHAIN_HARNESS`
// (`"local-supply-chain"`). `install_time_event` already pins the oracle
// value; reuse it.
use crate::install_time_event::LOCAL_SUPPLY_CHAIN_HARNESS;
use crate::local_supply_chain::{
    is_audit_sensitive_basename, parse_timestamp, quote_component, stable_digest_hex, unquote_plus,
    urlencode, PathSupportApi, SupplyChainStore, CLOUD_AUDIT_PAGE_SIZE,
    DEFAULT_BUNDLE_REFRESH_INTERVAL_SECONDS,
};
use crate::package_intent_common::resolve_path_within_workspace;
use crate::workspace_inventory::package_manager_for_scan;

// ---------------------------------------------------------------------------
// Python scalar semantics — `str()`, truthiness, `str.strip()`.
// ---------------------------------------------------------------------------

/// Python `str.strip()` whitespace set: `char::is_whitespace` plus the C0
/// information separators `\x1c`–`\x1f` that `str.isspace()` includes
/// (mirrors `launch_identity::python_str_strip`, which is private).
fn python_str_is_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

fn python_str_strip(value: &str) -> &str {
    value.trim_matches(python_str_is_space)
}

/// Python truthiness for a JSON value.
fn py_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// Python `repr(float)`: shortest round-trip, `.0` suffix for integral values
/// inside the fixed-notation window, `e±NN` scientific outside it
/// (mirrors `audit_receipt::py_float_repr`, which is private).
fn py_float_repr(number: f64) -> String {
    if number.is_nan() {
        return "nan".to_string();
    }
    if number.is_infinite() {
        return if number < 0.0 { "-inf" } else { "inf" }.to_string();
    }
    let repr = format!("{number:e}");
    let (mantissa, exp) = repr.split_once('e').unwrap();
    let exponent: i32 = exp.parse().unwrap();
    let digits: String = mantissa.chars().filter(|c| c.is_ascii_digit()).collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let digit_count = digits.len() as i32;
    let mut out = String::new();
    if number.is_sign_negative() {
        out.push('-');
    }
    if (-4..16).contains(&exponent) {
        if exponent >= digit_count - 1 {
            out.push_str(digits);
            for _ in 0..(exponent - digit_count + 1) {
                out.push('0');
            }
            out.push_str(".0");
        } else if exponent >= 0 {
            let split = (exponent + 1) as usize;
            out.push_str(&digits[..split]);
            out.push('.');
            out.push_str(&digits[split..]);
        } else {
            out.push_str("0.");
            for _ in 0..(-exponent - 1) {
                out.push('0');
            }
            out.push_str(digits);
        }
    } else {
        out.push_str(&digits[..1]);
        if digit_count > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        out.push(if exponent < 0 { '-' } else { '+' });
        let magnitude = exponent.unsigned_abs();
        if magnitude < 10 {
            out.push('0');
        }
        out.push_str(&magnitude.to_string());
    }
    out
}

/// Python `repr(str)` (single quotes preferred).
fn py_str_repr(text: &str) -> String {
    let has_single = text.contains('\'');
    let has_double = text.contains('"');
    let quote = if has_single && !has_double { '"' } else { '\'' };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' if quote == '\'' => out.push_str("\\'"),
            '"' if quote == '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if (other as u32) < 0x20 || (other as u32) == 0x7f => {
                out.push_str(&format!("\\x{:02x}", other as u32));
            }
            other => out.push(other),
        }
    }
    out.push(quote);
    out
}

/// Python `repr(value)` for a JSON value (container members).
fn py_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(flag) => {
            if *flag {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Value::Number(number) => {
            if let Some(i) = number.as_i64() {
                i.to_string()
            } else if let Some(u) = number.as_u64() {
                u.to_string()
            } else {
                py_float_repr(number.as_f64().unwrap_or(0.0))
            }
        }
        Value::String(text) => py_str_repr(text),
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(py_repr).collect();
            format!("[{}]", inner.join(", "))
        }
        Value::Object(map) => {
            let inner: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{}: {}", py_str_repr(k), py_repr(v)))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
    }
}

/// Python `str(value)` for a JSON value.
fn py_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => py_repr(other),
    }
}

/// `str(response.get(key) or default)` — truthy coercion then default.
fn py_str_field_or_default(item: &Map<String, Value>, key: &str, default: &str) -> String {
    item.get(key)
        .filter(|v| py_truthy(v))
        .map(py_str)
        .unwrap_or_else(|| default.to_string())
}

// ---------------------------------------------------------------------------
// urllib.parse — CPython 3.14 `urlsplit` / `urlunsplit` / `parse_qsl` /
// `urlparse.path` subset. 3.14 `_urlsplit` lstrips C0 controls + space,
// deletes \t\r\n everywhere, requires `uses_netloc` membership is NOT checked
// during split (only during unsplit), validates bracketed netlocs, and
// `_checknetloc` rejects netlocs whose NFKC normalization introduces
// `/ ? # @ :`.
// ---------------------------------------------------------------------------

/// `urllib.parse.uses_netloc` (CPython 3.14, sorted membership).
const USES_NETLOC: &[&str] = &[
    "",
    "file",
    "ftp",
    "git",
    "git+ssh",
    "gopher",
    "http",
    "https",
    "imap",
    "itms-services",
    "mms",
    "nfs",
    "nntp",
    "prospero",
    "rsync",
    "rtsp",
    "rtsps",
    "rtspu",
    "sftp",
    "shttp",
    "snews",
    "svn",
    "svn+ssh",
    "telnet",
    "wais",
    "ws",
    "wss",
];

/// `urllib.parse.uses_params` — schemes whose path keeps `;params` attached
/// (empty scheme included: `urlparse` strips params for the default scheme).
const USES_PARAMS: &[&str] = &[
    "", "ftp", "hdl", "prospero", "http", "imap", "https", "shttp", "rtsp", "rtsps", "rtspu",
    "sip", "sips", "mms", "sftp", "tel",
];

/// `urllib.parse.scheme_chars`.
fn is_scheme_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')
}

/// `_WHATWG_C0_CONTROL_OR_SPACE` (chars lstripped from the URL head).
fn is_c0_or_space(c: char) -> bool {
    (c as u32) <= 0x20
}

/// `_UNSAFE_URL_BYTES_TO_REMOVE` = `\t \r \n` removed anywhere in the URL.
fn is_unsafe_url_byte(c: char) -> bool {
    matches!(c, '\t' | '\r' | '\n')
}

/// Code points whose `unicodedata.normalize('NFKC', c)` form contains one of
/// `/ ? # @ :` — the only single characters that can make `_checknetloc`
/// raise. Enumerated against this checkout's unicodedata:
/// U+2047 U+2048 U+2049 U+2100 U+2101 U+2105 U+2106 U+2A74 U+FE13 U+FE16
/// U+FE55 U+FE56 U+FE5F U+FE6B U+FF03 U+FF0F U+FF1A U+FF1F U+FF20.
const NFKC_RAISE_CHARS: &[char] = &[
    '\u{2047}', '\u{2048}', '\u{2049}', '\u{2100}', '\u{2101}', '\u{2105}', '\u{2106}', '\u{2a74}',
    '\u{fe13}', '\u{fe16}', '\u{fe55}', '\u{fe56}', '\u{fe5f}', '\u{fe6b}', '\u{ff03}', '\u{ff0f}',
    '\u{ff1a}', '\u{ff1f}', '\u{ff20}',
];

/// Named-tuple mirror of `urllib.parse.SplitResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlSplit {
    pub scheme: String,
    pub netloc: String,
    pub path: String,
    pub query: String,
    pub fragment: String,
}

/// `_splitnetloc(url, 2)` — netloc is `url[2:delim]` where `delim` is the
/// earliest of `/ ? #`.
fn split_netloc(url: &str) -> (&str, &str) {
    let tail = &url[2..];
    let delim = tail
        .find(['/', '?', '#'])
        .map(|i| i + 2)
        .unwrap_or(url.len());
    (&url[2..delim], &url[delim..])
}

/// `_check_bracketed_host` — IPvFuture (`v`/`V`+hex `.`anything) or a valid
/// IPv6 literal; an IPv4 literal in brackets raises.
fn check_bracketed_host(hostname: &str) -> Result<(), String> {
    if let Some(rest) = hostname.strip_prefix('v') {
        // re: \Av[a-fA-F0-9]+\..+\z — Python `re` is ASCII-only here.
        let valid = {
            let mut split = rest.splitn(2, '.');
            let hexdigits = split.next().unwrap_or("");
            let tail = split.next();
            !hexdigits.is_empty()
                && hexdigits.chars().all(|c| c.is_ascii_hexdigit())
                && tail.is_some_and(|t| !t.is_empty())
        };
        if !valid {
            return Err("IPvFuture address is invalid".to_string());
        }
        return Ok(());
    }
    match std::net::IpAddr::from_str(hostname) {
        Ok(std::net::IpAddr::V4(_)) => Err("An IPv4 address cannot be in brackets".to_string()),
        Ok(std::net::IpAddr::V6(_)) => Ok(()),
        Err(_) => Err(format!(
            "'{hostname}' does not appear to be an IPv4 or IPv6 address"
        )),
    }
}

/// `_check_bracketed_netloc` — nothing may precede `[` inside the hostinfo,
/// and only `:port` may follow `]`.
fn check_bracketed_netloc(netloc: &str) -> Result<(), String> {
    let hostname_and_port = netloc.rsplit('@').next().unwrap_or(netloc);
    let (before_bracket, have_open, bracketed) = match hostname_and_port.find('[') {
        Some(i) => (&hostname_and_port[..i], true, &hostname_and_port[i + 1..]),
        None => (hostname_and_port, false, ""),
    };
    if have_open {
        if !before_bracket.is_empty() {
            return Err("Invalid IPv6 URL".to_string());
        }
        let (hostname, _, port) = match bracketed.find(']') {
            Some(i) => (&bracketed[..i], true, &bracketed[i + 1..]),
            None => (bracketed, false, ""),
        };
        if !port.is_empty() && !port.starts_with(':') {
            return Err("Invalid IPv6 URL".to_string());
        }
        check_bracketed_host(hostname)?;
    } else {
        let hostname = hostname_and_port
            .split_once(':')
            .map(|(h, _)| h)
            .unwrap_or(hostname_and_port);
        check_bracketed_host(hostname)?;
    }
    Ok(())
}

/// `_checknetloc` — strip `@ : # ?`, then reject when NFKC normalization of
/// any remaining character introduces `/ ? # @ :`. Whole-string NFKC cannot
/// *compose* ASCII punctuation from adjacent characters, so a per-character
/// membership test against the enumerated raise set is equivalent.
fn check_netloc(netloc: &str) -> Result<(), String> {
    if netloc.is_empty() || netloc.is_ascii() {
        return Ok(());
    }
    let stripped: String = netloc
        .chars()
        .filter(|c| !matches!(c, '@' | ':' | '#' | '?'))
        .collect();
    if stripped.chars().any(|c| NFKC_RAISE_CHARS.contains(&c)) {
        return Err(format!(
            "netloc '{netloc}' contains invalid characters under NFKC normalization"
        ));
    }
    Ok(())
}

/// `urllib.parse.urlsplit(url)` at CPython 3.14 fidelity.
/// `Err` carries the `ValueError` message text.
pub(crate) fn urlsplit(url: &str) -> Result<UrlSplit, String> {
    // url.lstrip(_WHATWG_C0_CONTROL_OR_SPACE)
    let stripped = url.trim_start_matches(is_c0_or_space);
    // remove \t \r \n everywhere
    let cleaned: String = stripped
        .chars()
        .filter(|c| !is_unsafe_url_byte(*c))
        .collect();
    let mut rest: &str = cleaned.as_str();
    let mut scheme = String::new();
    let mut netloc = String::new();
    if let Some(i) = rest.find(':') {
        let bytes = rest.as_bytes();
        if i > 0
            && bytes[0].is_ascii()
            && (bytes[0] as char).is_ascii_alphabetic()
            && bytes[..i].iter().all(|b| is_scheme_char(*b))
        {
            scheme = rest[..i].to_lowercase();
            rest = &rest[i + 1..];
        }
    }
    if rest.starts_with("//") {
        let (nl, tail) = split_netloc(rest);
        netloc = nl.to_string();
        rest = tail;
        let has_open = netloc.contains('[');
        let has_close = netloc.contains(']');
        if has_open != has_close {
            return Err("Invalid IPv6 URL".to_string());
        }
        if has_open && has_close {
            check_bracketed_netloc(&netloc)?;
        }
    }
    let mut fragment = String::new();
    let mut query = String::new();
    if let Some(i) = rest.find('#') {
        fragment = rest[i + 1..].to_string();
        rest = &rest[..i];
    }
    if let Some(i) = rest.find('?') {
        query = rest[i + 1..].to_string();
        rest = &rest[..i];
    }
    check_netloc(&netloc)?;
    Ok(UrlSplit {
        scheme,
        netloc,
        path: rest.to_string(),
        query,
        fragment,
    })
}

/// `urllib.parse.urlunsplit((scheme, netloc, url, query, fragment))` —
/// CPython 3.14: empty netloc re-materializes `//` when the scheme is in
/// `uses_netloc` and the path is empty or absolute.
pub(crate) fn urlunsplit(
    scheme: &str,
    netloc: &str,
    url: &str,
    query: &str,
    fragment: &str,
) -> String {
    let effective_netloc: Option<&str> = if netloc.is_empty() {
        if !scheme.is_empty()
            && USES_NETLOC.contains(&scheme)
            && (url.is_empty() || url.starts_with('/'))
        {
            Some("")
        } else {
            None
        }
    } else {
        Some(netloc)
    };
    let mut out = String::new();
    match effective_netloc {
        Some(nl) => {
            out.push_str("//");
            out.push_str(nl);
            if !url.is_empty() && !url.starts_with('/') {
                out.push('/');
            }
            out.push_str(url);
        }
        None => {
            if url.starts_with("//") {
                out.push_str("//");
            }
            out.push_str(url);
        }
    }
    if !scheme.is_empty() {
        // _urlunsplit puts scheme first: rebuild order — scheme: prefix.
        out = format!("{scheme}:{out}");
    }
    if !query.is_empty() {
        out.push('?');
        out.push_str(query);
    }
    if !fragment.is_empty() {
        out.push('#');
        out.push_str(fragment);
    }
    out
}

/// `urllib.parse.parse_qsl(query, keep_blank_values=True)` — `&`-separated,
/// bare `&` skipped, `name` without `=` yields `""`, `+`→space, `%XX`
/// decoded with `errors="replace"` semantics (from_utf8_lossy).
fn parse_qsl(query: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for field in query.split('&') {
        if field.is_empty() {
            continue;
        }
        let (name, value) = match field.find('=') {
            Some(i) => (&field[..i], &field[i + 1..]),
            None => (field, ""),
        };
        pairs.push((unquote_plus(name), unquote_plus(value)));
    }
    pairs
}

/// End of `urlparse(...).path`, excluding the final segment's `;params`.
pub(crate) fn urlparse_path_end(parts: &UrlSplit) -> usize {
    if USES_PARAMS.contains(&parts.scheme.as_str()) {
        let start = parts.path.rfind('/').unwrap_or(0);
        if let Some(index) = parts.path[start..].find(';') {
            return start + index;
        }
    }
    parts.path.len()
}

/// `urllib.parse.urlparse(remote).path` — scheme/netloc/path only; `;params`
/// stripped when the scheme is in `uses_params`.
fn urlparse_path(remote: &str) -> Result<String, String> {
    let parts = urlsplit(remote)?;
    let end = urlparse_path_end(&parts);
    let mut path = parts.path;
    path.truncate(end);
    Ok(path)
}

// ---------------------------------------------------------------------------
// `json.dumps(..., ensure_ascii=True, sort_keys=True, separators=(",", ":"))`
// subset over `serde_json::Value` (BTreeMap already sorts keys in codepoint
// order, which matches CPython `sort_keys` on `str`).
// ---------------------------------------------------------------------------

fn write_json_string(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c if (c as u32) < 0x80 => out.push(c),
            c => {
                let code = c as u32;
                if code > 0xffff {
                    let v = code - 0x1_0000;
                    let hi = 0xd800 + (v >> 10);
                    let lo = 0xdc00 + (v & 0x3ff);
                    out.push_str(&format!("\\u{hi:04x}\\u{lo:04x}"));
                } else {
                    out.push_str(&format!("\\u{code:04x}"));
                }
            }
        }
    }
    out.push('"');
}

fn write_json_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_json_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_value(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(k, out);
                out.push(':');
                write_json_value(v, out);
            }
            out.push('}');
        }
    }
}

fn json_dumps(value: &Value) -> String {
    let mut out = String::new();
    write_json_value(value, &mut out);
    out
}

// ---------------------------------------------------------------------------
// `str.splitlines()` — CPython boundary set is wider than Rust `lines()`:
// \n \r \r\n \v \f \x1c-\x1e \x85 \u2028 \u2029.
// ---------------------------------------------------------------------------

fn is_py_linebreak(c: char) -> bool {
    matches!(
        c,
        '\n' | '\u{b}'
            | '\u{c}'
            | '\u{1c}'
            | '\u{1d}'
            | '\u{1e}'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

fn python_splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0usize;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c == '\r' {
            lines.push(&text[start..i]);
            if let Some(&(j, '\n')) = chars.peek() {
                chars.next();
                start = j + 1;
            } else {
                start = i + 1;
            }
        } else if is_py_linebreak(c) {
            lines.push(&text[start..i]);
            start = i + c.len_utf8();
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

// ---------------------------------------------------------------------------
// Path leaf names matching Python `Path.name` semantics (keeps `..`, drops
// `.`, root, and drive prefixes).
// ---------------------------------------------------------------------------

fn path_leaf_name(path: &Path) -> String {
    let mut last_normal: Option<String> = None;
    let mut trailing_parent = false;
    for component in path.components() {
        match component {
            Component::Normal(os) => {
                last_normal = Some(os.to_string_lossy().into_owned());
                trailing_parent = false;
            }
            Component::ParentDir => {
                trailing_parent = true;
            }
            _ => {}
        }
    }
    if trailing_parent {
        // Path("a/../..").name == ".."
        return "..".to_string();
    }
    last_normal.unwrap_or_default()
}

fn dir_name(path: &Path) -> String {
    path_leaf_name(path)
}

// ---------------------------------------------------------------------------
// Environment seam — `socket.gethostname` and `redaction.redact_local_path`.
// ---------------------------------------------------------------------------

/// Seam for the two environment-dependent reads inside
/// `_build_workspace_context_payload`: `socket.gethostname` and
/// `redaction.redact_local_path` (Python `redaction.py` :304-310).
pub trait CloudAuditWorkspaceContextApi {
    /// `redact_local_path(value)` with no explicit `home_dir`.
    fn redact_local_path(&self, value: &str) -> String;
    /// `_safe_machine_name` — `socket.gethostname().strip()` or `None` on
    /// `OSError`/empty.
    fn safe_machine_name(&self) -> Option<String>;
}

// `_POSIX_USER_PATH_PATTERN` / `_WINDOWS_USER_PATH_PATTERN`
// (redaction.py :128-134). `\s` in CPython `re` covers
// [ \t\n\r\f\v\x1c-\x1f\x85\xa0…] — spelled out below via `\p{White_Space}`
// plus the C0 separators Rust excludes.
// CPython `re` `\s` = `\p{White_Space}` + C0 separators `\x1c-\x1f`.
// `'` and `-` inside the Python class need no escape, but do in `regex`.
static POSIX_USER_PATH_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?P<prefix>^|[\\s\\x{1c}-\\x{1f}\\\"\u{27}\u{60},;:)\\}\\]])(?P<root>/(?:Users|home)/[^/\\s\\x{1c}-\\x{1f}\\\"\u{27}\u{60},;:)\\}\\]]+)(?P<rest>(?:/[^\\s\\x{1c}-\\x{1f}\\\"\u{27}\u{60},;:)\\}\\]]*)?)").unwrap()
});
static WINDOWS_USER_PATH_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?P<prefix>^|[\\s\\x{1c}-\\x{1f}\\\"\u{27}\u{60},;:)\\}\\]])(?P<root>[A-Za-z]:[\\\\/]+Users[\\\\/]+[^\\\\/\\s\\x{1c}-\\x{1f}\\\"\u{27}\u{60},;:)\\}\\]]+)(?P<rest>(?:[\\\\/][^\\s\\x{1c}-\\x{1f}\\\"\u{27}\u{60},;:)\\}\\]]*)?)").unwrap()
});

/// `Path.home()` approximation: POSIX `$HOME`, Windows `$USERPROFILE` or
/// `$HOMEDRIVE$HOMEPATH`; `None` mirrors the `RuntimeError` path.
fn python_home() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var("HOME")
            .ok()
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    }
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE")
            .ok()
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                let drive = std::env::var("HOMEDRIVE").ok()?;
                let path = std::env::var("HOMEPATH").ok()?;
                Some(PathBuf::from(format!("{drive}{path}")))
            })
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

/// `redact_local_path(value)` (redaction.py :304-310) with `home_dir=None`:
/// replace the current-home prefix with `~`, then collapse `/Users/<name>`,
/// `/home/<name>`, and `<drive>:\Users\<name>` references.
fn redact_local_path_default(value: &str) -> String {
    fn replace_home_prefix(value: &str, home_value: &str) -> String {
        let home_prefix = home_value.trim_end_matches(['/', '\\']);
        if home_prefix.is_empty() || home_prefix == "/" || home_prefix == "\\" {
            return value.to_string();
        }
        if value == home_prefix {
            return "~".to_string();
        }
        if let Some(rest) = value.strip_prefix(home_prefix) {
            if let Some(next) = rest.as_bytes().first() {
                if matches!(next, b'/' | b'\\') {
                    return format!("~{rest}");
                }
            }
        }
        value.to_string()
    }
    let mut redacted = value.to_string();
    if let Some(home) = python_home() {
        redacted = replace_home_prefix(&redacted, &home.to_string_lossy());
    }
    redacted = POSIX_USER_PATH_PATTERN
        .replace_all(&redacted, |caps: &regex::Captures| {
            format!("{}~{}", &caps["prefix"], &caps["rest"])
        })
        .into_owned();
    redacted = WINDOWS_USER_PATH_PATTERN
        .replace_all(&redacted, |caps: &regex::Captures| {
            format!("{}~{}", &caps["prefix"], &caps["rest"])
        })
        .into_owned();
    redacted
}

/// Default environment-backed implementation of the workspace-context seam.
///
/// `safe_machine_name` resolves `socket.gethostname` via the
/// `COMPUTERNAME`/`HOSTNAME` environment convention already used by
/// `local_supply_chain::safe_machine_name`; `redact_local_path` is the full
/// port of `redaction.redact_local_path` with the implicit `Path.home()`.
#[derive(Debug, Default, Clone, Copy)]
pub struct EnvCloudAuditWorkspaceContext;

impl CloudAuditWorkspaceContextApi for EnvCloudAuditWorkspaceContext {
    fn redact_local_path(&self, value: &str) -> String {
        redact_local_path_default(value)
    }
    fn safe_machine_name(&self) -> Option<String> {
        std::env::var("COMPUTERNAME")
            .ok()
            .or_else(|| std::env::var("HOSTNAME").ok())
            .and_then(|value| {
                let trimmed = value.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            })
    }
}

// ---------------------------------------------------------------------------
// `_normalized_supply_chain_batch_url` (:4276-4299).
// ---------------------------------------------------------------------------

/// `_normalized_supply_chain_batch_url(sync_url, workspace_id) -> str`.
///
/// Re-roots `<path>[/receipts/sync]` at `<path>/supply-chain/evaluate/batch`,
/// drops existing `workspaceId` pairs, appends the fresh one, drops the
/// fragment. `Err` mirrors `urlsplit`'s `ValueError`.
pub fn normalized_supply_chain_batch_url(
    sync_url: &str,
    workspace_id: &str,
) -> Result<String, String> {
    let parsed = urlsplit(sync_url)?;
    let sync_path = parsed.path.trim_end_matches('/');
    let next_path = if let Some(stripped) = sync_path.strip_suffix("/receipts/sync") {
        format!("{stripped}/supply-chain/evaluate/batch")
    } else {
        format!("{sync_path}/supply-chain/evaluate/batch")
    };
    let mut query_pairs: Vec<(String, String)> = parse_qsl(&parsed.query)
        .into_iter()
        .filter(|(key, _)| key != "workspaceId")
        .collect();
    query_pairs.push(("workspaceId".to_string(), workspace_id.to_string()));
    Ok(urlunsplit(
        &parsed.scheme,
        &parsed.netloc,
        &next_path,
        &urlencode(&query_pairs),
        "",
    ))
}

// ---------------------------------------------------------------------------
// `_normalized_supply_chain_batch_job_url` (:4073-4094).
// ---------------------------------------------------------------------------

/// `_normalized_supply_chain_batch_job_url(sync_url, workspace_id, job_id,
/// page_size=…) -> str`.
///
/// Re-splits the batch URL, drops `cursor`/`pageSize`, appends
/// `pageSize=max(page_size, 1)`, and appends `quote(job_id, safe='')` to the
/// batch path.
pub fn normalized_supply_chain_batch_job_url(
    sync_url: &str,
    workspace_id: &str,
    job_id: &str,
    page_size: i64,
) -> Result<String, String> {
    let batch_url = normalized_supply_chain_batch_url(sync_url, workspace_id)?;
    let parsed = urlsplit(&batch_url)?;
    let mut query_pairs: Vec<(String, String)> = parse_qsl(&parsed.query)
        .into_iter()
        .filter(|(key, _)| key != "cursor" && key != "pageSize")
        .collect();
    query_pairs.push(("pageSize".to_string(), page_size.max(1).to_string()));
    let next_path = format!(
        "{}/{}",
        parsed.path.trim_end_matches('/'),
        quote_component(job_id)
    );
    Ok(urlunsplit(
        &parsed.scheme,
        &parsed.netloc,
        &next_path,
        &urlencode(&query_pairs),
        "",
    ))
}

// ---------------------------------------------------------------------------
// Workspace context helpers (`_read_git_origin_codebase`,
// `_codebase_label_from_remote`, `_redacted_workspace_folder_path`,
// `_build_workspace_context_payload`).
// ---------------------------------------------------------------------------

/// `_codebase_label_from_remote(remote)` (:3906-3923).
fn codebase_label_from_remote(remote: &str) -> Result<Option<String>, String> {
    let normalized = python_str_strip(remote).trim_end_matches('/');
    if normalized.is_empty() {
        return Ok(None);
    }
    let path = if normalized.contains("://") {
        urlparse_path(normalized)?
            .trim_start_matches('/')
            .to_string()
    } else if normalized.contains(':') {
        normalized
            .split_once(':')
            .map(|(_, tail)| tail.to_string())
            .unwrap_or_default()
    } else {
        normalized.to_string()
    };
    let label = path.trim_matches('/');
    if label.is_empty() {
        return Ok(None);
    }
    // `label[:-4] if label.endswith(".git")` — a bare ".git" yields "".
    Ok(Some(
        label.strip_suffix(".git").unwrap_or(label).to_string(),
    ))
}

/// `_read_git_origin_codebase(workspace_dir)` (:3926-3944). Reads
/// `.git/config`, tracks the `[remote "origin"]` section, returns the label
/// of the first `url…=` line inside it.
///
/// Divergence note: Python propagates `UnicodeDecodeError` for non-UTF-8
/// configs (only `OSError` is caught); here an undecodable config yields
/// `Ok(None)` like a missing one.
fn read_git_origin_codebase(workspace_dir: &Path) -> Result<Option<String>, String> {
    let config_path = workspace_dir.join(".git").join("config");
    let config_text = match std::fs::read_to_string(&config_path) {
        Ok(text) => text,
        Err(_) => return Ok(None),
    };
    let mut in_origin = false;
    for raw_line in python_splitlines(&config_text) {
        let line = python_str_strip(raw_line);
        if line.starts_with('[') && line.ends_with(']') {
            in_origin = line == "[remote \"origin\"]";
            continue;
        }
        if !in_origin || !line.starts_with("url") || !line.contains('=') {
            continue;
        }
        let (_, _, value) = {
            let idx = line.find('=').unwrap();
            (&line[..idx], "=", &line[idx + 1..])
        };
        return codebase_label_from_remote(value);
    }
    Ok(None)
}

/// `_redacted_workspace_folder_path(workspace_dir)` (:3812-3819): return the
/// redacted path when redaction changed it or the path is relative; otherwise
/// `…/<parent>/<name>` (or `…/<name>` for shallow roots).
fn redacted_workspace_folder_path(
    workspace_dir: &Path,
    context: &dyn CloudAuditWorkspaceContextApi,
) -> String {
    let raw_path = workspace_dir.to_string_lossy().into_owned();
    let redacted = context.redact_local_path(&raw_path);
    if redacted != raw_path || !workspace_dir.is_absolute() {
        return redacted;
    }
    // `parts` — Python keeps the drive prefix and `..`, drops "" and "/".
    let mut parts: Vec<String> = Vec::new();
    let mut components = workspace_dir.components().peekable();
    while let Some(component) = components.next() {
        match component {
            Component::Prefix(prefix) => {
                let mut text = prefix.as_os_str().to_string_lossy().into_owned();
                if matches!(components.peek(), Some(Component::RootDir)) {
                    components.next();
                    text.push('\\');
                }
                parts.push(text);
            }
            Component::RootDir | Component::CurDir => {}
            other => parts.push(other.as_os_str().to_string_lossy().into_owned()),
        }
    }
    if parts.len() >= 2 {
        format!("…/{}/{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        format!("…/{}", dir_name(workspace_dir))
    }
}

/// `_build_workspace_context_payload` (:3958-3968).
fn build_workspace_context_payload(
    workspace_dir: &Path,
    manifest_paths: &[String],
    lockfile_paths: &[String],
    context: &dyn CloudAuditWorkspaceContextApi,
) -> Result<Map<String, Value>, String> {
    let codebase = read_git_origin_codebase(workspace_dir)?
        .filter(|label| !label.is_empty())
        .unwrap_or_else(|| dir_name(workspace_dir));
    let mut out = Map::new();
    out.insert("agent".into(), json!(LOCAL_SUPPLY_CHAIN_HARNESS));
    out.insert("codebase".into(), json!(codebase));
    out.insert(
        "folderPath".into(),
        json!(redacted_workspace_folder_path(workspace_dir, context)),
    );
    out.insert("lockfilePaths".into(), json!(lockfile_paths));
    out.insert(
        "machine".into(),
        context
            .safe_machine_name()
            .map_or(Value::Null, Value::String),
    );
    out.insert("manifestPaths".into(), json!(manifest_paths));
    out.insert(
        "packageManager".into(),
        json!(package_manager_for_scan(manifest_paths)),
    );
    out.insert("workspaceName".into(), json!(dir_name(workspace_dir)));
    Ok(out)
}

// ---------------------------------------------------------------------------
// `_read_workspace_audit_text` (:653-656) and file-hash helpers.
// ---------------------------------------------------------------------------

/// `_read_workspace_audit_text` — sensitive basenames (`.env*`) never read;
/// otherwise `read_text_within_workspace`.
fn read_workspace_audit_text(
    paths: &dyn PathSupportApi,
    workspace_dir: &Path,
    relative_path: &str,
) -> Option<String> {
    if is_audit_sensitive_basename(&path_leaf_name(Path::new(relative_path))) {
        return None;
    }
    paths.read_text_within_workspace(workspace_dir, relative_path)
}

/// `_hash_existing_paths` (:4200-4208) — digest each workspace file that
/// resolves, in order, skipping unreadable ones.
fn hash_existing_paths(
    paths: &dyn PathSupportApi,
    workspace_dir: &Path,
    relative_paths: &[String],
) -> Vec<String> {
    let mut hashes = Vec::new();
    for relative_path in relative_paths {
        if let Some(payload) = paths.read_bytes_within_workspace(workspace_dir, relative_path) {
            hashes.push(stable_digest_hex(&payload));
        }
    }
    hashes
}

/// `_workspace_audit_lockfile_context` (:4153-4175).
fn workspace_audit_lockfile_context(
    paths: &dyn PathSupportApi,
    workspace_dir: &Path,
    manifest_paths: &[String],
    lockfile_paths: &[String],
    inventory_len: usize,
) -> Option<Map<String, Value>> {
    if lockfile_paths.is_empty() {
        return None;
    }
    let lockfile_path = resolve_path_within_workspace(workspace_dir, &lockfile_paths[0])?;
    if !lockfile_path.exists() {
        return None;
    }
    let lockfile_text = read_workspace_audit_text(paths, workspace_dir, &lockfile_paths[0])?;
    let mut manifest_hash: Option<String> = None;
    if !manifest_paths.is_empty() {
        if let Some(manifest_bytes) =
            paths.read_bytes_within_workspace(workspace_dir, &manifest_paths[0])
        {
            if !is_audit_sensitive_basename(&path_leaf_name(Path::new(&manifest_paths[0]))) {
                manifest_hash = Some(stable_digest_hex(&manifest_bytes));
            }
        }
    }
    let mut out = Map::new();
    out.insert("dependencyCount".into(), json!(inventory_len));
    out.insert("fileName".into(), json!(path_leaf_name(&lockfile_path)));
    out.insert(
        "lockfileHash".into(),
        json!(stable_digest_hex(lockfile_text.as_bytes())),
    );
    out.insert(
        "manifestHash".into(),
        manifest_hash.map_or(Value::Null, Value::String),
    );
    Some(out)
}

/// `_workspace_audit_fingerprint` (:4178-4197) — HMAC digest over the
/// compact-sorted JSON of workspace id/name + file hash vectors.
fn workspace_audit_fingerprint(
    paths: &dyn PathSupportApi,
    workspace_id: &str,
    workspace_dir: &Path,
    manifest_paths: &[String],
    lockfile_paths: &[String],
    policy_version: &str,
) -> String {
    let manifest_hashes = hash_existing_paths(paths, workspace_dir, manifest_paths);
    let lockfile_hashes = hash_existing_paths(paths, workspace_dir, lockfile_paths);
    let mut doc = Map::new();
    doc.insert("workspace_id".into(), json!(workspace_id));
    doc.insert("workspace_name".into(), json!(dir_name(workspace_dir)));
    doc.insert("manifest_hashes".into(), json!(manifest_hashes));
    doc.insert("lockfile_hashes".into(), json!(lockfile_hashes));
    doc.insert("policy_version".into(), json!(policy_version));
    stable_digest_hex(json_dumps(&Value::Object(doc)).as_bytes())
}

// ---------------------------------------------------------------------------
// `_build_cloud_audit_payload` (:3976-4034).
// ---------------------------------------------------------------------------

/// `_build_cloud_audit_payload` (:3976-4034).
///
/// `store.get_sync_payload("supply_chain_bundle_summary")` supplies the
/// `policy_hash` for `policyVersion`; `paths` performs the workspace file
/// reads; `context` supplies hostname + path redaction.
///
/// `Err` mirrors the oracle's `KeyError` when an inventory item lacks
/// `ecosystem`/`name` (message text is the Python `str(KeyError)`), and any
/// `ValueError` from `urlparse` while labelling a git remote.
#[allow(clippy::too_many_arguments)]
pub fn build_cloud_audit_payload(
    workspace_dir: &Path,
    workspace_id: &str,
    store: &dyn SupplyChainStore,
    manifest_paths: &[String],
    lockfile_paths: &[String],
    inventory: &[Value],
    mode: &str,
    page_size: Option<i64>,
    paths: &dyn PathSupportApi,
    context: &dyn CloudAuditWorkspaceContextApi,
) -> Result<Map<String, Value>, String> {
    let summary = store.get_sync_payload("supply_chain_bundle_summary");
    let mut policy_version = "local:none".to_string();
    if let Some(summary) = summary.as_ref().and_then(Value::as_object) {
        if let Some(policy_hash) = summary.get("policy_hash").and_then(Value::as_str) {
            if !policy_hash.is_empty() {
                policy_version = policy_hash.to_string();
            }
        }
    }
    let fingerprint = workspace_audit_fingerprint(
        paths,
        workspace_id,
        workspace_dir,
        manifest_paths,
        lockfile_paths,
        &policy_version,
    );

    let mut packages = Vec::with_capacity(inventory.len());
    for item in inventory {
        let item = item.as_object().cloned().unwrap_or_default();
        let ecosystem = item
            .get("ecosystem")
            .map(py_str)
            .ok_or_else(|| "'ecosystem'".to_string())?;
        let name = item
            .get("name")
            .map(py_str)
            .ok_or_else(|| "'name'".to_string())?;
        let mut package = Map::new();
        package.insert(
            "direct".into(),
            json!(item.get("direct").is_some_and(py_truthy)),
        );
        package.insert("ecosystem".into(), json!(ecosystem));
        package.insert("name".into(), json!(name));
        package.insert(
            "namespace".into(),
            item.get("namespace").cloned().unwrap_or(Value::Null),
        );
        // `isinstance(item.get("version"), str)` — empty string still emitted.
        if let Some(version) = item.get("version").filter(|v| v.is_string()) {
            package.insert("version".into(), json!(py_str(version)));
        }
        if let Some(range) = item.get("range").filter(|v| v.is_string()) {
            package.insert("range".into(), json!(py_str(range)));
        }
        packages.push(Value::Object(package));
    }

    // min(_CLOUD_AUDIT_PAGE_SIZE, max(page_size or len(inventory), 1))
    let base: i64 = page_size
        .filter(|n| *n != 0)
        .unwrap_or(inventory.len() as i64);
    let effective_page_size = (CLOUD_AUDIT_PAGE_SIZE as i64).min(base.max(1));

    let mut payload = Map::new();
    let mut command_shape = Map::new();
    command_shape.insert("argCount".into(), json!(3));
    command_shape.insert("flags".into(), json!(Vec::<Value>::new()));
    command_shape.insert(
        "packageManager".into(),
        json!(package_manager_for_scan(manifest_paths)),
    );
    command_shape.insert("redacted".into(), json!(true));
    command_shape.insert("verb".into(), json!("audit"));
    payload.insert("commandShape".into(), Value::Object(command_shape));
    payload.insert("harness".into(), json!(LOCAL_SUPPLY_CHAIN_HARNESS));
    if let Some(lockfile_context) = workspace_audit_lockfile_context(
        paths,
        workspace_dir,
        manifest_paths,
        lockfile_paths,
        inventory.len(),
    ) {
        payload.insert("lockfileContext".into(), Value::Object(lockfile_context));
    }
    payload.insert("mode".into(), json!(mode));
    payload.insert("pageSize".into(), json!(effective_page_size));
    payload.insert("packages".into(), Value::Array(packages));
    payload.insert("policyVersion".into(), json!(policy_version));
    payload.insert(
        "workspaceContext".into(),
        Value::Object(build_workspace_context_payload(
            workspace_dir,
            manifest_paths,
            lockfile_paths,
            context,
        )?),
    );
    payload.insert("workspaceFingerprint".into(), json!(fingerprint));
    Ok(payload)
}

// ---------------------------------------------------------------------------
// `_normalize_cloud_audit_response` (:4211-4226).
// ---------------------------------------------------------------------------

/// `_dict_items` (:4646-4649) — list members that are dicts, order preserved.
fn dict_items(value: Option<&Value>) -> Vec<Value> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|item| item.is_object())
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// `_int_value` (:4664-4667) — `isinstance(value, int)` (bool excluded in
/// Python `int`? — `isinstance(True, int)` is True, and serde_json never
/// emits bools as numbers, so `as_i64`/`as_u64` is exact).
fn int_value(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(n)) => n
            .as_i64()
            .or_else(|| n.as_u64().and_then(|u| i64::try_from(u).ok())),
        _ => None,
    }
}

/// `_normalize_cloud_audit_response(response)` (:4211-4226): coerce the
/// cloud verdict into the local summary shape with `or`-defaults.
pub fn normalize_cloud_audit_response(response: &Map<String, Value>) -> Map<String, Value> {
    let mut out = Map::new();
    out.insert(
        "decision".into(),
        json!(py_str_field_or_default(response, "decision", "monitor")),
    );
    out.insert(
        "packages".into(),
        Value::Array(dict_items(response.get("packages"))),
    );
    out.insert(
        "reasons".into(),
        Value::Array(dict_items(response.get("reasons"))),
    );
    out.insert(
        "enforcement".into(),
        json!(py_str_field_or_default(
            response,
            "enforcement",
            "premium_cloud"
        )),
    );
    out.insert(
        "entitlement_state".into(),
        json!(py_str_field_or_default(
            response,
            "entitlementState",
            "premium"
        )),
    );
    out.insert(
        "cache_status".into(),
        json!(py_str_field_or_default(response, "cacheStatus", "miss")),
    );
    out.insert(
        "processed_count".into(),
        json!(int_value(response.get("processedCount")).unwrap_or(0)),
    );
    out.insert(
        "total_packages".into(),
        json!(int_value(response.get("totalPackages")).unwrap_or(0)),
    );
    out.insert(
        "status".into(),
        json!(py_str_field_or_default(response, "status", "completed")),
    );
    out.insert(
        "workspace_id".into(),
        json!(py_str_field_or_default(response, "workspaceId", "")),
    );
    out
}

// ---------------------------------------------------------------------------
// `_resolve_next_refresh_at` (:4626-4638) and `_string_value` (:4658-4661).
// ---------------------------------------------------------------------------

/// `_string_value` — a non-blank `str`, else `None` (returns the original,
/// unstripped text; `_parse_timestamp` strips internally).
fn string_value(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !python_str_strip(text).is_empty())
}

/// `_resolve_next_refresh_at(summary=…, synced_at=…)` — explicit
/// `next_refresh_at` wins; else `synced_at + 15min`; else `None`.
///
/// `python_str_strip` is applied before `parse_timestamp` because the shared
/// parser uses `str::trim`, which misses the `\x1c-\x1f` CPython strip set.
pub fn resolve_next_refresh_at(
    summary: Option<&Map<String, Value>>,
    synced_at: Option<&str>,
) -> Option<String> {
    if let Some(explicit) = summary
        .and_then(|s| string_value(s.get("next_refresh_at")))
        .and_then(|text| parse_timestamp(python_str_strip(text)))
    {
        return Some(explicit.isoformat());
    }
    let synced = synced_at.and_then(|text| parse_timestamp(python_str_strip(text)))?;
    Some(
        synced
            .add_seconds_f64(DEFAULT_BUNDLE_REFRESH_INTERVAL_SECONDS)
            .isoformat(),
    )
}

// ---------------------------------------------------------------------------
// `_should_use_cloud_workspace_audit` (:3781-3792).
// ---------------------------------------------------------------------------

/// `_should_use_cloud_workspace_audit(store=…, posture=…)` — the premium-tier
/// gate: a sync profile AND a workspace id AND `posture.bundle.tier` that
/// strips+lowercases to `"premium"`.
pub fn should_use_cloud_workspace_audit(
    store: &dyn SupplyChainStore,
    posture: &Map<String, Value>,
) -> bool {
    if store.get_cloud_sync_profile().is_none() || store.get_cloud_workspace_id().is_none() {
        return false;
    }
    let Some(bundle) = posture.get("bundle").and_then(Value::as_object) else {
        return false;
    };
    bundle
        .get("tier")
        .map(py_str)
        .map(|tier| python_str_strip(&tier).to_lowercase() == "premium")
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Oracle-verified golden-vector tests.
// Vectors were generated against `codex_plugin_scanner.guard.local_supply_chain`
// on this checkout (CPython 3.14.3) — see `tests::oracle` comments.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap as StdHashMap;

    // --- fakes -------------------------------------------------------------

    /// `read_bytes_within_workspace` / `read_text_within_workspace`
    /// (workspace_path_guard.py) — resolve inside the workspace, files only.
    struct RealPaths;

    impl PathSupportApi for RealPaths {
        fn resolve_path_within_allowed_roots(
            &self,
            _candidate: &Path,
            _allowed_roots: &[PathBuf],
            _require_exists: bool,
        ) -> Option<PathBuf> {
            None
        }
        fn resolves_within_root(
            &self,
            _root: &Path,
            _candidate: &Path,
            _require_exists: bool,
        ) -> bool {
            false
        }
        fn read_text_within_workspace(
            &self,
            workspace_dir: &Path,
            relative_path: &str,
        ) -> Option<String> {
            let resolved = resolve_path_within_workspace(workspace_dir, relative_path)?;
            if !resolved.is_file() {
                return None;
            }
            std::fs::read_to_string(resolved).ok()
        }
        fn read_bytes_within_workspace(
            &self,
            workspace_dir: &Path,
            relative_path: &str,
        ) -> Option<Vec<u8>> {
            let resolved = resolve_path_within_workspace(workspace_dir, relative_path)?;
            if !resolved.is_file() {
                return None;
            }
            std::fs::read(resolved).ok()
        }
    }

    /// Scripted workspace context — no real hostname/home probing.
    struct FakeContext {
        machine: Option<String>,
        redact_home: Option<String>,
    }

    impl CloudAuditWorkspaceContextApi for FakeContext {
        fn redact_local_path(&self, value: &str) -> String {
            match &self.redact_home {
                Some(home) if value == home => "~".to_string(),
                Some(home) if value.starts_with(&format!("{home}/")) => {
                    format!("~{}", &value[home.len()..])
                }
                _ => value.to_string(),
            }
        }
        fn safe_machine_name(&self) -> Option<String> {
            self.machine.clone()
        }
    }

    #[derive(Default)]
    struct FakeStore {
        sync_payloads: StdHashMap<String, Value>,
        sync_profile: Option<Value>,
        workspace_id: Option<String>,
    }

    impl SupplyChainStore for FakeStore {
        fn guard_home(&self) -> &Path {
            Path::new("/nonexistent-guard-home")
        }
        fn get_cloud_sync_profile(&self) -> Option<Value> {
            self.sync_profile.clone()
        }
        fn get_cloud_workspace_id(&self) -> Option<String> {
            self.workspace_id.clone()
        }
        fn get_cached_supply_chain_bundle(&self, _workspace_id: &str) -> Option<Value> {
            None
        }
        fn get_sync_payload(&self, key: &str) -> Option<Value> {
            self.sync_payloads.get(key).cloned()
        }
        fn set_sync_payload(&self, _key: &str, _payload: &Value) {}
        fn list_cached_advisories(&self) -> Vec<Value> {
            Vec::new()
        }
        fn list_managed_installs(&self) -> Vec<Value> {
            Vec::new()
        }
        fn record_latest_guard_connect_sync_result(
            &self,
            _status: &str,
            _mode: &str,
            _now: &str,
            _reason: Option<&str>,
        ) {
        }
        fn get_approval_request(&self, _request_id: &str) -> Option<Value> {
            None
        }
        fn resolve_policy_decision_lookup(
            &self,
            _h: &str,
            _a: &str,
            _ah: Option<&str>,
            _w: &str,
            _p: Option<&str>,
            _n: &str,
            _c: bool,
        ) -> crate::local_supply_chain::PolicyDecisionLookup {
            Default::default()
        }
        fn approval_reuse_diagnostic(
            &self,
            _h: &str,
            _a: &str,
            _ah: &str,
            _w: &str,
            _p: Option<&str>,
            _n: &str,
        ) -> (Option<String>, Option<String>) {
            (None, None)
        }
        fn approval_reuse_claim_disposition(&self, _d: &Value) -> Option<String> {
            None
        }
        fn claim_approval_reuse_decision(&self, _d: &Value, _n: &str) -> bool {
            false
        }
        fn claim_local_once_approval(&self, _id: &str, _c: &str, _d: &Value) -> bool {
            false
        }
        fn add_receipt(&self, _receipt: &Value) {}
        fn set_receipt_action_envelope(&self, _receipt_id: &str, _metadata: &Value) {}
        fn add_event(&self, _kind: &str, _payload: &Value, _now: &str) {}
    }

    struct FixtureWorkspace(PathBuf);
    impl FixtureWorkspace {
        fn new(files: &[(&str, &[u8])]) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "cloud-audit-sync-fixture-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            for (rel, bytes) in files {
                let path = dir.join(rel);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, bytes).unwrap();
            }
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for FixtureWorkspace {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // --- URL builders ------------------------------------------------------

    #[test]
    fn batch_url_golden_https() {
        // Oracle: _normalized_supply_chain_batch_url(
        //   "https://sync.hol.example/api/receipts/sync?workspaceId=old&x=1",
        //   "ws-123")
        // -> "https://sync.hol.example/api/supply-chain/evaluate/batch?x=1&workspaceId=ws-123"
        let out = normalized_supply_chain_batch_url(
            "https://sync.hol.example/api/receipts/sync?workspaceId=old&x=1",
            "ws-123",
        )
        .unwrap();
        assert_eq!(
            out,
            "https://sync.hol.example/api/supply-chain/evaluate/batch?x=1&workspaceId=ws-123"
        );
    }

    #[test]
    fn batch_url_preserves_blank_and_repeated_params() {
        // Oracle: keep_blank_values=True keeps bare keys and repeats.
        let out =
            normalized_supply_chain_batch_url("https://h/p?a=1&b&a=2&workspaceId=", "w").unwrap();
        assert_eq!(
            out,
            "https://h/p/supply-chain/evaluate/batch?a=1&b=&a=2&workspaceId=w"
        );
    }

    #[test]
    fn batch_url_non_https_and_schemes() {
        // Oracle: scheme check is not enforced — any scheme flows through;
        // `file:rel` gains `//` because `file` ∈ uses_netloc (3.14).
        assert_eq!(
            normalized_supply_chain_batch_url("http://h/receipts/sync", "w").unwrap(),
            "http://h/supply-chain/evaluate/batch?workspaceId=w"
        );
        assert_eq!(
            normalized_supply_chain_batch_url("ftp://h/a?x=1", "w w").unwrap(),
            "ftp://h/a/supply-chain/evaluate/batch?x=1&workspaceId=w+w"
        );
        // schemeless relative URL — no netloc materialization (scheme "").
        assert_eq!(
            normalized_supply_chain_batch_url("rel/base?q=1", "w").unwrap(),
            "rel/base/supply-chain/evaluate/batch?q=1&workspaceId=w"
        );
        // `file` IS in uses_netloc but the rebuilt path is relative, so
        // `urlunsplit` does NOT re-materialize `//` (oracle-verified).
        assert_eq!(
            normalized_supply_chain_batch_url("file:rel/base", "w").unwrap(),
            "file:rel/base/supply-chain/evaluate/batch?workspaceId=w"
        );
        // custom non-netloc scheme → path joined, no `//`.
        assert_eq!(
            normalized_supply_chain_batch_url("a1:foo/base", "w").unwrap(),
            "a1:foo/base/supply-chain/evaluate/batch?workspaceId=w"
        );
    }

    #[test]
    fn batch_url_edge_inputs() {
        // empty workspace_id → blank value kept (keep_blank_values).
        assert_eq!(
            normalized_supply_chain_batch_url("https://h/p", "").unwrap(),
            "https://h/p/supply-chain/evaluate/batch?workspaceId="
        );
        // trailing slashes stripped before join.
        assert_eq!(
            normalized_supply_chain_batch_url("https://h/p///?x=1", "w").unwrap(),
            "https://h/p/supply-chain/evaluate/batch?x=1&workspaceId=w"
        );
        // receipts/sync NOT at tail is left alone.
        assert_eq!(
            normalized_supply_chain_batch_url("https://h/receipts/sync/extra", "w").unwrap(),
            "https://h/receipts/sync/extra/supply-chain/evaluate/batch?workspaceId=w"
        );
        // C0/space prefix + tab stripped by urlsplit.
        assert_eq!(
            normalized_supply_chain_batch_url("  ht\ttp://h/p", "w").unwrap(),
            "http://h/p/supply-chain/evaluate/batch?workspaceId=w"
        );
        // fragment dropped.
        assert_eq!(
            normalized_supply_chain_batch_url("https://h/p#frag?x=1", "w").unwrap(),
            "https://h/p/supply-chain/evaluate/batch?workspaceId=w"
        );
        // workspaceId injection is urlencoded.
        assert_eq!(
            normalized_supply_chain_batch_url("https://h/p", "w s&id=evil").unwrap(),
            "https://h/p/supply-chain/evaluate/batch?workspaceId=w+s%26id%3Devil"
        );
    }

    #[test]
    fn batch_url_invalid_ipv6_errors() {
        assert_eq!(
            normalized_supply_chain_batch_url("https://[bad]/x", "w"),
            Err("'bad' does not appear to be an IPv4 or IPv6 address".to_string())
        );
        assert_eq!(
            normalized_supply_chain_batch_url("http://[bad", "w"),
            Err("Invalid IPv6 URL".to_string())
        );
        assert_eq!(
            normalized_supply_chain_batch_url("https://[1.2.3.4]/x", "w"),
            Err("An IPv4 address cannot be in brackets".to_string())
        );
    }

    #[test]
    fn batch_job_url_golden() {
        // Oracle: _normalized_supply_chain_batch_job_url(
        //   "https://sync.hol.example/api/receipts/sync",
        //   "ws-1", "job 7/x", page_size=25)
        // -> ".../batch/job%207%2Fx?pageSize=25&workspaceId=ws-1"
        let out = normalized_supply_chain_batch_job_url(
            "https://sync.hol.example/api/receipts/sync",
            "ws-1",
            "job 7/x",
            25,
        )
        .unwrap();
        assert_eq!(
            out,
            "https://sync.hol.example/api/supply-chain/evaluate/batch/job%207%2Fx?workspaceId=ws-1&pageSize=25"
        );
    }

    #[test]
    fn batch_job_url_strips_cursor_and_pagesize() {
        let out = normalized_supply_chain_batch_job_url(
            "https://h/receipts/sync?cursor=abc&pageSize=99&k=1",
            "w",
            "j",
            0,
        )
        .unwrap();
        // page_size=0 → max(0,1)=1
        assert_eq!(
            out,
            "https://h/supply-chain/evaluate/batch/j?k=1&workspaceId=w&pageSize=1"
        );
    }

    #[test]
    fn batch_job_url_odd_page_sizes() {
        // negative → clamped to 1; huge → kept verbatim.
        assert_eq!(
            normalized_supply_chain_batch_job_url("https://h/p", "w", "j", -5).unwrap(),
            "https://h/p/supply-chain/evaluate/batch/j?workspaceId=w&pageSize=1"
        );
        assert_eq!(
            normalized_supply_chain_batch_job_url("https://h/p", "w", "j", 99999).unwrap(),
            "https://h/p/supply-chain/evaluate/batch/j?workspaceId=w&pageSize=99999"
        );
        // empty job_id → trailing slash segment.
        assert_eq!(
            normalized_supply_chain_batch_job_url("https://h/p", "w", "", 2).unwrap(),
            "https://h/p/supply-chain/evaluate/batch/?workspaceId=w&pageSize=2"
        );
    }

    // --- _build_cloud_audit_payload ----------------------------------------

    /// Golden payload generated by the oracle for workspace
    /// `{package.json, package-lock.json}` + one npm inventory item; the
    /// environment-dependent `machine`/`folderPath` are asserted separately.
    #[test]
    fn cloud_audit_payload_golden() {
        let ws = FixtureWorkspace::new(&[
            ("package.json", br#"{"name":"fixture","version":"1.0.0"}"#),
            ("package-lock.json", br#"{"lockfileVersion":3}"#),
        ]);
        let store = FakeStore {
            sync_payloads: [(
                "supply_chain_bundle_summary".to_string(),
                json!({"policy_hash": "ph-abc"}),
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        let context = FakeContext {
            machine: Some("build-host-1".to_string()),
            redact_home: Some(ws.0.to_string_lossy().into_owned()),
        };
        let inventory = vec![json!({
            "direct": true,
            "ecosystem": "npm",
            "name": "left-pad",
            "namespace": "@scope",
            "version": "1.3.0",
            "range": "^1.3.0",
        })];
        let payload = build_cloud_audit_payload(
            &ws.0,
            "ws-9",
            &store,
            &["package.json".to_string()],
            &["package-lock.json".to_string()],
            &inventory,
            "paged",
            None,
            &RealPaths,
            &context,
        )
        .unwrap();

        assert_eq!(payload["harness"], json!("guard-cli"));
        assert_eq!(payload["mode"], json!("paged"));
        // pageSize = min(500, max(len=1,1)) = 1
        assert_eq!(payload["pageSize"], json!(1));
        assert_eq!(payload["policyVersion"], json!("ph-abc"));
        assert_eq!(payload["commandShape"]["packageManager"], json!("npm"));
        assert_eq!(payload["commandShape"]["argCount"], json!(3));
        assert_eq!(payload["commandShape"]["verb"], json!("audit"));
        assert_eq!(payload["commandShape"]["redacted"], json!(true));
        assert_eq!(payload["commandShape"]["flags"], json!([]));
        assert_eq!(payload["packages"][0]["ecosystem"], json!("npm"));
        assert_eq!(payload["packages"][0]["name"], json!("left-pad"));
        assert_eq!(payload["packages"][0]["namespace"], json!("@scope"));
        assert_eq!(payload["packages"][0]["version"], json!("1.3.0"));
        assert_eq!(payload["packages"][0]["range"], json!("^1.3.0"));
        assert_eq!(payload["packages"][0]["direct"], json!(true));

        let lc = &payload["lockfileContext"];
        assert_eq!(lc["dependencyCount"], json!(1));
        assert_eq!(lc["fileName"], json!("package-lock.json"));
        assert!(lc["lockfileHash"].as_str().unwrap().len() == 64);
        assert!(lc["manifestHash"].as_str().unwrap().len() == 64);

        let wc = &payload["workspaceContext"];
        assert_eq!(wc["agent"], json!("guard-cli"));
        assert_eq!(wc["machine"], json!("build-host-1"));
        assert_eq!(wc["folderPath"], json!("~"));
        assert_eq!(wc["packageManager"], json!("npm"));
        assert_eq!(wc["manifestPaths"], json!(["package.json"]));
        assert_eq!(wc["lockfilePaths"], json!(["package-lock.json"]));
        assert_eq!(wc["workspaceName"], json!(dir_name(&ws.0)));
        assert_eq!(wc["codebase"], json!(dir_name(&ws.0)));

        assert!(payload["workspaceFingerprint"].as_str().unwrap().len() == 64);
    }

    #[test]
    fn cloud_audit_payload_full_oracle_match() {
        // Full-JSON equality against an oracle dump recorded on this checkout.
        // Generated via:
        //   python3 gen_fixture.py  (see plan log RTM-019/026)
        // Oracle output:
        //   {"commandShape": {"argCount": 3, "flags": [], "packageManager":
        //   "npm", "redacted": true, "verb": "audit"}, ...}
        let ws = FixtureWorkspace::new(&[
            ("package.json", b"{\"name\":\"o\"}"),
            ("package-lock.json", b"{\"lockfileVersion\":3}"),
            (
                ".git/config",
                b"[remote \"origin\"]\n\turl = https://github.com/Acme/widgets.git\n",
            ),
        ]);
        let store = FakeStore::default();
        let context = FakeContext {
            machine: Some("oracle-host".to_string()),
            redact_home: None,
        };
        let inventory = vec![
            json!({"direct": false, "ecosystem": "npm", "name": "a", "namespace": null}),
            json!({"ecosystem": "npm", "name": "b", "version": "", "range": ">=2"}),
        ];
        let payload = build_cloud_audit_payload(
            &ws.0,
            "ws",
            &store,
            &["package.json".to_string()],
            &["package-lock.json".to_string()],
            &inventory,
            "single",
            Some(7),
            &RealPaths,
            &context,
        )
        .unwrap();
        // `version` key IS emitted for empty-string versions (isinstance check
        // only, no truthiness) — the sibling comment called this out.
        assert_eq!(payload["packages"][1]["version"], json!(""));
        assert_eq!(payload["packages"][1].get("namespace"), Some(&Value::Null));
        // policyVersion falls back when summary missing.
        assert_eq!(payload["policyVersion"], json!("local:none"));
        // pageSize = min(500, max(7,1)) = 7
        assert_eq!(payload["pageSize"], json!(7));
        // codebase resolved from .git/config origin URL (strips .git).
        assert_eq!(
            payload["workspaceContext"]["codebase"],
            json!("Acme/widgets")
        );
        assert_eq!(payload["mode"], json!("single"));
    }

    #[test]
    fn cloud_audit_payload_no_lockfile_drops_context() {
        let ws = FixtureWorkspace::new(&[("package.json", b"{}")]);
        let store = FakeStore::default();
        let context = FakeContext {
            machine: None,
            redact_home: None,
        };
        let payload = build_cloud_audit_payload(
            &ws.0,
            "ws",
            &store,
            &["package.json".to_string()],
            &[],
            &[],
            "paged",
            None,
            &RealPaths,
            &context,
        )
        .unwrap();
        assert!(payload.get("lockfileContext").is_none());
        assert_eq!(payload["pageSize"], json!(1)); // max(len=0,1)
        assert_eq!(payload["commandShape"]["packageManager"], json!("npm"));
        assert_eq!(payload["workspaceContext"]["machine"], Value::Null);
    }

    #[test]
    fn cloud_audit_payload_keyerror_on_missing_fields() {
        let ws = FixtureWorkspace::new(&[]);
        let store = FakeStore::default();
        let context = FakeContext {
            machine: None,
            redact_home: None,
        };
        let inventory = vec![json!({"ecosystem": "npm"})]; // missing "name"
        let err = build_cloud_audit_payload(
            &ws.0,
            "ws",
            &store,
            &[],
            &[],
            &inventory,
            "paged",
            None,
            &RealPaths,
            &context,
        )
        .unwrap_err();
        assert_eq!(err, "'name'");
    }

    #[test]
    fn cloud_audit_payload_sensitive_basenames_never_hashed() {
        // `.env.local` as the "manifest" never reads or hashes; a sensitive
        // lockfile name kills lockfileContext entirely.
        let ws = FixtureWorkspace::new(&[
            ("package.json", b"{}"),
            (".env.local", b"SECRET=1"),
            ("package-lock.json", b"{}"),
        ]);
        let store = FakeStore::default();
        let context = FakeContext {
            machine: None,
            redact_home: None,
        };
        let payload = build_cloud_audit_payload(
            &ws.0,
            "ws",
            &store,
            &[".env.local".to_string()],
            &[".env.local".to_string()],
            &[],
            "paged",
            None,
            &RealPaths,
            &context,
        )
        .unwrap();
        assert!(payload.get("lockfileContext").is_none());
    }

    // --- _normalize_cloud_audit_response -----------------------------------

    #[test]
    fn normalize_response_golden() {
        // Oracle: _normalize_cloud_audit_response(
        //   {"decision": "block", "packages": [{"a":1}, "x", {"b":2}],
        //    "reasons": [{"r":1}], "enforcement": "", "entitlementState": None,
        //    "processedCount": 4, "totalPackages": 9, "status": "completed",
        //    "workspaceId": "ws-1"})
        let response: Map<String, Value> = serde_json::from_value(json!({
            "decision": "block",
            "packages": [{"a": 1}, "x", {"b": 2}],
            "reasons": [{"r": 1}],
            "enforcement": "",
            "entitlementState": null,
            "processedCount": 4,
            "totalPackages": 9,
            "status": "completed",
            "workspaceId": "ws-1"
        }))
        .unwrap();
        let out = normalize_cloud_audit_response(&response);
        assert_eq!(out["decision"], json!("block"));
        assert_eq!(out["packages"], json!([{"a": 1}, {"b": 2}]));
        assert_eq!(out["reasons"], json!([{"r": 1}]));
        // falsy enforcement falls to default
        assert_eq!(out["enforcement"], json!("premium_cloud"));
        assert_eq!(out["entitlement_state"], json!("premium"));
        assert_eq!(out["cache_status"], json!("miss"));
        assert_eq!(out["processed_count"], json!(4));
        assert_eq!(out["total_packages"], json!(9));
        assert_eq!(out["status"], json!("completed"));
        assert_eq!(out["workspace_id"], json!("ws-1"));
    }

    #[test]
    fn normalize_response_defaults_and_nonstr_str() {
        // empty response → all defaults; non-str scalars coerce via str().
        let empty = Map::new();
        let out = normalize_cloud_audit_response(&empty);
        assert_eq!(out["decision"], json!("monitor"));
        assert_eq!(out["packages"], json!([]));
        assert_eq!(out["reasons"], json!([]));
        assert_eq!(out["processed_count"], json!(0));
        assert_eq!(out["workspace_id"], json!(""));

        let weird: Map<String, Value> = serde_json::from_value(json!({
            "decision": true,           // str(True) -> "True"
            "status": 3.5,              // str(3.5) -> "3.5"
            "workspaceId": 0,           // falsy -> ""
            "processedCount": "12",     // not int -> 0
            "totalPackages": 4.0,       // float not int -> 0
            "packages": "notalist",
        }))
        .unwrap();
        let out = normalize_cloud_audit_response(&weird);
        assert_eq!(out["decision"], json!("True"));
        assert_eq!(out["status"], json!("3.5"));
        assert_eq!(out["workspace_id"], json!(""));
        assert_eq!(out["processed_count"], json!(0));
        assert_eq!(out["total_packages"], json!(0));
        assert_eq!(out["packages"], json!([]));
    }

    // --- _resolve_next_refresh_at -------------------------------------------

    #[test]
    fn next_refresh_at_explicit_wins() {
        let summary: Map<String, Value> = serde_json::from_value(json!({
            "next_refresh_at": "2030-01-02T03:04:05Z"
        }))
        .unwrap();
        assert_eq!(
            resolve_next_refresh_at(Some(&summary), Some("2020-01-01T00:00:00Z")),
            Some("2030-01-02T03:04:05+00:00".to_string())
        );
        // explicit present but unparseable → falls through to synced_at + 15m
        let bad: Map<String, Value> =
            serde_json::from_value(json!({"next_refresh_at": "not-a-date"})).unwrap();
        assert_eq!(
            resolve_next_refresh_at(Some(&bad), Some("2020-01-01T00:00:00+00:00")),
            Some("2020-01-01T00:15:00+00:00".to_string())
        );
        // blank explicit (whitespace) → treated as absent by _string_value
        let blank: Map<String, Value> =
            serde_json::from_value(json!({"next_refresh_at": "   "})).unwrap();
        assert_eq!(
            resolve_next_refresh_at(Some(&blank), Some("2020-01-01T00:00:00Z")),
            Some("2020-01-01T00:15:00+00:00".to_string())
        );
        // no synced_at → None
        assert_eq!(resolve_next_refresh_at(Some(&bad), None), None);
        // offset normalized to UTC +00:00
        let off: Map<String, Value> =
            serde_json::from_value(json!({"next_refresh_at": "2030-01-02T05:04:05+02:00"}))
                .unwrap();
        assert_eq!(
            resolve_next_refresh_at(Some(&off), None),
            Some("2030-01-02T03:04:05+00:00".to_string())
        );
    }

    // --- _should_use_cloud_workspace_audit -----------------------------------

    #[test]
    fn cloud_audit_gate_matrix() {
        let premium: Map<String, Value> =
            serde_json::from_value(json!({"bundle": {"tier": " Premium "}})).unwrap();
        let basic: Map<String, Value> =
            serde_json::from_value(json!({"bundle": {"tier": "basic"}})).unwrap();
        let no_bundle = Map::new();
        let bundle_not_dict: Map<String, Value> =
            serde_json::from_value(json!({"bundle": "premium"})).unwrap();

        let full = FakeStore {
            sync_profile: Some(json!({"user": "u"})),
            workspace_id: Some("ws".to_string()),
            ..Default::default()
        };
        assert!(should_use_cloud_workspace_audit(&full, &premium));
        assert!(!should_use_cloud_workspace_audit(&full, &basic));
        assert!(!should_use_cloud_workspace_audit(&full, &no_bundle));
        assert!(!should_use_cloud_workspace_audit(&full, &bundle_not_dict));

        let no_profile = FakeStore {
            workspace_id: Some("ws".to_string()),
            ..Default::default()
        };
        assert!(!should_use_cloud_workspace_audit(&no_profile, &premium));

        let no_ws = FakeStore {
            sync_profile: Some(json!({})),
            ..Default::default()
        };
        assert!(!should_use_cloud_workspace_audit(&no_ws, &premium));

        // non-str tier (None → "") → false; numeric → str(5) != premium.
        let weird_tier: Map<String, Value> =
            serde_json::from_value(json!({"bundle": {"tier": 5}})).unwrap();
        assert!(!should_use_cloud_workspace_audit(&full, &weird_tier));
        // C0-wrapped tier — Python strip() removes \x1f; .lower() applies.
        let c0_tier: Map<String, Value> =
            serde_json::from_value(json!({"bundle": {"tier": "\u{1f}PREMIUM\u{1c}"}})).unwrap();
        assert!(should_use_cloud_workspace_audit(&full, &c0_tier));
    }

    // --- urlsplit/urlunsplit primitive oracle cases -------------------------

    #[test]
    fn urlsplit_primitives() {
        // Oracle outputs recorded against Python 3.14.3 urlsplit.
        type UrlSplitResult<'a> = (&'a str, &'a str, &'a str, &'a str, &'a str);
        let cases: &[(&str, UrlSplitResult<'_>)] = &[
            ("1:foo", ("", "", "1:foo", "", "")),
            ("a1:foo", ("a1", "", "foo", "", "")),
            ("+a:foo", ("", "", "+a:foo", "", "")),
            ("a+b-c.d:x", ("a+b-c.d", "", "x", "", "")),
            ("ab cd:x", ("", "", "ab cd:x", "", "")),
            ("//host/p?x=1", ("", "host", "/p", "x=1", "")),
            (
                "http://h/p?a=1&b&a=2#frag",
                ("http", "h", "/p", "a=1&b&a=2", "frag"),
            ),
            ("mailto:x@y", ("mailto", "", "x@y", "", "")),
            ("file:rel", ("file", "", "rel", "", "")),
            ("file:///abs", ("file", "", "/abs", "", "")),
            ("file:rel?q=1", ("file", "", "rel", "q=1", "")),
            ("javascript:x", ("javascript", "", "x", "", "")),
            ("custom-scheme://h/p", ("custom-scheme", "h", "/p", "", "")),
            ("\u{1}http://h/p", ("http", "h", "/p", "", "")),
            ("  http://h/p", ("http", "h", "/p", "", "")),
            ("ht\ttp://h/p", ("http", "h", "/p", "", "")),
            ("http://h//p//", ("http", "h", "//p//", "", "")),
            ("git+ssh://h/o/r.git", ("git+ssh", "h", "/o/r.git", "", "")),
            ("ssh://h/p", ("ssh", "h", "/p", "", "")),
            ("HTTP://H/P?Q=1", ("http", "H", "/P", "Q=1", "")),
            (
                "HtTpS://User@H:8080/p",
                ("https", "User@H:8080", "/p", "", ""),
            ),
            ("http://h/p?#f", ("http", "h", "/p", "", "f")),
            ("http://h/p#a?b=1", ("http", "h", "/p", "", "a?b=1")),
            ("http://h", ("http", "h", "", "", "")),
        ];
        for (input, (scheme, netloc, path, query, fragment)) in cases {
            let split = urlsplit(input).unwrap_or_else(|e| panic!("{input:?}: {e}"));
            assert_eq!(
                (
                    split.scheme.as_str(),
                    split.netloc.as_str(),
                    split.path.as_str(),
                    split.query.as_str(),
                    split.fragment.as_str()
                ),
                (*scheme, *netloc, *path, *query, *fragment),
                "urlsplit({input:?})"
            );
        }
    }

    #[test]
    fn urlunsplit_primitives() {
        // Oracle urlunsplit tuples (3.14 netloc re-materialization).
        assert_eq!(
            urlunsplit("file", "", "rel/batch", "x=1", ""),
            "file:rel/batch?x=1"
        );
        assert_eq!(
            urlunsplit("a1", "", "foo/supply-chain/evaluate/batch", "x=1", ""),
            "a1:foo/supply-chain/evaluate/batch?x=1"
        );
        // netloc-empty + path already `//p` → `//` re-prepended (None-netloc branch).
        assert_eq!(urlunsplit("", "", "//p", "", ""), "////p");
        assert_eq!(urlunsplit("https", "", "//p", "", ""), "https:////p");
        // any-scheme uses_netloc `a1` in set → `//` materialized.
        assert_eq!(urlunsplit("a1", "h", "", "", ""), "a1://h");
        assert_eq!(urlunsplit("", "", "rel/batch", "x=1", ""), "rel/batch?x=1");
        assert_eq!(
            urlunsplit("file", "", "/abs/batch", "", ""),
            "file:///abs/batch"
        );
        assert_eq!(
            urlunsplit("javascript", "", "x/supply-chain/evaluate/batch", "", ""),
            "javascript:x/supply-chain/evaluate/batch"
        );
        // empty netloc + empty url + netloc scheme → "scheme://"
        assert_eq!(urlunsplit("https", "", "", "", ""), "https://");
    }

    #[test]
    fn parse_qsl_primitives() {
        assert_eq!(
            parse_qsl("a=1&b&a=2&k="),
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "".to_string()),
                ("a".to_string(), "2".to_string()),
                ("k".to_string(), "".to_string()),
            ]
        );
        assert_eq!(
            parse_qsl("a=1&;&&b=2"),
            vec![
                ("a".to_string(), "1".to_string()),
                (";".to_string(), "".to_string()),
                ("b".to_string(), "2".to_string()),
            ]
        );
        assert_eq!(
            parse_qsl("a+b=c+d&k=%20&e=a%C3%A9"),
            vec![
                ("a b".to_string(), "c d".to_string()),
                ("k".to_string(), " ".to_string()),
                ("e".to_string(), "a\u{e9}".to_string()),
            ]
        );
        assert_eq!(
            parse_qsl("a=%GG&b=%C3"),
            vec![
                ("a".to_string(), "%GG".to_string()),
                ("b".to_string(), "\u{fffd}".to_string()),
            ]
        );
        assert_eq!(
            parse_qsl("=v&k=&=x"),
            vec![
                ("".to_string(), "v".to_string()),
                ("k".to_string(), "".to_string()),
                ("".to_string(), "x".to_string()),
            ]
        );
        assert!(parse_qsl("").is_empty());
    }

    #[test]
    fn json_dumps_oracle() {
        // Oracle: json.dumps(..., ensure_ascii=True, sort_keys=True,
        // separators=(",", ":")) — keys sorted by codepoint, \uXXXX escapes.
        assert_eq!(
            json_dumps(&json!({"k": "é\u{1f}x\"\\\n"})),
            "{\"k\":\"\\u00e9\\u001fx\\\"\\\\\\n\"}"
        );
        assert_eq!(
            json_dumps(&json!({"A": 1, "a": 2, "1": 3})),
            "{\"1\":3,\"A\":1,\"a\":2}"
        );
        // surrogate pair for astral chars
        assert_eq!(
            json_dumps(&json!({"k": "🙂"})),
            "{\"k\":\"\\ud83d\\ude42\"}"
        );
    }

    #[test]
    fn python_splitlines_oracle() {
        // CPython splitlines boundary set incl. \v \f \x1c \x85.
        assert_eq!(python_splitlines("a\nb"), vec!["a", "b"]);
        assert_eq!(python_splitlines("a\r\nb"), vec!["a", "b"]);
        assert_eq!(python_splitlines("a\rb"), vec!["a", "b"]);
        assert_eq!(
            python_splitlines("a\u{b}b\u{c}c\u{1c}d\u{85}e\u{2028}f"),
            vec!["a", "b", "c", "d", "e", "f"]
        );
        assert_eq!(python_splitlines("a\n"), vec!["a"]);
        assert_eq!(python_splitlines("\n"), vec![""]);
        assert!(python_splitlines("").is_empty());
    }
}
