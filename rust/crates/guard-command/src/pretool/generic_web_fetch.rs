//! Proof that a plain web fetch or search is low risk on its own.
//!
//! The intrinsic result for such a call is `allow`, so the installed
//! `new_network_domain_action` floor (never this module) decides whether it
//! proceeds, warns, reviews or blocks. Anything outside the narrow shape
//! below keeps the intrinsic network review.

use super::extract::GenericSignals;
use super::tools::tool_matches;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use regex::Regex;
use std::sync::LazyLock;
use url::{Host, Url};

const MAX_URL_BYTES: usize = 2048;
const CREDENTIAL_QUERY_TERMS: [&str; 8] = [
    "token",
    "key",
    "secret",
    "password",
    "auth",
    "sig",
    "session",
    "credential",
];
const PRIVATE_SUFFIXES: [&str; 9] = [
    ".local",
    ".internal",
    ".localhost",
    ".localdomain",
    ".lan",
    ".home",
    ".home.arpa",
    ".intranet",
    ".corp",
];

// Wildcard DNS services that resolve any name to the address spelled inside
// it, so a public-looking name can still point at loopback or a LAN host.
const REBINDING_SUFFIXES: [&str; 9] = [
    ".nip.io",
    ".sslip.io",
    ".xip.io",
    ".localtest.me",
    ".lvh.me",
    ".traefik.me",
    ".local.gd",
    ".vcap.me",
    ".localhost.direct",
];

// How many encoding layers (percent, base64, hex) a URL part is unwrapped
// through before it is screened. Real exfiltration rarely stacks more than
// two; each layer is cheap because parts are bounded by `MAX_URL_BYTES`.
const MAX_DECODE_DEPTH: usize = 3;
const MIN_ENCODED_PART_BYTES: usize = 16;
// A host label this long that is pure hex and decodes to printable text is
// data spelled into DNS, not a name. Random hex of this length decodes to all
// printable bytes well under once in ten thousand.
const MIN_HEX_TEXT_LABEL_BYTES: usize = 20;

/// Credential formats whose shape alone identifies them, so finding one in a
/// URL means the request carries a credential to that host. Sample values
/// count too: a request cannot be shown to send only a placeholder.
static STRUCTURED_CREDENTIAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?:^|[^A-Za-z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?:$|[^A-Za-z0-9])",
        r"|gh[pousr]_[A-Za-z0-9]{36,}",
        r"|github_pat_[A-Za-z0-9_]{22,}",
        r"|gl(?:pat|dt|rt|ptt|cbt|ft|imt|oas|soat)-[A-Za-z0-9_-]{20,}",
        r"|xox[abposr]-[A-Za-z0-9-]{10,}",
        r"|(?:sk|rk)_live_[A-Za-z0-9]{16,}",
        r"|sk-(?:ant|proj)-[A-Za-z0-9_-]{20,}",
        r"|AIza[0-9A-Za-z_-]{35}",
        r"|-----BEGIN[A-Z ]*PRIVATE KEY-----",
        r"|eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}",
        r"|[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@",
        r#"|"type"\s*:\s*"service_account""#,
        r#"|"private_key(?:_id)?"\s*:"#,
    ))
    .expect("structured credential pattern compiles")
});

fn text_carries_credential(text: &str) -> bool {
    STRUCTURED_CREDENTIAL.is_match(text)
        || !guard_scanner::secret_detection::scan_secret_text(text, "", "url", None, 1)
            .findings
            .is_empty()
}

/// Decoded bytes as text the credential screen can read. Control characters
/// become spaces rather than discarding the reading, so a NUL or escape byte
/// placed before a credential cannot hide it.
fn decoded_text(bytes: Vec<u8>) -> Option<String> {
    let text = String::from_utf8(bytes).ok()?;
    Some(
        text.chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect(),
    )
}

/// The readings of one URL part under each encoding it could be spelled in.
fn decoded_readings(part: &str) -> Vec<String> {
    let mut readings = Vec::new();
    if part.contains('%') {
        if let Ok(decoded) = percent_encoding::percent_decode_str(part).decode_utf8() {
            if decoded != part {
                readings.push(decoded.into_owned());
            }
        }
    }
    if part.len() < MIN_ENCODED_PART_BYTES {
        return readings;
    }
    if part.len().is_multiple_of(2) && part.bytes().all(|b| b.is_ascii_hexdigit()) {
        if let Some(text) = hex::decode(part).ok().and_then(decoded_text) {
            readings.push(text);
        }
    }
    if part
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_' | b'='))
    {
        for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
            if let Some(text) = engine.decode(part).ok().and_then(decoded_text) {
                readings.push(text);
                break;
            }
        }
    }
    readings
}

fn part_carries_credential(part: &str, depth: usize) -> bool {
    if text_carries_credential(part) {
        return true;
    }
    depth < MAX_DECODE_DEPTH
        && decoded_readings(part)
            .iter()
            .any(|reading| part_carries_credential(reading, depth + 1))
}

/// A host label that is hex-encoded text, such as a secret spelled into a
/// subdomain so the DNS lookup itself carries it out.
fn hex_text_label(label: &str) -> bool {
    label.len() >= MIN_HEX_TEXT_LABEL_BYTES
        && label.len().is_multiple_of(2)
        && label.bytes().all(|b| b.is_ascii_hexdigit())
        && hex::decode(label).is_ok_and(|bytes| bytes.iter().all(|b| (0x20..0x7f).contains(b)))
}

/// True when any part of the URL, read raw or through up to
/// `MAX_DECODE_DEPTH` layers of percent, hex or base64 encoding, carries a
/// credential, or a host label spells encoded text.
fn url_carries_credential(raw: &str, url: &Url) -> bool {
    if let Some(Host::Domain(name)) = url.host() {
        // The parser lowercases the host, which hides case-sensitive formats
        // such as an AWS key id, so the host is also read as it was written.
        if name
            .split('.')
            .chain(raw_host(raw).split('.'))
            .any(|label| hex_text_label(label) || part_carries_credential(label, 0))
        {
            return true;
        }
    }
    let mut parts: Vec<String> = url
        .path_segments()
        .map(|segments| segments.map(str::to_owned).collect())
        .unwrap_or_default();
    // A connection string spans several segments (`/postgres://user:pass@db`),
    // so the whole path is read as one part too.
    parts.push(url.path().to_owned());
    for (key, value) in url.query_pairs() {
        parts.push(key.into_owned());
        parts.push(value.into_owned());
    }
    if let Some(query) = url.query() {
        parts.push(query.to_owned());
    }
    if let Some(fragment) = url.fragment() {
        parts.push(fragment.to_owned());
    }
    parts.iter().any(|part| part_carries_credential(part, 0))
}

/// The host of a URL as it was written: the authority after `://`, without
/// user info or port.
fn raw_host(raw: &str) -> &str {
    let authority = raw
        .split_once("://")
        .map_or(raw, |(_, rest)| rest)
        .split(['/', '?', '#', '\\'])
        .next()
        .unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    host.rsplit_once(':').map_or(host, |(name, _)| name)
}

/// A label that spells an address, such as `127` in `127.0.0.1.example.test`
/// or `10-0-0-5` in `10-0-0-5.example.test`.
fn address_label(label: &str) -> bool {
    !label.is_empty()
        && label
            .split('-')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
}

fn is_fetch_tool(tool: &str) -> bool {
    tool_matches(tool, &["web_fetch", "webfetch", "fetch_web"])
}

fn is_search_tool(tool: &str) -> bool {
    tool_matches(tool, &["web_search", "websearch"])
}

fn public_dns_host(host: &Host<&str>) -> bool {
    let Host::Domain(name) = host else {
        return false;
    };
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    name.contains('.')
        && !name.starts_with('.')
        && name != "localhost"
        && !PRIVATE_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
        && !REBINDING_SUFFIXES
            .iter()
            .any(|suffix| name.ends_with(suffix) || name == suffix[1..])
        && !name.split('.').any(address_label)
}

pub(in crate::pretool) fn plain_public_url(raw: &str) -> bool {
    if raw.len() > MAX_URL_BYTES || raw.trim() != raw {
        return false;
    }
    let Ok(url) = Url::parse(raw) else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || !url.host().as_ref().is_some_and(public_dns_host)
    {
        return false;
    }
    !url.query_pairs().any(|(key, _)| {
        let key = key.to_ascii_lowercase();
        CREDENTIAL_QUERY_TERMS.iter().any(|term| key.contains(term))
    }) && !url_carries_credential(raw, &url)
}

/// True only for a bounded GET-style fetch or search of public web content.
pub(super) fn plain_public_web_request(signals: &GenericSignals) -> bool {
    let Some(tool) = signals.tool_name.as_deref() else {
        return false;
    };
    let fetch = is_fetch_tool(tool);
    if !(fetch || is_search_tool(tool))
        || signals.sensitive_target
        || signals.request_body_or_method
        || signals.command.is_some()
        || signals.package_present
        || !signals.path_values.is_empty()
        || (fetch && signals.url_values.is_empty())
    {
        return false;
    }
    signals.url_values.iter().all(|raw| plain_public_url(raw))
}

#[cfg(test)]
mod tests {
    use super::plain_public_url;

    #[test]
    fn public_urls_pass_and_risky_classes_do_not() {
        assert!(plain_public_url("https://status.example.test/api/health"));
        assert!(plain_public_url("http://docs.example.test/a?page=2"));
        for risky in [
            "https://user:pw@status.example.test/",
            "https://user@status.example.test/",
            "ftp://status.example.test/",
            "file:///tmp/w/app",
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "http://169.254.169.254/latest/meta-data",
            "http://2130706433/",
            "http://localhost/",
            "http://metadata.google.internal/",
            "http://printer.local/",
            "http://app.example.internal/",
            "http://intranet/",
            "http://127.0.0.1.nip.io/",
            "http://10-0-0-5.sslip.io/",
            "http://app.localtest.me/",
            "http://lvh.me/",
            "http://127.0.0.1.example.test/",
            "http://10-0-0-5.example.test/",
            "https://status.example.test/?api_token=x",
            "https://status.example.test/?Key=x",
            "https://status.example.test/?sig=x",
            "https://status.example.test/?sessionid=x",
            "not a url",
        ] {
            assert!(!plain_public_url(risky), "{risky}");
        }
        let long = format!("https://status.example.test/{}", "a".repeat(2100));
        assert!(!plain_public_url(&long));
    }

    /// Credential-shaped values are assembled at run time so the source holds
    /// no literal that a secret scanner would read as a leaked key.
    fn joined(parts: &[&str]) -> String {
        parts.concat()
    }

    fn hex(text: &str) -> String {
        text.bytes().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn urls_that_carry_a_credential_are_not_plain() {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        use base64::Engine;
        let aws = joined(&["AK", "IA", "Q3EGUWZ7", "XMPLK4RT"]);
        let github = joined(&["gh", "p_", &"a1B2c3D4e5".repeat(4)]);
        let jwt = joined(&[
            "ey",
            "JhbGciOiJIUzI1NiJ9",
            ".",
            "ey",
            "JzdWIiOiIxMjM0NTY3ODkwIn0",
            ".",
            "c2lnbmF0dXJlX3ZhbHVlX2hlcmU",
        ]);
        let dsn = joined(&[
            "postgres",
            "://admin:",
            "s3cr3tPassw0rd",
            "@db.example.test:5432/app",
        ]);
        let gcp = joined(&["{\"type\":\"service", "_account\",\"project_id\":\"demo\"}"]);
        let gitlab = joined(&["gl", "dt-", &"Zx9Yw8Vu7T".repeat(2)]);
        for risky in [
            format!("https://collect.example.test/?d={}", STANDARD.encode(&aws)),
            format!(
                "https://collect.example.test/u/{}",
                URL_SAFE_NO_PAD.encode(&github)
            ),
            format!("https://collect.example.test/?t={jwt}"),
            format!(
                "https://collect.example.test/?c={}",
                URL_SAFE_NO_PAD.encode(&jwt)
            ),
            format!(
                "https://collect.example.test/?db={}",
                url::form_urlencoded::byte_serialize(dsn.as_bytes()).collect::<String>()
            ),
            format!("https://collect.example.test/?sa={}", STANDARD.encode(&gcp)),
            format!("https://collect.example.test/?x={gitlab}"),
            format!("https://collect.example.test/?h={}", hex(&github)),
            format!(
                "https://collect.example.test/#{}",
                STANDARD.encode(STANDARD.encode(&aws))
            ),
            format!("https://{}.collect.example.test/", hex("HOME=/home/dev")),
            format!("https://collect.example.test/?d=00{}", hex(&aws)),
            format!(
                "https://collect.example.test/?d={}",
                STANDARD.encode([b"\0", aws.as_bytes()].concat())
            ),
            format!("https://{aws}.collect.example.test/"),
            format!(
                "https://collect.example.test/{}",
                joined(&[
                    "postgres:",
                    "//admin:",
                    "pw4fixture",
                    "@db.example.test/app"
                ])
            ),
        ] {
            assert!(!plain_public_url(&risky), "{risky}");
        }
    }

    #[test]
    fn ordinary_encoded_urls_stay_plain() {
        for benign in [
            "https://docs.example.test/guide/getting-started#install",
            "https://registry.example.test/package/left-pad/v/1.3.0",
            "https://cdn.example.test/assets/app.3f9a1c2b7e4d5f60.js",
            "https://git.example.test/org/repo/commit/0123456789abcdef0123456789abcdef01234567",
            "https://search.example.test/?q=rust+base64+decode&page=2",
            "https://img.example.test/?url=aHR0cHM6Ly9leGFtcGxlLmNvbS9pbWFnZS5wbmc",
            "https://deadbeefcafe.example.test/",
            "https://example.test/blog/2026/11/why-we-moved-to-rust",
            "https://api.example.test/v1/items?id=550e8400-e29b-41d4-a716-446655440000",
        ] {
            assert!(plain_public_url(benign), "{benign}");
        }
    }
}
