//! Proof that a plain web fetch or search is low risk on its own.
//!
//! The intrinsic result for such a call is `allow`, so the installed
//! `new_network_domain_action` floor (never this module) decides whether it
//! proceeds, warns, reviews or blocks. Anything outside the narrow shape
//! below keeps the intrinsic network review.

use super::extract::GenericSignals;
use super::tools::tool_matches;
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
    })
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
}
