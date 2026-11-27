//! Registrable domains from the pinned public-suffix snapshot (PRD D5).
//!
//! The rules are compiled at build time by `guard-command-catalog-data` from
//! its `public-suffix/` snapshot, whose file digest is pinned. A `site-group` grant is offered only
//! when [`registrable_domain`] returns a value: never for an IP literal, a single-label host, a
//! host that is itself a public suffix, or when the embedded rules fail to decode.

use std::collections::HashSet;
use std::sync::OnceLock;

/// Longest host Guard groups; anything longer is not grouped.
const MAX_HOST_CHARS: usize = 253;

struct Rules {
    normal: HashSet<String>,
    wildcard: HashSet<String>,
    exception: HashSet<String>,
}

fn rules() -> Option<&'static Rules> {
    static RULES: OnceLock<Option<Rules>> = OnceLock::new();
    RULES.get_or_init(load).as_ref()
}

#[cfg(not(guard_source_bootstrap))]
fn load() -> Option<Rules> {
    let bytes = crate::packaged_blob::decode(
        guard_command_catalog_data::PUBLIC_SUFFIX_RULES_ZST,
        guard_command_catalog_data::PUBLIC_SUFFIX_RULES_LEN,
        guard_command_catalog_data::PUBLIC_SUFFIX_RULES_SHA256,
    );
    parse(std::str::from_utf8(&bytes).ok()?)
}

/// The source bootstrap build embeds no snapshot, so no host is grouped.
#[cfg(guard_source_bootstrap)]
fn load() -> Option<Rules> {
    None
}

fn parse(text: &str) -> Option<Rules> {
    let mut parsed = Rules {
        normal: HashSet::new(),
        wildcard: HashSet::new(),
        exception: HashSet::new(),
    };
    for rule in text.lines().filter(|line| !line.is_empty()) {
        if let Some(name) = rule.strip_prefix('!') {
            parsed.exception.insert(name.to_owned());
        } else if let Some(name) = rule.strip_prefix("*.") {
            parsed.wildcard.insert(name.to_owned());
        } else {
            parsed.normal.insert(rule.to_owned());
        }
    }
    (!parsed.normal.is_empty()).then_some(parsed)
}

/// True when the embedded snapshot decoded, so `site-group` can be offered at all.
pub fn public_suffix_available() -> bool {
    rules().is_some()
}

/// The upstream version label of the embedded snapshot, empty when none is embedded.
pub fn public_suffix_version() -> &'static str {
    #[cfg(not(guard_source_bootstrap))]
    {
        guard_command_catalog_data::PUBLIC_SUFFIX_VERSION
    }
    #[cfg(guard_source_bootstrap)]
    {
        ""
    }
}

/// The registrable domain (public suffix plus one label) of an ASCII host, lowercase, without a
/// trailing dot. `None` for an IP literal, a single-label host, a host that is itself a public
/// suffix, a malformed host, or when the snapshot is unavailable.
pub fn registrable_domain(host: &str) -> Option<String> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty()
        || host.len() > MAX_HOST_CHARS
        || host.starts_with('[')
        || host.parse::<std::net::Ipv4Addr>().is_ok()
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
    {
        return None;
    }
    let host = host.to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|label| label.is_empty()) {
        return None;
    }
    let suffix_labels = suffix_label_count(rules()?, &labels);
    if suffix_labels >= labels.len() {
        return None;
    }
    Some(labels[labels.len() - suffix_labels - 1..].join("."))
}

/// Number of labels in the prevailing public-suffix rule for `labels` (the PSL algorithm): an
/// exception rule wins and drops its leftmost label; otherwise the longest normal or wildcard rule
/// wins; otherwise the implicit `*` rule (one label).
fn suffix_label_count(rules: &Rules, labels: &[&str]) -> usize {
    let count = labels.len();
    for start in 0..count {
        if rules.exception.contains(&labels[start..].join(".")) {
            return count - start - 1;
        }
    }
    let mut longest = 1;
    for start in 0..count {
        let candidate = labels[start..].join(".");
        let wildcard = start + 1 < count && rules.wildcard.contains(&labels[start + 1..].join("."));
        if rules.normal.contains(&candidate) || wildcard {
            longest = longest.max(count - start);
            break;
        }
    }
    longest
}

#[cfg(test)]
#[path = "public_suffix_tests.rs"]
mod tests;
