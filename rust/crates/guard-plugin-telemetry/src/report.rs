//! Matching installed plugins to public listings and building report entries.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::installed::InstalledPlugin;
use crate::MAX_ENTRIES;

/// One public listing from the HOL index.
#[derive(Debug, Clone, Deserialize)]
pub struct IndexEntry {
    pub slug: String,
    #[serde(default)]
    pub repository: Option<String>,
    #[serde(default, rename = "manifestName")]
    pub manifest_name: Option<String>,
    #[serde(default, rename = "pluginRoot")]
    pub plugin_root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReportEntry {
    pub slug: String,
    pub runtime: &'static str,
    pub version: Option<String>,
    pub key: String,
}

/// `https://github.com/owner/repo` lower-cased and without `.git`, matching
/// the portal's normalization exactly; anything else is None.
pub fn normalize_repository_url(value: &str) -> Option<String> {
    let lowered = value.trim().to_ascii_lowercase();
    let mut rest = lowered.as_str();
    rest = rest.strip_prefix("git+").unwrap_or(rest);
    rest = rest
        .strip_prefix("https://")
        .or_else(|| rest.strip_prefix("http://"))?;
    rest = rest.strip_prefix("www.").unwrap_or(rest);
    let rest = rest.split(['#', '?']).next().unwrap_or("");
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let mut parts = rest.split('/');
    let host = parts.next()?;
    let owner = parts.next()?;
    let repo = parts.next()?;
    if parts.next().is_some() || !matches!(host, "github.com" | "gitlab.com") {
        return None;
    }
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    let ok = |part: &str| !part.is_empty() && !part.chars().any(char::is_whitespace);
    if !ok(owner) || !ok(repo) {
        return None;
    }
    Some(format!("https://{host}/{owner}/{repo}"))
}

/// The single listing an installed plugin belongs to, or None.
///
/// A plugin matches only by its manifest repository. When several listings
/// share that repository (a monorepo), the manifest name must pick exactly
/// one. A plugin with no repository never matches, so a private plugin that
/// happens to share a listed name is never reported.
pub(crate) fn match_listing<'a>(
    index: &'a [IndexEntry],
    plugin: &InstalledPlugin,
) -> Option<&'a IndexEntry> {
    let repository = plugin.repository.as_deref()?;
    let candidates: Vec<&IndexEntry> = index
        .iter()
        .filter(|entry| {
            entry
                .repository
                .as_deref()
                .and_then(normalize_repository_url)
                .as_deref()
                == Some(repository)
        })
        .collect();
    match candidates.as_slice() {
        [only] => Some(only),
        [] => None,
        many => {
            let name = plugin.name.as_deref()?;
            let named: Vec<&&IndexEntry> = many
                .iter()
                .filter(|entry| entry.manifest_name.as_deref() == Some(name))
                .collect();
            if named.len() == 1 {
                Some(named[0])
            } else {
                None
            }
        }
    }
}

fn counting_key(secret: &[u8], week: &str, slug: &str, runtime: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(format!("{week}:{slug}:{runtime}").as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Orders dotted numeric versions numerically (`1.10.0` > `1.9.0`), a release
/// above its prereleases, and anything else as text.
fn compare_versions(a: &str, b: &str) -> Ordering {
    fn parts(version: &str) -> (Option<Vec<u64>>, bool) {
        let version = version.strip_prefix('v').unwrap_or(version);
        let core = version.split('+').next().unwrap_or(version);
        let (release, prerelease) = match core.split_once('-') {
            Some((release, _)) => (release, true),
            None => (core, false),
        };
        let numbers = release
            .split('.')
            .map(|part| part.parse::<u64>().ok())
            .collect::<Option<Vec<_>>>();
        (numbers, prerelease)
    }
    match (parts(a), parts(b)) {
        ((Some(x), x_pre), (Some(y), y_pre)) => x.cmp(&y).then(y_pre.cmp(&x_pre)),
        _ => a.cmp(b),
    }
}

/// Whether `candidate` should replace `current` as the version to report:
/// a known version beats an unknown one, and a higher version beats a lower.
fn is_newer(candidate: Option<&str>, current: Option<&str>) -> bool {
    match (candidate, current) {
        (Some(_), None) => true,
        (Some(a), Some(b)) => compare_versions(a, b) == Ordering::Greater,
        (None, _) => false,
    }
}

/// One entry per (listing, runtime) among the installed plugins that match a
/// public listing, capped at `MAX_ENTRIES`. When a runtime's cache holds
/// several versions of a plugin, the highest is reported.
pub fn build_report(
    index: &[IndexEntry],
    installed: &[InstalledPlugin],
    secret: &[u8],
    week: &str,
) -> Vec<ReportEntry> {
    let mut entries: BTreeMap<(String, &'static str), ReportEntry> = BTreeMap::new();
    for plugin in installed {
        let Some(listing) = match_listing(index, plugin) else {
            continue;
        };
        let entry = entries
            .entry((listing.slug.clone(), plugin.runtime))
            .or_insert_with(|| ReportEntry {
                slug: listing.slug.clone(),
                runtime: plugin.runtime,
                version: plugin.version.clone(),
                key: counting_key(secret, week, &listing.slug, plugin.runtime),
            });
        if is_newer(plugin.version.as_deref(), entry.version.as_deref()) {
            entry.version = plugin.version.clone();
        }
    }
    entries.into_values().take(MAX_ENTRIES).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listing(slug: &str, repository: Option<&str>, name: Option<&str>) -> IndexEntry {
        IndexEntry {
            slug: slug.to_owned(),
            repository: repository.map(str::to_owned),
            manifest_name: name.map(str::to_owned),
            plugin_root: None,
        }
    }

    fn plugin(
        runtime: &'static str,
        repository: Option<&str>,
        name: Option<&str>,
    ) -> InstalledPlugin {
        InstalledPlugin {
            runtime,
            name: name.map(str::to_owned),
            version: Some("1.0.0".to_owned()),
            repository: repository.map(str::to_owned),
        }
    }

    #[test]
    fn normalizes_like_the_portal() {
        assert_eq!(
            normalize_repository_url("git+https://www.GitHub.com/Octo/Repo.git").as_deref(),
            Some("https://github.com/octo/repo")
        );
        assert_eq!(
            normalize_repository_url("https://github.com/o/r/").as_deref(),
            Some("https://github.com/o/r")
        );
        assert_eq!(
            normalize_repository_url("https://github.com/o/r/tree/main"),
            None
        );
        assert_eq!(normalize_repository_url("https://example.com/o/r"), None);
        assert_eq!(normalize_repository_url("git@github.com:o/r.git"), None);
    }

    #[test]
    fn reports_only_listed_plugins_and_never_matches_on_name_alone() {
        let index = vec![
            listing("octo/pdf", Some("https://github.com/octo/pdf"), Some("pdf")),
            listing("mono/a", Some("https://github.com/mono/tools"), Some("a")),
            listing("mono/b", Some("https://github.com/mono/tools"), Some("b")),
        ];
        let installed = vec![
            plugin("codex", Some("https://github.com/octo/pdf"), Some("pdf")),
            plugin(
                "claude-code",
                Some("https://github.com/octo/pdf"),
                Some("pdf"),
            ),
            plugin("codex", Some("https://github.com/mono/tools"), Some("b")),
            plugin(
                "codex",
                Some("https://github.com/mono/tools"),
                Some("unknown"),
            ),
            plugin("codex", None, Some("pdf")),
            plugin(
                "codex",
                Some("https://github.com/private/thing"),
                Some("secret-tool"),
            ),
        ];
        let entries = build_report(&index, &installed, &[7u8; 32], "2026-W43");
        let pairs: Vec<(&str, &str)> = entries
            .iter()
            .map(|e| (e.slug.as_str(), e.runtime))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("mono/b", "codex"),
                ("octo/pdf", "claude-code"),
                ("octo/pdf", "codex")
            ]
        );
        let wire = serde_json::to_string(&entries).unwrap();
        assert!(
            !wire.contains("private") && !wire.contains("secret-tool") && !wire.contains("unknown")
        );
    }

    #[test]
    fn keys_change_with_week_listing_runtime_and_secret() {
        let a = counting_key(&[1u8; 32], "2026-W43", "octo/pdf", "codex");
        assert_eq!(a.len(), 64);
        assert_ne!(a, counting_key(&[1u8; 32], "2026-W44", "octo/pdf", "codex"));
        assert_ne!(
            a,
            counting_key(&[1u8; 32], "2026-W43", "octo/other", "codex")
        );
        assert_ne!(
            a,
            counting_key(&[1u8; 32], "2026-W43", "octo/pdf", "cursor")
        );
        assert_ne!(a, counting_key(&[2u8; 32], "2026-W43", "octo/pdf", "codex"));
        assert_eq!(a, counting_key(&[1u8; 32], "2026-W43", "octo/pdf", "codex"));
    }

    #[test]
    fn reports_the_highest_cached_version() {
        let index = vec![listing(
            "octo/pdf",
            Some("https://github.com/octo/pdf"),
            None,
        )];
        let at = |version: Option<&str>| InstalledPlugin {
            version: version.map(str::to_owned),
            ..plugin(
                "claude-code",
                Some("https://github.com/octo/pdf"),
                Some("pdf"),
            )
        };
        let installed = vec![
            at(None),
            at(Some("1.10.0")),
            at(Some("1.9.0")),
            at(Some("1.10.0-rc.1")),
        ];
        let entries = build_report(&index, &installed, &[7u8; 32], "2026-W43");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].version.as_deref(), Some("1.10.0"));
    }
}
