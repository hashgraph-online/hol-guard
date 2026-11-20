//! Update prompts for installed plugins that publish checked releases on HOL.
//!
//! Guard downloads the public release index (listings whose authors record
//! releases with the HOL Plugin Release workflow) and this module compares
//! each installed plugin's version with it on the device. Nothing about the
//! installed plugins is sent anywhere.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{json, Value};

use crate::installed::InstalledPlugin;
use crate::report::{match_listing, IndexEntry};
use crate::{valid_version, MAX_ENTRIES};

/// The file in the Guard home that holds dismissed prompts.
pub const DISMISSALS_FILE: &str = "plugin-updates.json";
const MAX_DISMISSALS: usize = 500;

/// One release in the public release index.
#[derive(Debug, Clone)]
pub struct IndexedRelease {
    pub version: String,
    pub max_severity: Option<String>,
    pub fixes_security: bool,
}

/// A listing's checked releases, newest first.
#[derive(Debug, Clone)]
pub struct ReleaseIndexEntry {
    pub slug: String,
    pub releases_url: String,
    pub releases: Vec<IndexedRelease>,
}

/// A prompt the user dismissed for one listing's latest version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dismissal {
    pub slug: String,
    pub version: String,
}

/// Reads the public release index leniently: an entry without a slug, URL
/// or release list is skipped, a release without a string version is
/// skipped, and an optional field of the wrong type is treated as absent,
/// so one malformed release never hides the prompts for every other plugin.
pub fn parse_release_index(entries: &[Value]) -> Vec<ReleaseIndexEntry> {
    entries
        .iter()
        .filter_map(|entry| {
            Some(ReleaseIndexEntry {
                slug: entry.get("slug")?.as_str()?.to_owned(),
                releases_url: entry
                    .get("releasesUrl")?
                    .as_str()
                    .filter(|url| printable_https_url(url))?
                    .to_owned(),
                releases: entry
                    .get("releases")?
                    .as_array()?
                    .iter()
                    .filter_map(|release| {
                        Some(IndexedRelease {
                            version: release.get("version")?.as_str()?.to_owned(),
                            max_severity: release
                                .get("maxSeverity")
                                .and_then(Value::as_str)
                                .map(str::to_owned),
                            fixes_security: release
                                .get("fixesSecurity")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                        })
                    })
                    .collect(),
            })
        })
        .collect()
}

/// An `https://` URL without whitespace or control characters, safe to print.
fn printable_https_url(url: &str) -> bool {
    url.len() <= 512 && url.starts_with("https://") && url.chars().all(|c| c.is_ascii_graphic())
}

/// The dismissals saved in the Guard home; empty when the file is missing
/// or unreadable, and entries of the wrong shape are dropped.
pub fn read_dismissals(guard_home: &Path) -> Vec<Dismissal> {
    let Ok(text) = fs::read_to_string(guard_home.join(DISMISSALS_FILE)) else {
        return Vec::new();
    };
    let Ok(payload) = serde_json::from_str::<Value>(&text) else {
        return Vec::new();
    };
    let items: Vec<Dismissal> = payload
        .get("dismissed")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|item| {
            Some(Dismissal {
                slug: item.get("slug")?.as_str()?.to_owned(),
                version: item.get("version")?.as_str()?.to_owned(),
            })
        })
        .collect();
    let skip = items.len().saturating_sub(MAX_DISMISSALS);
    items.into_iter().skip(skip).collect()
}

/// Replaces the saved dismissals. Each write goes through its own temporary
/// file, so two commands running at once never share one, and the file is
/// swapped in whole.
pub fn write_dismissals(guard_home: &Path, dismissals: &[Dismissal]) -> Result<(), String> {
    let unwritable = |_| "plugin_updates_dismissals_unwritable".to_owned();
    fs::create_dir_all(guard_home).map_err(unwritable)?;
    let skip = dismissals.len().saturating_sub(MAX_DISMISSALS);
    let body = serde_json::to_vec(&json!({ "dismissed": &dismissals[skip..] }))
        .map_err(|_| "plugin_updates_dismissals_unwritable".to_owned())?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let temporary = guard_home.join(format!(
        "{DISMISSALS_FILE}.{}.{nanos}.tmp",
        std::process::id()
    ));
    let result = fs::write(&temporary, body)
        .and_then(|()| fs::rename(&temporary, guard_home.join(DISMISSALS_FILE)));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(unwritable)
}

/// Saves a dismissal for one listing's latest version, replacing any
/// earlier one for that listing.
pub fn dismiss(guard_home: &Path, slug: &str, version: &str) -> Result<(), String> {
    let mut dismissals: Vec<Dismissal> = read_dismissals(guard_home)
        .into_iter()
        .filter(|item| item.slug != slug)
        .collect();
    dismissals.push(Dismissal {
        slug: slug.to_owned(),
        version: version.to_owned(),
    });
    write_dismissals(guard_home, &dismissals)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpdatePrompt {
    pub slug: String,
    pub runtime: &'static str,
    #[serde(rename = "installedVersion")]
    pub installed_version: String,
    #[serde(rename = "latestVersion")]
    pub latest_version: String,
    pub urgent: bool,
    /// `security_fix` when a newer release fixes a high or critical finding,
    /// `installed_high_severity` when the installed release had one, else None.
    pub reason: Option<&'static str>,
    #[serde(rename = "releasesUrl")]
    pub releases_url: String,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct UpdateCheck {
    pub updates: Vec<UpdatePrompt>,
    pub dismissed: usize,
}

#[derive(Debug, PartialEq, Eq)]
enum Identifier<'a> {
    Numeric(u64),
    Text(&'a str),
}

#[derive(Debug, PartialEq, Eq)]
struct Version<'a> {
    core: [u64; 3],
    pre: Vec<Identifier<'a>>,
}

/// `MAJOR.MINOR.PATCH[-pre][+build]`, with an optional leading `v`; None otherwise.
/// Anything outside the portal's version shape, such as a terminal control
/// sequence in a release index, is not a version.
fn parse_version(value: &str) -> Option<Version<'_>> {
    if !valid_version(value, 64) {
        return None;
    }
    let value = value.strip_prefix('v').unwrap_or(value);
    let value = value.split('+').next()?;
    let (core, pre) = match value.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (value, None),
    };
    let mut parts = core.split('.');
    let mut numbers = [0u64; 3];
    for number in &mut numbers {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *number = part.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    let pre = match pre {
        None => Vec::new(),
        Some(pre) => pre
            .split('.')
            .map(|part| {
                if part.is_empty() {
                    None
                } else if part.bytes().all(|b| b.is_ascii_digit()) {
                    part.parse().ok().map(Identifier::Numeric)
                } else {
                    Some(Identifier::Text(part))
                }
            })
            .collect::<Option<Vec<_>>>()?,
    };
    Some(Version { core: numbers, pre })
}

fn compare_identifiers(left: &Identifier<'_>, right: &Identifier<'_>) -> Ordering {
    match (left, right) {
        (Identifier::Numeric(a), Identifier::Numeric(b)) => a.cmp(b),
        (Identifier::Numeric(_), Identifier::Text(_)) => Ordering::Less,
        (Identifier::Text(_), Identifier::Numeric(_)) => Ordering::Greater,
        (Identifier::Text(a), Identifier::Text(b)) => a.cmp(b),
    }
}

/// Semantic-version precedence; None when either side is not a semantic version.
pub fn compare_versions(left: &str, right: &str) -> Option<Ordering> {
    let (left, right) = (parse_version(left)?, parse_version(right)?);
    let ordering = left.core.cmp(&right.core).then_with(|| {
        match (left.pre.is_empty(), right.pre.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => left
                .pre
                .iter()
                .zip(&right.pre)
                .map(|(a, b)| compare_identifiers(a, b))
                .find(|ordering| ordering.is_ne())
                .unwrap_or_else(|| left.pre.len().cmp(&right.pre.len())),
        }
    });
    Some(ordering)
}

fn high_severity(release: &IndexedRelease) -> bool {
    matches!(release.max_severity.as_deref(), Some("high" | "critical"))
}

fn prompt_for(
    plugin: &InstalledPlugin,
    slug: &str,
    entry: &ReleaseIndexEntry,
) -> Option<UpdatePrompt> {
    let installed = plugin.version.as_deref()?;
    let newer: Vec<&IndexedRelease> = entry
        .releases
        .iter()
        .filter(|release| compare_versions(&release.version, installed) == Some(Ordering::Greater))
        .collect();
    let latest = newer.iter().copied().reduce(|best, release| {
        if compare_versions(&release.version, &best.version) == Some(Ordering::Greater) {
            release
        } else {
            best
        }
    })?;
    let installed_release = entry
        .releases
        .iter()
        .find(|release| compare_versions(&release.version, installed) == Some(Ordering::Equal));
    let reason = if newer.iter().any(|release| release.fixes_security) {
        Some("security_fix")
    } else if installed_release.is_some_and(high_severity) {
        Some("installed_high_severity")
    } else {
        None
    };
    Some(UpdatePrompt {
        slug: slug.to_owned(),
        runtime: plugin.runtime,
        installed_version: installed.to_owned(),
        latest_version: latest.version.clone(),
        urgent: reason.is_some(),
        reason,
        releases_url: entry.releases_url.clone(),
    })
}

/// Whether `candidate` is a newer install of the same listing than `current`.
/// A known version beats an unknown one.
fn newer_install(candidate: &InstalledPlugin, current: &InstalledPlugin) -> bool {
    match (candidate.version.as_deref(), current.version.as_deref()) {
        (Some(left), Some(right)) => compare_versions(left, right) == Some(Ordering::Greater),
        (Some(_), None) => true,
        _ => false,
    }
}

/// One prompt per (listing, runtime) whose newest installed version is older
/// than a checked release, urgent prompts first, minus the ones the user
/// dismissed for that latest version. A runtime can keep several cached
/// versions of one plugin; only the newest decides the prompt.
pub fn check_updates(
    index: &[IndexEntry],
    releases: &[ReleaseIndexEntry],
    installed: &[InstalledPlugin],
    dismissed: &[Dismissal],
) -> UpdateCheck {
    let by_slug: BTreeMap<&str, &ReleaseIndexEntry> = releases
        .iter()
        .map(|entry| (entry.slug.as_str(), entry))
        .collect();
    let mut newest: BTreeMap<(&str, &'static str), &InstalledPlugin> = BTreeMap::new();
    for plugin in installed {
        let Some(listing) = match_listing(index, plugin) else {
            continue;
        };
        if !by_slug.contains_key(listing.slug.as_str()) {
            continue;
        }
        newest
            .entry((listing.slug.as_str(), plugin.runtime))
            .and_modify(|current| {
                if newer_install(plugin, current) {
                    *current = plugin;
                }
            })
            .or_insert(plugin);
    }
    let mut check = UpdateCheck::default();
    for prompt in newest
        .into_iter()
        .filter_map(|((slug, _), plugin)| prompt_for(plugin, slug, by_slug[slug]))
    {
        let hidden = dismissed.iter().any(|dismissal| {
            dismissal.slug == prompt.slug
                && compare_versions(&dismissal.version, &prompt.latest_version)
                    == Some(Ordering::Equal)
        });
        if hidden {
            check.dismissed += 1;
        } else {
            check.updates.push(prompt);
        }
    }
    check.updates.sort_by_key(|prompt| !prompt.urgent);
    check.updates.truncate(MAX_ENTRIES);
    check
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listing(slug: &str, repository: &str) -> IndexEntry {
        IndexEntry {
            slug: slug.to_owned(),
            repository: Some(repository.to_owned()),
            manifest_name: None,
            plugin_root: None,
        }
    }

    fn installed(repository: &str, version: Option<&str>) -> InstalledPlugin {
        InstalledPlugin {
            runtime: "claude-code",
            name: Some("demo".to_owned()),
            version: version.map(str::to_owned),
            repository: Some(repository.to_owned()),
        }
    }

    fn release(version: &str, severity: &str, fixes_security: bool) -> IndexedRelease {
        IndexedRelease {
            version: version.to_owned(),
            max_severity: Some(severity.to_owned()),
            fixes_security,
        }
    }

    fn releases(list: Vec<IndexedRelease>) -> Vec<ReleaseIndexEntry> {
        vec![ReleaseIndexEntry {
            slug: "demo".to_owned(),
            releases_url: "https://hol.org/plugins/demo/releases".to_owned(),
            releases: list,
        }]
    }

    const REPO: &str = "https://github.com/acme/demo";

    #[test]
    fn compares_semantic_versions() {
        assert_eq!(compare_versions("1.10.0", "1.9.9"), Some(Ordering::Greater));
        assert_eq!(
            compare_versions("v1.2.3", "1.2.3+build"),
            Some(Ordering::Equal)
        );
        assert_eq!(
            compare_versions("1.0.0-beta.2", "1.0.0-beta.11"),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare_versions("1.0.0-rc.1", "1.0.0"),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare_versions("1.0.0-alpha", "1.0.0-1"),
            Some(Ordering::Greater)
        );
        assert_eq!(compare_versions("1.0", "1.0.0"), None);
        assert_eq!(compare_versions("latest", "1.0.0"), None);
    }

    #[test]
    fn prompts_for_a_newer_checked_release() {
        let check = check_updates(
            &[listing("demo", REPO)],
            &releases(vec![
                release("1.2.0", "low", false),
                release("1.1.0", "none", false),
            ]),
            &[installed(REPO, Some("1.1.0"))],
            &[],
        );
        assert_eq!(check.updates.len(), 1);
        let prompt = &check.updates[0];
        assert_eq!(prompt.latest_version, "1.2.0");
        assert!(!prompt.urgent);
        assert_eq!(prompt.reason, None);
    }

    #[test]
    fn marks_security_fixes_and_high_severity_installs_urgent() {
        let fix = check_updates(
            &[listing("demo", REPO)],
            &releases(vec![
                release("1.2.0", "low", true),
                release("1.1.0", "critical", false),
            ]),
            &[installed(REPO, Some("1.0.0"))],
            &[],
        );
        assert_eq!(fix.updates[0].reason, Some("security_fix"));
        let installed_high = check_updates(
            &[listing("demo", REPO)],
            &releases(vec![
                release("1.2.0", "high", false),
                release("1.1.0", "high", false),
            ]),
            &[installed(REPO, Some("1.1.0"))],
            &[],
        );
        assert_eq!(
            installed_high.updates[0].reason,
            Some("installed_high_severity")
        );
        assert!(installed_high.updates[0].urgent);
    }

    #[test]
    fn skips_current_unversioned_unlisted_and_dismissed_plugins() {
        let index = [listing("demo", REPO)];
        let list = releases(vec![release("1.2.0", "none", false)]);
        let current = check_updates(&index, &list, &[installed(REPO, Some("1.2.0"))], &[]);
        assert!(current.updates.is_empty());
        let unversioned = check_updates(&index, &list, &[installed(REPO, None)], &[]);
        assert!(unversioned.updates.is_empty());
        let unlisted = check_updates(
            &index,
            &list,
            &[installed("https://github.com/acme/other", Some("0.1.0"))],
            &[],
        );
        assert!(unlisted.updates.is_empty());
        let dismissal = Dismissal {
            slug: "demo".to_owned(),
            version: "1.2.0".to_owned(),
        };
        let dismissed = check_updates(
            &index,
            &list,
            &[installed(REPO, Some("1.0.0"))],
            &[dismissal],
        );
        assert!(dismissed.updates.is_empty());
        assert_eq!(dismissed.dismissed, 1);
        let newer = releases(vec![
            release("1.3.0", "none", false),
            release("1.2.0", "none", false),
        ]);
        let reprompt = check_updates(
            &index,
            &newer,
            &[installed(REPO, Some("1.0.0"))],
            &[Dismissal {
                slug: "demo".to_owned(),
                version: "1.2.0".to_owned(),
            }],
        );
        assert_eq!(reprompt.updates[0].latest_version, "1.3.0");
    }

    #[test]
    fn an_older_cached_copy_does_not_prompt_when_the_latest_is_installed() {
        let index = [listing("demo", REPO)];
        let list = releases(vec![
            release("1.3.0", "none", false),
            release("1.2.0", "none", false),
        ]);
        for order in [["1.2.0", "1.3.0"], ["1.3.0", "1.2.0"]] {
            let cached = order.map(|version| installed(REPO, Some(version)));
            assert!(check_updates(&index, &list, &cached, &[])
                .updates
                .is_empty());
        }
        let stale = [
            installed(REPO, Some("1.1.0")),
            installed(REPO, Some("1.2.0")),
        ];
        let check = check_updates(&index, &list, &stale, &[]);
        assert_eq!(check.updates.len(), 1);
        assert_eq!(check.updates[0].installed_version, "1.2.0");
    }

    #[test]
    fn a_malformed_release_field_drops_only_that_field_or_release() {
        let entries: Vec<Value> = serde_json::from_str(
            r#"[
                {"slug":"demo","releasesUrl":"https://hol.org/r","releases":[
                    {"version":"1.3.0","maxSeverity":7,"fixesSecurity":null},
                    {"version":2},
                    {"version":"1.2.0","maxSeverity":"high","fixesSecurity":true}
                ]},
                {"slug":"broken","releases":[]},
                "not an object"
            ]"#,
        )
        .unwrap();
        let parsed = parse_release_index(&entries);
        assert_eq!(parsed.len(), 1);
        let versions: Vec<_> = parsed[0]
            .releases
            .iter()
            .map(|release| {
                (
                    release.version.as_str(),
                    release.max_severity.as_deref(),
                    release.fixes_security,
                )
            })
            .collect();
        assert_eq!(
            versions,
            [("1.3.0", None, false), ("1.2.0", Some("high"), true)]
        );
    }

    #[test]
    fn control_characters_never_reach_a_prompt() {
        assert_eq!(compare_versions("1.2.0-\u{1b}[2J", "1.0.0"), None);
        let entries: Vec<Value> = serde_json::from_str(
            r#"[
                {"slug":"a","releasesUrl":"https://hol.org/r\u001b[2J","releases":[]},
                {"slug":"b","releasesUrl":"javascript:alert(1)","releases":[]},
                {"slug":"c","releasesUrl":"https://hol.org/r","releases":[]}
            ]"#,
        )
        .unwrap();
        let slugs: Vec<_> = parse_release_index(&entries)
            .into_iter()
            .map(|entry| entry.slug)
            .collect();
        assert_eq!(slugs, ["c"]);
        let index = [listing("demo", REPO)];
        let list = releases(vec![release("1.3.0-\u{1b}[2J", "none", false)]);
        let check = check_updates(&index, &list, &[installed(REPO, Some("1.0.0"))], &[]);
        assert!(check.updates.is_empty());
    }

    #[test]
    fn dismissals_round_trip_and_replace_earlier_ones_for_a_listing() {
        let home = std::env::temp_dir().join(format!(
            "guard-plugin-updates-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(read_dismissals(&home).is_empty());
        dismiss(&home, "demo", "1.2.0").unwrap();
        dismiss(&home, "other", "0.1.0").unwrap();
        dismiss(&home, "demo", "1.3.0").unwrap();
        let saved = read_dismissals(&home);
        assert_eq!(
            saved,
            [
                Dismissal {
                    slug: "other".to_owned(),
                    version: "0.1.0".to_owned()
                },
                Dismissal {
                    slug: "demo".to_owned(),
                    version: "1.3.0".to_owned()
                },
            ]
        );
        let leftovers = fs::read_dir(&home)
            .unwrap()
            .filter(|item| {
                item.as_ref()
                    .is_ok_and(|item| item.file_name() != DISMISSALS_FILE)
            })
            .count();
        assert_eq!(leftovers, 0);
        write_dismissals(&home, &[]).unwrap();
        assert!(read_dismissals(&home).is_empty());
        fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn an_unwritable_home_reports_an_error() {
        let file =
            std::env::temp_dir().join(format!("guard-plugin-updates-file-{}", std::process::id()));
        fs::write(&file, b"").unwrap();
        assert_eq!(
            dismiss(&file.join("home"), "demo", "1.0.0"),
            Err("plugin_updates_dismissals_unwritable".to_owned())
        );
        fs::remove_file(&file).unwrap();
    }
}
