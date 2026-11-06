//! `hol-guard plugin install|uninstall`: turn a listing's install spec into
//! the argument vectors each runtime's own CLI takes.
//!
//! The spec comes from the HOL registry and is untrusted. It carries only
//! identifiers (repository, marketplace and plugin names), never command
//! text. Every identifier is checked here and the argv is built from fixed
//! program names, so a listing cannot make Guard run anything else. The Kit
//! still runs nothing itself: the CLI shows the plan and runs it only on
//! `--apply`, one runtime at a time.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// v2 adds HOL's security result, a scanned commit to pin and the Skills
/// CLI version. Fields v2 does not know are ignored, never turned into
/// commands, so HOL can add fields without breaking shipped copies.
pub const SPEC_SCHEMA_V2: &str = "hol.plugin-install-spec.v2";
/// The newest spec this Kit reads; the CLI asks HOL for it.
pub const SPEC_VERSION: u32 = 2;

/// Runtimes the spec may name, in the order the plan lists them.
const RUNTIMES: [&str; 3] = ["claude-code", "codex", "agent-skills"];

/// A scan older than this many days asks before installing.
const STALE_SCAN_DAYS: i64 = 30;
/// A trust score below this asks before installing.
const LOW_TRUST: f64 = 60.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Install,
    Uninstall,
}

#[derive(Debug, Deserialize)]
struct Spec {
    slug: String,
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    repository: Option<String>,
    #[serde(rename = "listingUrl")]
    listing_url: String,
    #[serde(default, rename = "trustScore")]
    trust_score: Option<f64>,
    targets: Vec<Target>,
    #[serde(default)]
    manual: Vec<String>,
    #[serde(default)]
    security: Option<SpecSecurity>,
    #[serde(default)]
    installable: Option<bool>,
    #[serde(default, rename = "blockedReason")]
    blocked_reason: Option<String>,
    #[serde(default, rename = "skillsCli")]
    skills_cli: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Target {
    runtime: String,
    #[serde(default)]
    marketplace: Option<Marketplace>,
    #[serde(default)]
    plugin: Option<String>,
    #[serde(default)]
    repository: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Marketplace {
    repository: String,
    name: String,
    /// The commit HOL scanned, when the marketplace is the listing's repository.
    #[serde(default, rename = "ref")]
    commit: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SpecSecurity {
    verdict: String,
    #[serde(default, rename = "scannedAt")]
    scanned_at: Option<String>,
    #[serde(default, rename = "scannedRef")]
    scanned_ref: Option<String>,
    #[serde(default)]
    findings: Option<Findings>,
    #[serde(default)]
    reasons: Vec<String>,
    #[serde(default, rename = "reportUrl")]
    report_url: Option<String>,
}

#[derive(Debug, Default, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub struct Findings {
    #[serde(default)]
    pub critical: u32,
    #[serde(default)]
    pub high: u32,
    #[serde(default)]
    pub medium: u32,
    #[serde(default)]
    pub low: u32,
}

/// Whether Guard installs, asks first, or refuses.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Gate {
    Pass,
    Confirm,
    Block,
}

/// HOL's security result as Guard read it, and Guard's decision.
#[derive(Debug, Serialize)]
pub struct Security {
    pub gate: Gate,
    /// HOL's verdict, or `unscanned` when the spec carries none.
    pub verdict: String,
    /// Why Guard asks or refuses, written by Guard.
    pub reasons: Vec<String>,
    /// HOL's own reasons, shown after Guard's.
    pub hol_reasons: Vec<String>,
    pub scanned_at: Option<String>,
    pub scanned_ref: Option<String>,
    pub findings: Option<Findings>,
    pub report_url: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Step {
    pub runtime: &'static str,
    /// The program each command starts with; the CLI checks it is on PATH.
    pub program: &'static str,
    /// True when the program was found on this machine.
    pub available: bool,
    /// False when Guard only prints the commands and never runs them.
    pub automatic: bool,
    pub commands: Vec<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
    /// `plugin@marketplace`, as the runtime names the install.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marketplace: Option<String>,
    /// The commit HOL scanned. Codex is pinned with `--ref` when the
    /// marketplace is added. Claude Code cannot take a commit on that
    /// command, so the CLI compares Claude Code's installed commit with
    /// this one after the install and rolls back a mismatch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_commit: Option<String>,
    /// Uninstall only: removes the marketplace Guard added for this listing.
    /// The CLI runs it only when no other plugin from it is installed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remove_marketplace: Option<Vec<String>>,
    /// Uninstall only: the repository the recorded marketplace came from, so
    /// the CLI leaves one the user has since pointed somewhere else.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marketplace_repository: Option<String>,
}

/// On an uninstall plan, offer to remove each marketplace Guard added
/// (`owned` names those runtimes) instead of leaving it registered.
pub fn offer_marketplace_removal(plan: &mut Plan, owned: &[String]) {
    for step in &mut plan.steps {
        let Some(name) = step.marketplace.as_deref() else {
            continue;
        };
        if owned.iter().any(|runtime| runtime == step.runtime) {
            step.remove_marketplace = Some(argv(&[
                step.program,
                "plugin",
                "marketplace",
                "remove",
                name,
            ]));
            step.note = Some(
                "Guard added this marketplace, so it removes it too unless another plugin uses it.",
            );
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Plan {
    pub action: &'static str,
    pub slug: String,
    pub name: String,
    pub version: Option<String>,
    pub repository: Option<String>,
    pub listing_url: String,
    pub trust_score: Option<f64>,
    /// Only for installs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<Security>,
    pub steps: Vec<Step>,
    /// Runtimes the listing supports that Guard cannot install for you.
    pub manual: Vec<String>,
}

/// GitHub `owner/name`: owner 1–39 of `[A-Za-z0-9-]` not starting with `-`,
/// name 1–100 of `[A-Za-z0-9._-]` not starting with `.` or `-`.
pub fn valid_repository(value: &str) -> bool {
    let Some((owner, name)) = value.split_once('/') else {
        return false;
    };
    let owner_ok = (1..=39).contains(&owner.len())
        && !owner.starts_with('-')
        && owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    let name_ok = (1..=100).contains(&name.len())
        && !name.starts_with(['.', '-'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    owner_ok && name_ok
}

/// Marketplace and plugin entry names: 1–128 of `[A-Za-z0-9._-]`, starting
/// with a letter or digit, so none can be read as a flag.
pub fn valid_identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub(crate) fn valid_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
}

/// Unicode format characters that can reorder or hide text on a terminal:
/// bidi embeddings, overrides and isolates, zero-width characters, the BOM,
/// interlinear annotation and tag characters.
fn is_hidden_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

/// Text Guard prints: no control or hidden format characters.
fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.chars().any(|c| c.is_control() || is_hidden_format(c))
}

const INVALID: &str = "plugin_kit_install_spec_invalid";
const UNSUPPORTED: &str = "plugin_kit_install_spec_unsupported";

/// Where listing pages live. HOL's own site unless the user pointed Guard at
/// another install-spec endpoint (a local portal in tests), in which case the
/// CLI passes that endpoint's origin and listings must live there instead.
pub const HOL_ORIGIN: &str = "https://hol.org/";

/// An origin the CLI may pass: `http(s)://host[:port]/`, nothing after it.
pub(crate) fn valid_origin(value: &str) -> bool {
    let Some(rest) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    else {
        return false;
    };
    let Some(authority) = rest.strip_suffix('/') else {
        return false;
    };
    (1..=255).contains(&authority.len())
        && authority
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
}

/// Hosts an install-spec override may reach over plain http: this machine,
/// or the host a container runs on.
const LOCAL_HOSTS: [&str; 4] = ["localhost", "127.0.0.1", "[::1]", "host.docker.internal"];

/// Checks an `HOL_GUARD_PLUGIN_SPEC_URL` override and returns the origin its
/// listings must use: `scheme://host[:port]/`, lowercase, with a default port
/// left out so `:443` and no port compare equal. The CLI appends `?slug=` to
/// the value, so it may carry no query, fragment or credentials, and only
/// https leaves the machine.
pub(crate) fn endpoint_origin(value: &str) -> Option<String> {
    let printable = value
        .bytes()
        .all(|b| (0x21..=0x7e).contains(&b) && !matches!(b, b'?' | b'#' | b'@' | b'\\'));
    if value.len() > 2048 || !printable {
        return None;
    }
    let (scheme, rest) = value.split_once("://")?;
    let default_port = match scheme {
        "https" => 443,
        "http" => 80,
        _ => return None,
    };
    let authority = rest
        .split_once('/')
        .map_or(rest, |(authority, _)| authority);
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (literal, after) = inner.split_once(']')?;
        if literal.is_empty() || !literal.bytes().all(|b| b.is_ascii_hexdigit() || b == b':') {
            return None;
        }
        (format!("[{}]", literal.to_ascii_lowercase()), after)
    } else {
        let end = authority.find(':').unwrap_or(authority.len());
        let host = &authority[..end];
        let labels_ok = host.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
        if !labels_ok {
            return None;
        }
        (host.to_ascii_lowercase(), &authority[end..])
    };
    let port = match port {
        "" => default_port,
        port => {
            let digits = port.strip_prefix(':')?;
            if !(1..=5).contains(&digits.len()) || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let number: u32 = digits.parse().ok()?;
            if !(1..=65535).contains(&number) {
                return None;
            }
            number
        }
    };
    if scheme == "http" && !LOCAL_HOSTS.contains(&host.as_str()) {
        return None;
    }
    Some(if port == default_port {
        format!("{scheme}://{host}/")
    } else {
        format!("{scheme}://{host}:{port}/")
    })
}

fn under_origin(url: &str, origin: &str) -> bool {
    url.strip_prefix(origin)
        .is_some_and(|rest| valid_text(rest, 300) && !rest.contains(char::is_whitespace))
}

/// A full git commit id, as HOL records the scanned commit.
fn valid_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `x.y.z`, digits only: the Skills CLI version pinned into `npx skills@x.y.z`.
fn valid_release(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| (1..=6).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit()))
}

/// Days since 1970-01-01 for a `YYYY-MM-DD` date, optionally followed by a
/// `T` and an RFC 3339 time (the date is enough to age a scan in days).
/// Impossible dates such as 2026-02-31 are refused.
pub(crate) fn days_from_date(value: &str) -> Option<i64> {
    let date = value.get(..10)?;
    let time_ok = match value.get(10..)? {
        "" => true,
        time => {
            time.starts_with('T')
                && time.len() <= 30
                && time[1..]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || matches!(b, b':' | b'.' | b'+' | b'-' | b'Z'))
        }
    };
    let mut parts = date.split('-');
    let (year, month, day) = (parts.next()?, parts.next()?, parts.next()?);
    let digits =
        |part: &str, len: usize| part.len() == len && part.bytes().all(|b| b.is_ascii_digit());
    if !time_ok || !digits(year, 4) || !digits(month, 2) || !digits(day, 2) {
        return None;
    }
    let (year, month, day): (i64, i64, i64) =
        (year.parse().ok()?, month.parse().ok()?, day.parse().ok()?);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if !(1..=month_days).contains(&day) {
        return None;
    }
    // Howard Hinnant's days_from_civil.
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

/// Days since 1970-01-01 by the system clock.
pub fn today() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| (elapsed.as_secs() / 86_400) as i64)
}

/// v1 copies parse strictly; a v1 spec carries only these keys.
fn v1_shape(spec: &Value) -> bool {
    fn only(value: &Value, keys: &[&str]) -> bool {
        value
            .as_object()
            .is_some_and(|object| object.keys().all(|key| keys.contains(&key.as_str())))
    }
    only(
        spec,
        &[
            "schema",
            "slug",
            "name",
            "version",
            "repository",
            "listingUrl",
            "trustScore",
            "targets",
            "manual",
        ],
    ) && spec["targets"].as_array().is_none_or(|targets| {
        targets.iter().all(|target| {
            only(target, &["runtime", "marketplace", "plugin", "repository"])
                && (target["marketplace"].is_null()
                    || only(&target["marketplace"], &["repository", "name"]))
        })
    })
}

/// `hol.plugin-install-spec.v<N>` -> N.
fn schema_version(schema: &str) -> Option<u32> {
    let digits = schema.strip_prefix("hol.plugin-install-spec.v")?;
    if digits.is_empty() || digits.len() > 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn parse(spec: Value, origin: &str) -> Result<Spec, String> {
    let version = spec["schema"]
        .as_str()
        .and_then(schema_version)
        .ok_or_else(|| UNSUPPORTED.to_owned())?;
    if version > SPEC_VERSION || version == 0 {
        return Err(UNSUPPORTED.to_owned());
    }
    if version == 1 && !v1_shape(&spec) {
        return Err(INVALID.to_owned());
    }
    let spec: Spec = serde_json::from_value(spec).map_err(|_| INVALID.to_owned())?;
    let listing_ok = under_origin(&spec.listing_url, origin);
    let version_ok = spec.version.as_deref().is_none_or(|v| valid_text(v, 64));
    let repository_ok = spec.repository.as_deref().is_none_or(valid_repository);
    let manual_ok = spec.manual.iter().all(|m| valid_identifier(m));
    let trust_ok = spec
        .trust_score
        .is_none_or(|score| score.is_finite() && (0.0..=100.0).contains(&score));
    let blocked_ok = spec
        .blocked_reason
        .as_deref()
        .is_none_or(|reason| valid_text(reason, 300));
    let skills_ok = spec.skills_cli.as_deref().is_none_or(valid_release);
    let security_ok = spec.security.as_ref().is_none_or(|security| {
        valid_identifier(&security.verdict)
            && security
                .scanned_at
                .as_deref()
                .is_none_or(|at| at.len() <= 40 && days_from_date(at).is_some())
            && security.scanned_ref.as_deref().is_none_or(valid_commit)
            && security.reasons.len() <= 5
            && security
                .reasons
                .iter()
                .all(|reason| valid_text(reason, 160))
            && security
                .report_url
                .as_deref()
                .is_none_or(|url| under_origin(url, origin))
    });
    if !valid_slug(&spec.slug)
        || !valid_text(&spec.name, 128)
        || !listing_ok
        || !version_ok
        || !repository_ok
        || !manual_ok
        || !trust_ok
        || !blocked_ok
        || !skills_ok
        || !security_ok
        || spec.targets.len() > RUNTIMES.len()
    {
        return Err(INVALID.to_owned());
    }
    let mut seen = BTreeSet::new();
    for target in &spec.targets {
        if !seen.insert(target.runtime.as_str()) {
            return Err(INVALID.to_owned());
        }
        let ok = match target.runtime.as_str() {
            "claude-code" | "codex" => {
                target.repository.is_none()
                    && target.plugin.as_deref().is_some_and(valid_identifier)
                    && target.marketplace.as_ref().is_some_and(|m| {
                        valid_repository(&m.repository)
                            && valid_identifier(&m.name)
                            && m.commit.as_deref().is_none_or(valid_commit)
                    })
            }
            "agent-skills" => {
                target.marketplace.is_none()
                    && target.plugin.is_none()
                    && target.repository.as_deref().is_some_and(valid_repository)
            }
            _ => false,
        };
        if !ok {
            return Err(INVALID.to_owned());
        }
    }
    Ok(spec)
}

/// Check a spec with the same rules as a plan, without building one.
pub(crate) fn validate(spec: &Value, origin: &str) -> Result<(), String> {
    parse(spec.clone(), origin).map(|_| ())
}

fn plural(count: u32, one: &str) -> String {
    if count == 1 {
        format!("1 {one}")
    } else {
        format!("{count} {one}s")
    }
}

/// HOL's result and Guard's decision (RD1). Refuse: HOL marked the listing
/// not installable, its scan blocked the plugin, or found a critical issue.
/// Ask first: no scan, a warning, a scan older than 30 days or with no date, a trust score
/// below 60, a high-severity finding, or a runtime Guard cannot pin to the
/// scanned commit.
fn security(spec: &Spec, today: i64) -> Security {
    let reported = spec.security.as_ref();
    let verdict = reported.map_or("unscanned", |s| s.verdict.as_str());
    let findings = reported.and_then(|s| s.findings);
    let mut block = Vec::new();
    let mut confirm = Vec::new();
    if spec.installable == Some(false) {
        block.push(
            spec.blocked_reason
                .clone()
                .unwrap_or_else(|| "HOL has blocked installs of this listing.".to_owned()),
        );
    }
    match verdict {
        "pass" => {}
        "block" => block.push("HOL's scan blocked this plugin.".to_owned()),
        "warn" => confirm.push("HOL's scan flagged this plugin for review.".to_owned()),
        "unscanned" => confirm.push("HOL has not scanned this plugin.".to_owned()),
        other => confirm.push(format!(
            "HOL reported a scan result this Guard does not recognize ({other})."
        )),
    }
    if let Some(findings) = findings {
        if findings.critical > 0 {
            block.push(format!(
                "HOL's scan found {}.",
                plural(findings.critical, "critical issue")
            ));
        }
        if findings.high > 0 {
            confirm.push(format!(
                "HOL's scan found {}.",
                plural(findings.high, "high-severity issue")
            ));
        }
    }
    let age = reported
        .and_then(|s| s.scanned_at.as_deref())
        .and_then(days_from_date)
        .map(|scanned| today - scanned);
    match age {
        // A day of slack for clocks and time zones; past that the date is wrong.
        Some(age) if age < -1 => confirm.push("HOL's scan date is in the future.".to_owned()),
        Some(age) if age > STALE_SCAN_DAYS => {
            confirm.push(format!("HOL's last scan is {age} days old."));
        }
        None if verdict != "unscanned" => {
            confirm.push("HOL did not say when it scanned this plugin.".to_owned());
        }
        _ => {}
    }
    if let Some(score) = spec.trust_score.filter(|score| *score < LOW_TRUST) {
        confirm.push(format!("HOL trust score is {score:.0}/100, below 60."));
    }
    let unpinned: Vec<&str> = spec
        .targets
        .iter()
        .filter(|t| t.marketplace.as_ref().is_some_and(|m| m.commit.is_none()))
        .map(|t| t.runtime.as_str())
        .collect();
    if !unpinned.is_empty() && verdict != "unscanned" {
        confirm.push(format!(
            "Guard cannot pin {} to the commit HOL scanned.",
            unpinned.join(" and ")
        ));
    }
    // A pin is only worth something if it is the commit HOL scanned.
    let scanned_ref = reported.and_then(|s| s.scanned_ref.as_deref());
    let pinned = spec.targets.iter().filter_map(|t| {
        Some((
            t.runtime.as_str(),
            t.marketplace.as_ref()?.commit.as_deref()?,
        ))
    });
    for (runtime, commit) in pinned {
        match scanned_ref {
            Some(scanned) if scanned != commit => block.push(format!(
                "HOL scanned commit {}, but the listing pins {runtime} to {}.",
                &scanned[..12],
                &commit[..12]
            )),
            None if verdict != "unscanned" => {
                confirm.push("HOL did not say which commit it scanned.".to_owned());
                break;
            }
            _ => {}
        }
    }
    let gate = if !block.is_empty() {
        Gate::Block
    } else if !confirm.is_empty() {
        Gate::Confirm
    } else {
        Gate::Pass
    };
    block.extend(confirm);
    Security {
        gate,
        verdict: verdict.to_owned(),
        reasons: block,
        hol_reasons: reported.map(|s| s.reasons.clone()).unwrap_or_default(),
        scanned_at: reported.and_then(|s| s.scanned_at.clone()),
        scanned_ref: reported.and_then(|s| s.scanned_ref.clone()),
        findings,
        report_url: reported.and_then(|s| s.report_url.clone()),
    }
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn step(
    target: &Target,
    action: Action,
    available: &BTreeSet<String>,
    skills_cli: Option<&str>,
) -> Step {
    let marketplace_install = |program: &'static str, add: &str, remove: &str, list: &[&str]| {
        let market = target.marketplace.as_ref().expect("validated");
        let plugin = target.plugin.as_deref().expect("validated");
        let id = format!("{plugin}@{}", market.name);
        // Only Codex takes a commit when adding a marketplace. Claude Code
        // clones a branch, so the CLI checks its commit after the install.
        let pin = (program == "codex")
            .then_some(market.commit.as_deref())
            .flatten();
        let mut add_marketplace =
            argv(&[program, "plugin", "marketplace", "add", &market.repository]);
        if let Some(commit) = pin {
            add_marketplace.extend(argv(&["--ref", commit]));
        }
        let commands = match action {
            Action::Install => vec![add_marketplace, argv(&[program, "plugin", add, &id])],
            Action::Uninstall => vec![argv(&[program, "plugin", remove, &id])],
        };
        Step {
            runtime: "",
            program,
            available: available.contains(program),
            automatic: true,
            commands,
            verify: Some(argv(list)),
            note: (action == Action::Uninstall)
                .then_some("The marketplace stays registered, since other plugins may use it."),
            plugin_id: Some(id),
            marketplace: Some(market.name.clone()),
            expected_commit: match action {
                Action::Install => market.commit.clone(),
                Action::Uninstall => None,
            },
            remove_marketplace: None,
            marketplace_repository: (action == Action::Uninstall)
                .then(|| market.repository.clone()),
        }
    };
    match target.runtime.as_str() {
        "claude-code" => Step {
            runtime: "claude-code",
            ..marketplace_install(
                "claude",
                "install",
                "uninstall",
                &["claude", "plugin", "list"],
            )
        },
        "codex" => Step {
            runtime: "codex",
            ..marketplace_install("codex", "add", "remove", &["codex", "plugin", "list"])
        },
        _ => {
            let repository = target.repository.as_deref().expect("validated");
            let skills = skills_cli.map_or_else(|| "skills".to_owned(), |v| format!("skills@{v}"));
            let commands = match action {
                Action::Install => vec![argv(&["npx", &skills, "add", repository])],
                Action::Uninstall => vec![argv(&["npx", &skills, "list"])],
            };
            Step {
                runtime: "agent-skills",
                program: "npx",
                available: available.contains("npx"),
                automatic: false,
                commands,
                verify: Some(argv(&["npx", &skills, "list"])),
                note: Some(match action {
                    Action::Install => "Run this yourself: the Skills CLI downloads a package from npm and installs for every agent it detects.",
                    Action::Uninstall => "Remove the skills with the Skills CLI; it lists what it installed.",
                }),
                plugin_id: None,
                marketplace: None,
                expected_commit: None,
                remove_marketplace: None,
                marketplace_repository: None,
            }
        }
    }
}

/// Build the plan. `available` names the programs found on PATH,
/// `requested` limits it to some runtimes (empty means every target),
/// `origin` is where listing pages must live (see [`HOL_ORIGIN`]) and
/// `today` is days since 1970-01-01, to age the scan.
pub fn plan(
    spec: Value,
    action: Action,
    available: &[String],
    requested: &[String],
    origin: &str,
    today: i64,
) -> Result<Plan, String> {
    let spec = parse(spec, origin)?;
    if requested.iter().any(|r| !RUNTIMES.contains(&r.as_str())) {
        return Err("plugin_kit_install_runtime_unknown".to_owned());
    }
    let offered: BTreeSet<&str> = spec.targets.iter().map(|t| t.runtime.as_str()).collect();
    if requested.iter().any(|r| !offered.contains(r.as_str())) {
        return Err("plugin_kit_install_runtime_not_offered".to_owned());
    }
    let available: BTreeSet<String> = available.iter().cloned().collect();
    let mut steps: Vec<Step> = spec
        .targets
        .iter()
        .filter(|t| requested.is_empty() || requested.contains(&t.runtime))
        .map(|t| step(t, action, &available, spec.skills_cli.as_deref()))
        .collect();
    steps.sort_by_key(|s| RUNTIMES.iter().position(|r| *r == s.runtime));
    let security = (action == Action::Install).then(|| security(&spec, today));
    Ok(Plan {
        action: match action {
            Action::Install => "install",
            Action::Uninstall => "uninstall",
        },
        slug: spec.slug,
        name: spec.name,
        version: spec.version,
        repository: spec.repository,
        listing_url: spec.listing_url,
        trust_score: spec.trust_score,
        security,
        steps,
        manual: spec.manual,
    })
}
