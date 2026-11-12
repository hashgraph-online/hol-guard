//! Workspace network rules and known-bad URL indicators from the signed
//! network protection bundle, applied to the destinations a tool call names.
//!
//! The bundle is verified when it is synced and saved in `sync_state`; this
//! reads the saved copy. Precedence, strongest first: a workspace block, an
//! exact known-bad URL, a workspace allow, then a known-bad dedicated host.
//! An allow only answers a host-level indicator; it never lifts an exact
//! known-bad URL or any other Guard decision. The overlay only ever raises
//! the result's floor.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use guard_command::network_url::{
    digest_normalized_network_url, host_matches_domain, normalize_network_url,
};
use guard_contracts::{GuardHookEnvelopeV2, PreToolResultV1};
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::Value;

use crate::local_store_read::{open_read_only_cached, table_exists, STORE_FILE_NAME};
use crate::policy_enforcement::ActionFloor;

pub(crate) const SYNC_STATE_KEY: &str = "network_protection_bundle";
const CONTRACT_VERSION: &str = "guard-network-protection-bundle.v1";
/// Destinations checked per tool call. A call naming more than this is
/// flagged for review rather than partly checked, so padding a command with
/// harmless URLs cannot push a bad one out of view.
const MAX_TARGETS: usize = 256;
/// Known-bad indicators are delisted upstream; past this, unsynced ones are
/// no longer trusted. Workspace rules stay in force until replaced.
const INDICATOR_STALE_AFTER_SECS: u64 = 7 * 24 * 60 * 60;
const TOO_MANY_DESTINATIONS: &str = "network_too_many_destinations";
const KNOWN_BAD_HOST: &str = "network_known_bad_host";

/// Whether `reason_code` is one of this overlay's review findings. They match
/// the synced bundle, so unlike a native "unproven" review they hold the hook
/// verdict at review before execution.
pub(crate) fn is_review_finding(reason_code: &str) -> bool {
    reason_code == TOO_MANY_DESTINATIONS || reason_code == KNOWN_BAD_HOST
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedBundle {
    bundle: Bundle,
    expires_at_epoch: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Bundle {
    contract_version: String,
    #[serde(default)]
    workspace_rules: Vec<Rule>,
    #[serde(default)]
    threat_urls: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    threat_hosts: BTreeMap<String, Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Rule {
    action: String,
    match_kind: String,
    pattern: String,
}

#[derive(Default)]
struct RuleSet {
    domains: Vec<String>,
    prefixes: Vec<String>,
}

impl RuleSet {
    fn matches(&self, host: &str, normalized: &str) -> Option<&str> {
        self.domains
            .iter()
            .find(|domain| host_matches_domain(host, domain))
            .or_else(|| {
                self.prefixes
                    .iter()
                    .find(|prefix| normalized.starts_with(prefix.as_str()))
            })
            .map(String::as_str)
    }
}

struct Compiled {
    expires_at_epoch: u64,
    block: RuleSet,
    allow: RuleSet,
    /// digest -> threat type
    threat_urls: HashMap<String, String>,
    /// dedicated host -> threat type
    threat_hosts: HashMap<String, String>,
}

fn compile(saved: SavedBundle) -> Option<Compiled> {
    if saved.bundle.contract_version != CONTRACT_VERSION {
        return None;
    }
    let mut block = RuleSet::default();
    let mut allow = RuleSet::default();
    for rule in saved.bundle.workspace_rules {
        let set = match rule.action.as_str() {
            "block" => &mut block,
            "allow" => &mut allow,
            _ => continue,
        };
        match rule.match_kind.as_str() {
            "domain" => {
                let pattern = rule.pattern.trim();
                let pattern = pattern.strip_prefix("*.").unwrap_or(pattern);
                if let Some(parsed) = normalize_network_url(pattern) {
                    set.domains.push(parsed.host);
                }
            }
            // The normal form always puts `/` after the host (and port), so a
            // prefix stays bound to its host: `trusted.example` never covers
            // `trusted.example.attacker.net`.
            "url_prefix" => {
                if let Some(parsed) = normalize_network_url(&rule.pattern) {
                    set.prefixes.push(parsed.normalized);
                }
            }
            _ => {}
        }
    }
    let invert = |groups: BTreeMap<String, Vec<String>>| {
        let mut map = HashMap::new();
        for (threat_type, values) in groups {
            for value in values {
                map.entry(value).or_insert_with(|| threat_type.clone());
            }
        }
        map
    };
    Some(Compiled {
        expires_at_epoch: saved.expires_at_epoch,
        block,
        allow,
        threat_urls: invert(saved.bundle.threat_urls),
        threat_hosts: invert(saved.bundle.threat_hosts),
    })
}

/// The Guard home, and its saved row's write time (microseconds) and size.
type RowKey = (PathBuf, String, i64);

/// The last compiled bundle, keyed by its row so an unchanged row is not read
/// or parsed again.
static COMPILED: Mutex<Option<(RowKey, Arc<Compiled>)>> = Mutex::new(None);

fn load(guard_home: &Path) -> Option<Arc<Compiled>> {
    let connection = open_read_only_cached(&guard_home.join(STORE_FILE_NAME)).ok()??;
    if !table_exists(&connection, "sync_state").ok()? {
        return None;
    }
    let key: RowKey = connection
        .prepare_cached(
            "select updated_at, length(payload_json) from sync_state where state_key = ?1",
        )
        .and_then(|mut statement| {
            statement
                .query_row([SYNC_STATE_KEY], |row| {
                    Ok((guard_home.to_path_buf(), row.get(0)?, row.get(1)?))
                })
                .optional()
        })
        .ok()??;
    if let Ok(cached) = COMPILED.lock() {
        if let Some((cached_key, compiled)) = cached.as_ref() {
            if *cached_key == key {
                return Some(Arc::clone(compiled));
            }
        }
    }
    let payload: String = connection
        .prepare_cached("select payload_json from sync_state where state_key = ?1")
        .and_then(|mut statement| statement.query_row([SYNC_STATE_KEY], |row| row.get(0)))
        .ok()?;
    let compiled = Arc::new(compile(serde_json::from_str(&payload).ok()?)?);
    if let Ok(mut cached) = COMPILED.lock() {
        *cached = Some((key, Arc::clone(&compiled)));
    }
    Some(compiled)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetworkFinding {
    pub(crate) floor: &'static str,
    pub(crate) reason_code: &'static str,
    pub(crate) reason: String,
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn host_indicator<'a>(compiled: &'a Compiled, host: &str) -> Option<&'a str> {
    if host.starts_with('[') || host.parse::<std::net::Ipv4Addr>().is_ok() {
        return compiled.threat_hosts.get(host).map(String::as_str);
    }
    let mut candidate = host;
    loop {
        if let Some(threat_type) = compiled.threat_hosts.get(candidate) {
            return Some(threat_type);
        }
        candidate = candidate.split_once('.')?.1;
        if !candidate.contains('.') {
            return None;
        }
    }
}

fn threat_label(threat_type: &str) -> String {
    threat_type.replace('_', " ")
}

fn too_many_targets() -> NetworkFinding {
    NetworkFinding {
        floor: "review",
        reason_code: TOO_MANY_DESTINATIONS,
        reason: format!(
            "This call names more than {MAX_TARGETS} network destinations, too many to check against your workspace rules. Review before letting this run."
        ),
    }
}

fn evaluate(compiled: &Compiled, targets: &[String], now: u64) -> Option<NetworkFinding> {
    let indicators_fresh = now
        <= compiled
            .expires_at_epoch
            .saturating_add(INDICATOR_STALE_AFTER_SECS);
    let mut review = None;
    for target in targets {
        let Some(parsed) = normalize_network_url(target) else {
            continue;
        };
        if let Some(rule) = compiled.block.matches(&parsed.host, &parsed.normalized) {
            return Some(NetworkFinding {
                floor: "block",
                reason_code: "network_workspace_block",
                reason: format!(
                    "Guard blocked {}: your workspace blocks network access to {rule}.",
                    parsed.host
                ),
            });
        }
        if !indicators_fresh {
            continue;
        }
        let digest = digest_normalized_network_url(&parsed.normalized);
        if let Some(threat_type) = compiled.threat_urls.get(&digest) {
            return Some(NetworkFinding {
                floor: "block",
                reason_code: "network_known_bad_url",
                reason: format!(
                    "Guard blocked a request to {}: the URL is listed by threat intelligence feeds as {}.",
                    parsed.host,
                    threat_label(threat_type)
                ),
            });
        }
        if review.is_some()
            || compiled
                .allow
                .matches(&parsed.host, &parsed.normalized)
                .is_some()
        {
            continue;
        }
        if let Some(threat_type) = host_indicator(compiled, &parsed.host) {
            review = Some(NetworkFinding {
                floor: "review",
                reason_code: KNOWN_BAD_HOST,
                reason: format!(
                    "{} hosts URLs listed by threat intelligence feeds as {}. Review before letting this run.",
                    parsed.host,
                    threat_label(threat_type)
                ),
            });
        }
    }
    review
}

fn raise(mut result: PreToolResultV1, finding: NetworkFinding) -> PreToolResultV1 {
    let (Some(floor), Some(minimum), Some(policy)) = (
        ActionFloor::parse(finding.floor),
        ActionFloor::parse(&result.minimum_action),
        ActionFloor::parse(&result.policy_action),
    ) else {
        return result;
    };
    if minimum > floor {
        return result;
    }
    if minimum == floor {
        // A review the edge already raised is provenance the composer settles
        // before execution. The bundle match holds the review, so it carries
        // the reason.
        if floor == ActionFloor::Review {
            result.explicitly_benign = false;
            result.reason_code = finding.reason_code.into();
            result.reason = finding.reason;
        }
        return result;
    }
    result.minimum_action = finding.floor.into();
    if policy < floor || floor == ActionFloor::Block {
        result.policy_action = finding.floor.into();
    }
    result.decision = "deny".into();
    result.explicitly_benign = false;
    result.reason_code = finding.reason_code.into();
    result.reason = finding.reason;
    result
}

/// `network_check` runner-authority kind: what the saved bundle decides for
/// one URL, using the same precedence the hook edge applies.
pub(crate) fn check_op(args: &Value) -> crate::runner_authority_op::KindResult {
    use crate::runner_authority_op::ERR_INVALID;
    let text = |key: &str| args.get(key).and_then(Value::as_str).ok_or(ERR_INVALID);
    let guard_home = Path::new(text("guard_home")?);
    let url = text("url")?;
    let parsed = normalize_network_url(url);
    let compiled = load(guard_home);
    let finding = match (&compiled, &parsed) {
        (Some(compiled), Some(_)) => evaluate(compiled, &[url.to_string()], now_epoch()),
        _ => None,
    };
    let indicators_applied = compiled.as_ref().is_some_and(|compiled| {
        now_epoch()
            <= compiled
                .expires_at_epoch
                .saturating_add(INDICATOR_STALE_AFTER_SECS)
    });
    Ok(serde_json::json!({
        "configured": compiled.is_some(),
        "indicators_applied": indicators_applied,
        "valid_url": parsed.is_some(),
        "host": parsed.as_ref().map(|parsed| parsed.host.clone()),
        "normalized_url": parsed.as_ref().map(|parsed| parsed.normalized.clone()),
        "decision": finding.as_ref().map_or("allow", |finding| finding.floor),
        "reason_code": finding.as_ref().map(|finding| finding.reason_code),
        "reason": finding.map(|finding| finding.reason),
    }))
}

/// [`apply`] for a hook envelope: the bundle is read from the envelope's Guard home.
pub(crate) fn apply_to_envelope(
    envelope: &GuardHookEnvelopeV2,
    result: PreToolResultV1,
) -> PreToolResultV1 {
    apply(
        Path::new(&envelope.source.guard_home),
        &envelope.raw_payload,
        result,
    )
}

/// Raises a PreToolUse result for destinations the saved bundle blocks or
/// flags. A missing, unreadable or unknown bundle leaves the result as is.
pub(crate) fn apply(
    guard_home: &Path,
    payload: &Value,
    result: PreToolResultV1,
) -> PreToolResultV1 {
    // A submitted prompt is the person's own text, not a destination; every
    // tool call, message and subagent tools included, is checked.
    if result.minimum_action == "block" || result.action.event == "UserPromptSubmit" {
        return result;
    }
    let targets = guard_command::pretool::generic::network_targets(payload, MAX_TARGETS + 1);
    if targets.is_empty() {
        return result;
    }
    let Some(compiled) = load(guard_home) else {
        return result;
    };
    let checked = &targets[..targets.len().min(MAX_TARGETS)];
    let finding = evaluate(&compiled, checked, now_epoch())
        .or_else(|| (targets.len() > MAX_TARGETS).then(too_many_targets));
    match finding {
        Some(finding) => raise(result, finding),
        None => result,
    }
}

#[cfg(test)]
#[path = "network_protection_tests.rs"]
mod tests;
