//! Policy-bundle rollout, downgrade reference and receipt simulation for
//! `RunnerAuthority`.
//!
//! These replace the Python helpers that decided whether canonical policy
//! enforcement applies to a device, which stored bundle a new bundle must not
//! be older than, and what a bundle would have decided for recent receipts.

use std::cmp::Ordering;

use guard_contracts::utc_timestamp_micros;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::policy_bundle_py::{is_py_space, non_empty};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const MATCHER_FAMILIES: [&str; 7] = [
    "file-read",
    "mcp",
    "mcp-tool",
    "package-request",
    "prompt",
    "prompt-env-read",
    "tool-action",
];
const SIMULATED_ACTIONS: [&str; 4] = ["allow", "block", "review", "ignore"];
const STALE_AFTER_MICROS: i64 = 24 * 60 * 60 * 1_000_000;

/// Python `int()` on an operator-supplied rollout percentage: an optional sign
/// and ASCII digits with single underscores between them.
fn parse_python_int(text: &str) -> Option<i64> {
    let (negative, digits) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    let well_formed = !digits.is_empty()
        && !digits.starts_with('_')
        && !digits.ends_with('_')
        && !digits.contains("__")
        && digits.bytes().all(|b| b.is_ascii_digit() || b == b'_');
    if !well_formed {
        return None;
    }
    let cleaned: String = digits.chars().filter(|c| *c != '_').collect();
    let value: i64 = cleaned.parse().ok()?;
    Some(if negative { -value } else { value })
}

fn rollout_percentage(raw: &str) -> i64 {
    let raw = raw.trim_matches(|c: char| c.is_whitespace()).to_lowercase();
    match raw.as_str() {
        "" | "0" | "false" | "off" | "legacy" => 0,
        "1" | "true" | "on" | "canonical" => 100,
        other => parse_python_int(other)
            .filter(|percentage| (1..=100).contains(percentage))
            .unwrap_or(0),
    }
}

/// `canonical_rollout`: whether canonical policy enforcement applies here.
pub(crate) fn canonical_rollout(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let raw = match args.get("raw") {
        Some(Value::String(raw)) => raw.as_str(),
        Some(Value::Null) | None => "",
        _ => return Err(ERR_INVALID),
    };
    let device_id = args
        .get("device_id")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let workspace = match args.get("workspace_id") {
        Some(Value::String(id)) if !id.is_empty() => id.as_str(),
        Some(Value::String(_) | Value::Null) | None => "local",
        _ => return Err(ERR_INVALID),
    };
    let percentage = rollout_percentage(raw);
    let enabled = match percentage {
        0 => false,
        100 => true,
        _ => {
            let digest = Sha256::digest(format!("{workspace}:{device_id}").as_bytes());
            let mut head = [0u8; 8];
            head.copy_from_slice(&digest[..8]);
            i64::try_from(u64::from_be_bytes(head) % 100).map_err(|_| ERR_INVALID)? < percentage
        }
    };
    Ok(json!({"enabled": enabled}))
}

/// Digit runs of a bundle version, compared numerically without overflow.
fn numeric_version(version: &str) -> Vec<(usize, String)> {
    let mut runs = Vec::new();
    let mut current = String::new();
    for c in version.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_digit() {
            current.push(c);
        } else if !current.is_empty() {
            let trimmed = current.trim_start_matches('0').to_owned();
            runs.push((trimmed.len(), trimmed));
            current.clear();
        }
    }
    runs
}

struct ReferenceKey {
    issued_at: i64,
    numeric: Vec<(usize, String)>,
    version: String,
    has_payload_hash: bool,
}

impl ReferenceKey {
    fn of(item: &Map<String, Value>) -> Self {
        let text = |key: &str| non_empty(item.get(key));
        let version = text("bundleVersion").unwrap_or("").to_owned();
        Self {
            // An unparseable timestamp sorts as the newest, so an unreadable
            // reference can only make the downgrade check stricter.
            issued_at: text("issuedAt")
                .and_then(utc_timestamp_micros)
                .unwrap_or(i64::MAX),
            numeric: numeric_version(&version),
            version,
            has_payload_hash: text("payloadHash").is_some(),
        }
    }

    fn compare(&self, other: &Self) -> Ordering {
        self.issued_at
            .cmp(&other.issued_at)
            .then_with(|| self.numeric.cmp(&other.numeric))
            .then_with(|| self.version.cmp(&other.version))
            .then_with(|| self.has_payload_hash.cmp(&other.has_payload_hash))
    }
}

/// `downgrade_reference`: the stored bundle a new bundle is compared to.
pub(crate) fn downgrade_reference(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let candidates = args
        .get("candidates")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    let workspace = match args.get("workspace_id") {
        Some(Value::String(id)) => Some(id.as_str()),
        Some(Value::Null) | None => None,
        _ => return Err(ERR_INVALID),
    };
    let mut best: Option<(&Value, ReferenceKey)> = None;
    for candidate in candidates {
        let Some(item) = candidate.as_object() else {
            continue;
        };
        if non_empty(item.get("issuedAt")).is_none() {
            continue;
        }
        if let Some(workspace) = workspace {
            let item_workspace = non_empty(item.get("workspaceId"));
            if item_workspace.is_some_and(|id| id != workspace) {
                continue;
            }
        }
        let key = ReferenceKey::of(item);
        // `max` keeps the first of equal candidates.
        if best
            .as_ref()
            .is_none_or(|(_, current)| key.compare(current) == Ordering::Greater)
        {
            best = Some((candidate, key));
        }
    }
    Ok(json!({"reference": best.map(|(candidate, _)| candidate)}))
}

fn matcher_family(receipt: &Map<String, Value>) -> Option<&'static str> {
    let artifact_id = non_empty(receipt.get("artifact_id"))?;
    MATCHER_FAMILIES
        .iter()
        .copied()
        .find(|family| artifact_id.contains(&format!(":{family}:")))
}

/// A receipt timestamp as parsed micros plus its original text.
type Stamp<'a> = Option<(i64, &'a str)>;

struct Decision<'a> {
    artifact_id: &'a str,
    harness: &'a str,
    action: &'a str,
    owner: &'a Value,
}

fn read_decisions(value: Option<&Value>) -> Result<Vec<Decision<'_>>, &'static str> {
    let mut decisions = Vec::new();
    for row in value.and_then(Value::as_array).ok_or(ERR_INVALID)? {
        let row = row.as_object().ok_or(ERR_INVALID)?;
        let text = |key: &str| row.get(key).and_then(Value::as_str).ok_or(ERR_INVALID);
        decisions.push(Decision {
            artifact_id: text("artifact_id")?,
            harness: text("harness")?,
            action: text("action")?,
            owner: row.get("owner").unwrap_or(&Value::Null),
        });
    }
    Ok(decisions)
}

fn simulation_micros(text: Option<&str>) -> Option<i64> {
    let text = text.filter(|text| !text.chars().all(is_py_space))?;
    utc_timestamp_micros(&text.replace('Z', "+00:00"))
}

/// `policy_simulation`: what a bundle's decisions would have done to the
/// sampled receipts.
pub(crate) fn policy_simulation(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let receipts = args
        .get("receipts")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    let decisions = read_decisions(args.get("decisions"))?;
    let now = args.get("now").and_then(Value::as_str).ok_or(ERR_INVALID)?;
    let bundle_field = |key: &str| non_empty(args.get(key));
    let (mut latest, mut oldest): (Stamp, Stamp) = (None, None);
    let mut counts = [0u64; 4];
    let (mut matched_count, mut unchanged_count) = (0u64, 0u64);
    let mut matches = Vec::new();
    for receipt in receipts {
        let receipt = receipt.as_object().ok_or(ERR_INVALID)?;
        if let (Some(micros), Some(text)) = (
            simulation_micros(receipt.get("timestamp").and_then(Value::as_str)),
            receipt.get("timestamp").and_then(Value::as_str),
        ) {
            if latest.is_none_or(|(best, _)| micros > best) {
                latest = Some((micros, text));
            }
            if oldest.is_none_or(|(best, _)| micros < best) {
                oldest = Some((micros, text));
            }
        }
        let Some(family) = matcher_family(receipt) else {
            continue;
        };
        let harness = non_empty(receipt.get("harness")).unwrap_or("*");
        let wanted = format!("family:{family}");
        let matched = decisions
            .iter()
            .find(|d| d.artifact_id == wanted && (d.harness == harness || d.harness == "*"));
        let observed = receipt
            .get("policy_decision")
            .cloned()
            .unwrap_or(Value::Null);
        let candidate = match matched {
            Some(decision) => decision.action,
            None => observed
                .as_str()
                .filter(|a| !a.is_empty())
                .unwrap_or("review"),
        };
        let simulated = SIMULATED_ACTIONS
            .iter()
            .copied()
            .find(|action| *action == candidate)
            .unwrap_or("review");
        if let Some(slot) = SIMULATED_ACTIONS.iter().position(|a| *a == simulated) {
            counts[slot] += 1;
        }
        if matched.is_some() {
            matched_count += 1;
        } else {
            unchanged_count += 1;
        }
        matches.push(json!({
            "receipt_id": receipt.get("receipt_id").cloned().unwrap_or(Value::Null),
            "artifact_id": receipt.get("artifact_id").cloned().unwrap_or(Value::Null),
            "harness": harness,
            "matcher_family": family,
            "observed_action": observed,
            "simulated_action": simulated,
            "matched_rule_id": matched.map_or(Value::Null, |decision| decision.owner.clone()),
            "policy_version": bundle_field("bundle_hash"),
            "timestamp": receipt.get("timestamp").cloned().unwrap_or(Value::Null),
        }));
    }
    let stale = simulation_micros(Some(now))
        .zip(latest)
        .is_some_and(|(generated, (latest, _))| {
            generated.saturating_sub(latest) > STALE_AFTER_MICROS
        });
    Ok(json!({
        "generated_at": now,
        "policy_bundle_version": bundle_field("bundle_version"),
        "policy_version": bundle_field("bundle_hash"),
        "receipt_count": receipts.len(),
        "summary": {
            "allow": counts[0],
            "block": counts[1],
            "review": counts[2],
            "ignore": counts[3],
            "matched": matched_count,
            "unchanged": unchanged_count,
        },
        "matches": matches,
        "event_freshness": {
            "latest_receipt_at": latest.map(|(_, text)| text),
            "oldest_receipt_at": oldest.map(|(_, text)| text),
            "sampled_receipts": receipts.len(),
            "stale": stale,
        },
    }))
}
