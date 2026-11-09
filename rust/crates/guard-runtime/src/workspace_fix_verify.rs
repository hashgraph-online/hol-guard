//! `workspace_fix_verify` runner-authority kind: whether a worktree's newest
//! assessed run settles its applied dependency fixes (the decision in
//! `workspace_assessment_fix_proposals.verify_proposals` before it moved
//! here). Python keeps the store reads and the guarded state writes.
//!
//! The request carries the run (`run_id`, `snapshot_digest`,
//! `started_at_ms`, decoded `coverage` and `findings`) and the proposals
//! still waiting on a verdict, as stored. The answer lists each proposal
//! whose state should change and the state it moves to.

use serde_json::{json, Map, Value};

use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const KEYS: [&str; 2] = ["run", "proposals"];
const RUN_KEYS: [&str; 5] = [
    "run_id",
    "snapshot_digest",
    "started_at_ms",
    "coverage",
    "findings",
];
const PROPOSAL_KEYS: [&str; 10] = [
    "proposal_id",
    "ecosystem",
    "package_name",
    "fix_version",
    "advisory_ids",
    "rule_ids",
    "snapshot_digest",
    "applied_at_ms",
    "state",
    "verification_run_id",
];
/// Absence of a finding only means "fixed" if the supply-chain detector
/// looked at everything. These coverage reasons say it did not; any
/// `snapshot_*` reason says the snapshot behind the run was itself partial.
/// A `detector_not_run:*` reason is deliberately not listed: the finding comes
/// from the supply-chain detector, so another detector's gap cannot hide it.
const BLOCKING_COVERAGE_REASONS: [&str; 4] = [
    "finding_cap",
    "supply_chain_incomplete",
    "lockfile_warnings",
    "advisory_data_unavailable",
];
/// Snapshot reasons that leave nothing unread: the dependency file was read
/// and hashed but never audited, so it cannot hide a finding in a file the
/// audit checked.
const READ_SNAPSHOT_REASONS: [&str; 2] = [
    "snapshot_unsupported_dependency_input",
    "snapshot_undiscovered_dependency_input",
];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    let run = exact_object(fields, &KEYS)
        .and_then(|_| fields.get("run"))
        .and_then(Value::as_object)
        .filter(|run| exact_object(run, &RUN_KEYS).is_some())
        .ok_or(ERR_INVALID)?;
    let proposals = fields
        .get("proposals")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|item| {
            item.as_object()
                .filter(|proposal| exact_object(proposal, &PROPOSAL_KEYS).is_some())
                .ok_or(ERR_INVALID)
        })
        .collect::<Result<Vec<&Map<String, Value>>, _>>()?;
    if !supply_chain_verifiable(run.get("coverage")) {
        return Ok(json!({"updates": []}));
    }
    let findings: Vec<&Map<String, Value>> = run
        .get("findings")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default();
    let updates = proposals
        .into_iter()
        .filter_map(|proposal| update(run, &findings, proposal))
        .collect::<Vec<Value>>();
    Ok(json!({"updates": updates}))
}

fn exact_object<'a>(
    fields: &'a Map<String, Value>,
    keys: &[&str],
) -> Option<&'a Map<String, Value>> {
    (fields.len() == keys.len() && keys.iter().all(|key| fields.contains_key(*key)))
        .then_some(fields)
}

fn update(
    run: &Map<String, Value>,
    findings: &[&Map<String, Value>],
    proposal: &Map<String, Value>,
) -> Option<Value> {
    // A run that started at or before the apply may have read the old manifest.
    let started = run.get("started_at_ms").and_then(Value::as_i64)?;
    let applied = proposal.get("applied_at_ms").and_then(Value::as_i64)?;
    if run.get("snapshot_digest") == proposal.get("snapshot_digest") || started <= applied {
        return None;
    }
    let outcome = if findings.iter().any(|finding| same_issue(finding, proposal)) {
        "still_present"
    } else {
        "verified_fixed"
    };
    if proposal.get("state").and_then(Value::as_str) == Some(outcome)
        && proposal.get("verification_run_id") == run.get("run_id")
    {
        return None;
    }
    Some(json!({"proposal_id": proposal.get("proposal_id"), "state": outcome}))
}

/// Whether a later finding is the problem the proposal set out to fix.
///
/// A finding id also hashes the resolved version, so a package that is still
/// vulnerable after the edit gets a new id. Identity is the package plus
/// either an overlapping advisory or rule id, or a version still below the
/// fix.
fn same_issue(finding: &Map<String, Value>, proposal: &Map<String, Value>) -> bool {
    if finding.get("ecosystem") != proposal.get("ecosystem")
        || finding.get("package_name") != proposal.get("package_name")
    {
        return false;
    }
    let overlaps = |key: &str| {
        let wanted = ids(proposal.get(key));
        ids(finding.get(key)).iter().any(|id| wanted.contains(id))
    };
    if overlaps("advisory_ids") || overlaps("rule_ids") {
        return true;
    }
    let fix_version = proposal
        .get("fix_version")
        .and_then(Value::as_str)
        .unwrap_or("");
    below(finding.get("package_version"), fix_version)
}

fn ids(value: Option<&Value>) -> Vec<&str> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// Whether `version` is older than `fix_version`; unreadable versions count
/// as older.
fn below(version: Option<&Value>, fix_version: &str) -> bool {
    let found = version.and_then(Value::as_str).and_then(parse_version);
    let (Some(found), Some(target)) = (found, parse_version(fix_version)) else {
        return true;
    };
    match compare_core(&found.core, &target.core) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Equal => found.prerelease && !target.prerelease,
        std::cmp::Ordering::Greater => false,
    }
}

struct Version<'a> {
    core: [&'a str; 3],
    prerelease: bool,
}

/// `MAJOR.MINOR.PATCH`, an optional `-pre` and an optional `+build`, ASCII
/// only, nothing after.
fn parse_version(text: &str) -> Option<Version<'_>> {
    let mut rest = text;
    let mut core = [""; 3];
    for (index, part) in core.iter_mut().enumerate() {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        *part = &rest[..digits];
        rest = &rest[digits..];
        if index < 2 {
            rest = rest.strip_prefix('.')?;
        }
    }
    let prerelease = match rest.strip_prefix('-') {
        Some(tail) => {
            rest = tail
                .trim_start_matches(|c: char| c.is_ascii_alphanumeric() || c == '.' || c == '-');
            if rest.len() == tail.len() {
                return None;
            }
            true
        }
        None => false,
    };
    if let Some(tail) = rest.strip_prefix('+') {
        rest = tail.trim_start_matches(|c: char| c.is_ascii_alphanumeric() || c == '.' || c == '-');
        if rest.len() == tail.len() {
            return None;
        }
    }
    rest.is_empty().then_some(Version { core, prerelease })
}

/// Numeric comparison of digit strings of any length.
fn compare_core(left: &[&str; 3], right: &[&str; 3]) -> std::cmp::Ordering {
    left.iter()
        .zip(right.iter())
        .map(|(a, b)| {
            let (a, b) = (a.trim_start_matches('0'), b.trim_start_matches('0'));
            a.len().cmp(&b.len()).then_with(|| a.cmp(b))
        })
        .find(|ordering| ordering.is_ne())
        .unwrap_or(std::cmp::Ordering::Equal)
}

fn supply_chain_verifiable(coverage: Option<&Value>) -> bool {
    let Some(coverage) = coverage.and_then(Value::as_object) else {
        return false;
    };
    let complete = coverage
        .get("detectors")
        .and_then(Value::as_object)
        .and_then(|detectors| detectors.get("supply_chain"))
        .and_then(Value::as_str)
        == Some("complete");
    let Some(reasons) = coverage.get("reasons").and_then(Value::as_array) else {
        return false;
    };
    let reasons = reasons
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<&str>>>();
    let Some(reasons) = reasons.filter(|_| complete) else {
        return false;
    };
    !reasons.iter().any(|reason| {
        BLOCKING_COVERAGE_REASONS.contains(reason)
            || (reason.starts_with("snapshot_") && !READ_SNAPSHOT_REASONS.contains(reason))
    })
}

#[cfg(test)]
#[path = "workspace_fix_verify_tests.rs"]
mod tests;
