//! Rollout controls for the command decision plane's shadow comparison.
//!
//! The shadow plane runs a proposed evaluator beside the one that is actually
//! enforcing and records how the two differ. Nothing it decides reaches the
//! user: enforcement stays bound to the current action, and this module only
//! answers which cohorts a given activity is sampled into and how the two
//! actions compare on the severity lattice.
//!
//! Python's `command_shadow_evaluation` resolves the same controls from four
//! environment variables, buckets an activity with a length-framed SHA-256, and
//! reads the comparison off `guard_action_severity`. Every rule here is that
//! module's, including the directions it fails in: a malformed value disables
//! recording rather than widening it, and an unrecognised cohort list disables
//! every cohort rather than none.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::effect_decision::{FinalDisposition, GuardAction};

/// `HOL_GUARD_DECISION_SHADOW_ENABLED` — `0` turns recording off.
pub const COMMAND_SHADOW_ENABLED_ENV: &str = "HOL_GUARD_DECISION_SHADOW_ENABLED";
/// `HOL_GUARD_DECISION_SHADOW_KILL_SWITCH` — `1` turns recording off.
pub const COMMAND_SHADOW_KILL_SWITCH_ENV: &str = "HOL_GUARD_DECISION_SHADOW_KILL_SWITCH";
/// `HOL_GUARD_DECISION_SHADOW_DISABLED_COHORTS` — a comma-separated list.
pub const COMMAND_SHADOW_DISABLED_COHORTS_ENV: &str = "HOL_GUARD_DECISION_SHADOW_DISABLED_COHORTS";
/// `HOL_GUARD_DECISION_SHADOW_SAMPLE_BASIS_POINTS` — `0`–`10000`.
pub const COMMAND_SHADOW_SAMPLE_BASIS_POINTS_ENV: &str =
    "HOL_GUARD_DECISION_SHADOW_SAMPLE_BASIS_POINTS";

/// `COMMAND_SHADOW_CONTROL_GENERATION`.
pub const COMMAND_SHADOW_CONTROL_GENERATION: u32 = 1;
/// `COMMAND_SHADOW_CONTROL_SCHEMA_VERSION`.
pub const COMMAND_SHADOW_CONTROL_SCHEMA_VERSION: &str = "guard.command-shadow-control.v1";
/// `COMMAND_SHADOW_SCHEMA_VERSION`.
pub const COMMAND_SHADOW_SCHEMA_VERSION: &str = "guard.command-shadow.v1";
/// `COMMAND_SHADOW_BASELINE_PROPOSAL_VERSION`.
pub const COMMAND_SHADOW_BASELINE_PROPOSAL_VERSION: &str =
    "guard.command-shadow-proposal.baseline.v1";

/// Full scale for the sampling rate: 10000 basis points is every activity.
pub const BASIS_POINTS_MAX: u32 = 10_000;

/// One release cohort the shadow plane can sample into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CommandShadowCohort {
    /// The current evaluator, proposed unchanged.
    Baseline,
    /// `cdx-060-verified-reads`.
    VerifiedReads,
    /// `cdx-061-contained-checks`.
    ContainedChecks,
    /// `cdx-062-contained-writes`.
    ContainedWrites,
    /// `cdx-063-task-capabilities`.
    TaskCapabilities,
    /// `cdx-064-remote-mutation-floors`.
    RemoteMutationFloors,
    /// `cdx-065-package-provenance-floors`.
    PackageProvenanceFloors,
    /// `cdx-066-critical-block-floors`.
    CriticalBlockFloors,
}

/// Every cohort, in the declaration order Python's enum uses.
pub const ALL_COMMAND_SHADOW_COHORTS: [CommandShadowCohort; 8] = [
    CommandShadowCohort::Baseline,
    CommandShadowCohort::VerifiedReads,
    CommandShadowCohort::ContainedChecks,
    CommandShadowCohort::ContainedWrites,
    CommandShadowCohort::TaskCapabilities,
    CommandShadowCohort::RemoteMutationFloors,
    CommandShadowCohort::PackageProvenanceFloors,
    CommandShadowCohort::CriticalBlockFloors,
];

impl CommandShadowCohort {
    /// Python `.value` — the wire name, which is also the sort key.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::VerifiedReads => "cdx-060-verified-reads",
            Self::ContainedChecks => "cdx-061-contained-checks",
            Self::ContainedWrites => "cdx-062-contained-writes",
            Self::TaskCapabilities => "cdx-063-task-capabilities",
            Self::RemoteMutationFloors => "cdx-064-remote-mutation-floors",
            Self::PackageProvenanceFloors => "cdx-065-package-provenance-floors",
            Self::CriticalBlockFloors => "cdx-066-critical-block-floors",
        }
    }

    /// `CommandShadowCohort(value)` — exact match or nothing.
    pub fn from_value(value: &str) -> Option<Self> {
        ALL_COMMAND_SHADOW_COHORTS
            .into_iter()
            .find(|cohort| cohort.as_str() == value)
    }
}

/// How a proposed action compares with the one being enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandShadowComparison {
    /// The proposal would have been less restrictive.
    Lowered,
    /// The proposal agrees with the current rank.
    Unchanged,
    /// The proposal would have been more restrictive.
    Strengthened,
}

impl CommandShadowComparison {
    /// Python `.value`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lowered => "lowered",
            Self::Unchanged => "unchanged",
            Self::Strengthened => "strengthened",
        }
    }
}

/// The resolved rollout controls for one process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandShadowControl {
    /// Whether recording is on at all.
    pub enabled: bool,
    /// Whether the kill switch has shut recording off.
    pub kill_switch: bool,
    /// The cohorts this release knows how to record.
    pub release_cohorts: BTreeSet<CommandShadowCohort>,
    /// The cohorts an operator has switched off.
    pub disabled_cohorts: BTreeSet<CommandShadowCohort>,
    /// The sampling rate, out of [`BASIS_POINTS_MAX`].
    pub sample_basis_points: u32,
    /// `COMMAND_SHADOW_CONTROL_GENERATION`.
    pub generation: u32,
    /// `COMMAND_SHADOW_CONTROL_SCHEMA_VERSION`.
    pub schema_version: &'static str,
}

impl CommandShadowControl {
    /// Which of a proposal's cohorts this activity records under.
    ///
    /// `selected_cohorts`: recording off, the kill switch, or a zero rate all
    /// return nothing; otherwise the proposal's cohorts are narrowed to the
    /// ones this release carries and the operator has not switched off, then
    /// each is sampled on its own bucket. An `activity_id` that is not an
    /// opaque identifier is refused rather than bucketed.
    pub fn selected_cohorts(
        &self,
        proposal_cohorts: &BTreeSet<CommandShadowCohort>,
        activity_id: &str,
    ) -> Result<Vec<CommandShadowCohort>, CommandShadowError> {
        if !self.enabled || self.kill_switch || self.sample_basis_points == 0 {
            return Ok(Vec::new());
        }
        let mut selected = Vec::new();
        for cohort in proposal_cohorts {
            if !self.release_cohorts.contains(cohort) || self.disabled_cohorts.contains(cohort) {
                continue;
            }
            if sample_bucket(*cohort, activity_id)? < self.sample_basis_points {
                selected.push(*cohort);
            }
        }
        // `sorted(..., key=lambda item: item.value)`: the cohort names sort the
        // same way the variants declare, so iterating the set is that order.
        Ok(selected)
    }
}

/// An input the shadow plane refuses, in Python's wording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandShadowError(String);

impl CommandShadowError {
    /// The refusal text, identical to the `ValueError` Python raises.
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CommandShadowError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CommandShadowError {}

/// Whether a value matches `_ACTIVITY_ID`: `[A-Za-z0-9][A-Za-z0-9._:-]{0,255}`.
fn is_activity_id(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    let mut count = 0usize;
    for character in characters {
        count += 1;
        if count > 255 {
            return false;
        }
        if !(character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-')) {
            return false;
        }
    }
    true
}

/// Which basis-point bucket an activity falls in for one cohort.
///
/// `_sample_bucket`: the cohort name and the activity id are length-framed so
/// no pair of values can be read two ways, hashed, and the whole digest is read
/// as one big-endian integer before the modulus.
pub fn sample_bucket(
    cohort: CommandShadowCohort,
    activity_id: &str,
) -> Result<u32, CommandShadowError> {
    if !is_activity_id(activity_id) {
        return Err(CommandShadowError(
            "activity_id must be an opaque identifier".to_owned(),
        ));
    }
    let name = cohort.as_str();
    let framed = format!(
        "{}:{}{}:{}",
        name.len(),
        name,
        activity_id.len(),
        activity_id
    );
    let digest = Sha256::digest(framed.as_bytes());
    // `int.from_bytes(digest, "big") % 10000` on 32 bytes: fold the digest
    // modulo the scale a byte at a time, which is that arithmetic without a
    // 256-bit integer.
    let mut remainder = 0u64;
    for byte in digest {
        remainder = (remainder * 256 + u64::from(byte)) % u64::from(BASIS_POINTS_MAX);
    }
    Ok(remainder as u32)
}

/// `_strict_flag`: an absent value takes the default, `1`/`0` decide, and
/// anything else takes the restrictive `invalid` answer.
fn strict_flag(raw: Option<&str>, default: bool, invalid: bool) -> bool {
    match raw {
        None => default,
        Some("1") => true,
        Some("0") => false,
        Some(_) => invalid,
    }
}

/// `_cohort_set`: an absent value takes the default, an empty one names no
/// cohorts, and a list holding anything unrecognised disables every cohort.
fn cohort_set(
    raw: Option<&str>,
    default: &BTreeSet<CommandShadowCohort>,
) -> BTreeSet<CommandShadowCohort> {
    let Some(raw) = raw else {
        return default.clone();
    };
    if raw.is_empty() {
        return BTreeSet::new();
    }
    let mut cohorts = BTreeSet::new();
    for value in raw.split(',') {
        match CommandShadowCohort::from_value(value) {
            Some(cohort) => {
                cohorts.insert(cohort);
            }
            None => return ALL_COMMAND_SHADOW_COHORTS.into_iter().collect(),
        }
    }
    cohorts
}

/// `_sample_basis_points`: absent means full scale, and anything that is not an
/// integer in range means no sampling at all.
fn sample_basis_points(raw: Option<&str>) -> u32 {
    let Some(raw) = raw else {
        return BASIS_POINTS_MAX;
    };
    // Python's `int()` accepts surrounding whitespace, a sign and underscores
    // between digits; a value it would refuse falls to zero either way, so the
    // only spellings that matter are the ones it accepts inside the range.
    let Ok(parsed) = parse_python_int(raw) else {
        return 0;
    };
    if (0..=i64::from(BASIS_POINTS_MAX)).contains(&parsed) {
        parsed as u32
    } else {
        0
    }
}

/// `int(raw)` for the spellings that can land inside the basis-point range.
fn parse_python_int(raw: &str) -> Result<i64, ()> {
    let trimmed = raw.trim();
    let (sign, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (-1i64, rest),
        None => (1i64, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') {
        return Err(());
    }
    let mut value = 0i64;
    let mut previous_underscore = false;
    for character in digits.chars() {
        if character == '_' {
            if previous_underscore {
                return Err(());
            }
            previous_underscore = true;
            continue;
        }
        let Some(digit) = character.to_digit(10) else {
            return Err(());
        };
        previous_underscore = false;
        // Anything this overflows is far outside the range and lands on zero.
        value = value
            .checked_mul(10)
            .and_then(|scaled| scaled.checked_add(i64::from(digit)))
            .ok_or(())?;
    }
    Ok(sign * value)
}

/// Resolve the rollout controls from the environment.
///
/// `load_command_shadow_control`: recording is on unless a value says
/// otherwise, the kill switch trips on anything it cannot read, and this
/// release carries only the baseline cohort.
pub fn load_command_shadow_control(
    read_env: impl Fn(&str) -> Option<String>,
) -> CommandShadowControl {
    let enabled = strict_flag(read_env(COMMAND_SHADOW_ENABLED_ENV).as_deref(), true, false);
    let kill_switch = strict_flag(
        read_env(COMMAND_SHADOW_KILL_SWITCH_ENV).as_deref(),
        false,
        true,
    );
    let disabled_cohorts = cohort_set(
        read_env(COMMAND_SHADOW_DISABLED_COHORTS_ENV).as_deref(),
        &BTreeSet::new(),
    );
    let sample_basis_points =
        sample_basis_points(read_env(COMMAND_SHADOW_SAMPLE_BASIS_POINTS_ENV).as_deref());
    CommandShadowControl {
        enabled,
        kill_switch,
        release_cohorts: [CommandShadowCohort::Baseline].into_iter().collect(),
        disabled_cohorts,
        sample_basis_points,
        generation: COMMAND_SHADOW_CONTROL_GENERATION,
        schema_version: COMMAND_SHADOW_CONTROL_SCHEMA_VERSION,
    }
}

/// How the proposed action compares with the one being enforced.
///
/// `_comparison`: the canonical severity lattice decides, so two actions that
/// rank the same compare unchanged even when they are not the same action.
pub fn command_shadow_comparison(
    current: GuardAction,
    proposed: GuardAction,
) -> CommandShadowComparison {
    match proposed.severity().cmp(&current.severity()) {
        std::cmp::Ordering::Less => CommandShadowComparison::Lowered,
        std::cmp::Ordering::Equal => CommandShadowComparison::Unchanged,
        std::cmp::Ordering::Greater => CommandShadowComparison::Strengthened,
    }
}

/// Whether a disposition is one the action can carry.
///
/// `_disposition_matches`: `allow` covers the three silent routes, and every
/// other action must be named by the disposition itself.
pub fn disposition_matches(action: GuardAction, disposition: FinalDisposition) -> bool {
    if action == GuardAction::Allow {
        return matches!(
            disposition,
            FinalDisposition::SilentVerified
                | FinalDisposition::SilentContained
                | FinalDisposition::WorkflowAuthorized
        );
    }
    disposition.as_str() == action.as_str()
}
