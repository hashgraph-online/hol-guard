//! Per-artifact advisory matching and the per-advisory remediation verdict.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use super::{
    text_ok, AdvisoryInput, Artifact, ArtifactInput, Coverage, InstanceInput, InstanceState,
    LocationInput, LocationState, Match, Request,
};
use crate::runtime_identity_range::{Interval, SemVer, Upper};

/// `None` when the advisory is about a different runtime entirely.
pub(super) fn match_artifact(
    artifact: &Artifact<'_>,
    advisory: &AdvisoryInput,
    intervals: &[Interval],
) -> Option<Match> {
    let input = artifact.input;
    if !input.family.eq_ignore_ascii_case(&advisory.family) {
        return None;
    }
    if let Some(vendor) = &advisory.vendor {
        match &input.vendor {
            None => return Some(Match::Unknown("vendor_unknown")),
            Some(observed) if !observed.eq_ignore_ascii_case(vendor) => return None,
            Some(_) => {}
        }
    }
    if !advisory.platforms.is_empty() {
        if let Some(found) = platform_mismatch(input, advisory) {
            return found;
        }
    }
    // The probe reads the runtime's version, not a bundled copy's.
    if advisory.bundled_component.is_some() {
        return Some(Match::Unknown("component_version_unobserved"));
    }
    // An advisory that names no vendor still flags every in-range build of
    // the family, but its ranges cannot clear a build: another vendor's
    // versions and backports follow their own numbering.
    let can_clear = advisory.vendor.is_some() && artifact.assurance.trusted();
    if advisory.version_scheme != "semver" {
        return Some(Match::Unknown("version_scheme_unsupported"));
    }
    if intervals.is_empty() {
        return Some(Match::Unknown("no_ranges"));
    }
    let Some(raw) = &input.version else {
        return Some(Match::Unknown("version_unknown"));
    };
    let Some(version) = SemVer::parse(raw) else {
        return Some(Match::Unknown("version_unparseable"));
    };
    if version.is_prerelease() && !advisory.include_prerelease {
        return Some(Match::Unknown("prerelease_unhandled"));
    }
    let in_range = intervals.iter().any(|interval| interval.contains(&version));
    let backported = input
        .build_id
        .as_ref()
        .is_some_and(|build| advisory.backport_build_ids.contains(build));
    Some(match (in_range, backported, can_clear) {
        (true, true, true) => Match::NotAffected("vendor_backport"),
        (true, true, false) => Match::Unknown("backport_unverified"),
        (true, false, _) => Match::Affected("in_range"),
        (false, _, true) => Match::NotAffected("outside_ranges"),
        (false, _, false) if advisory.vendor.is_none() => {
            Match::Unknown("advisory_vendor_unspecified")
        }
        (false, _, false) => Match::Unknown("outside_ranges_untrusted"),
    })
}

/// `None` when the artifact's platform is listed, `Some(None)` when it is
/// clearly another platform, and an unknown match when the probe could not
/// tell which platform it runs on. A wildcard covers every value, unknown
/// included. A universal (multi-architecture) binary may run any slice it
/// carries, so it confirms no single architecture.
fn platform_mismatch(input: &ArtifactInput, advisory: &AdvisoryInput) -> Option<Option<Match>> {
    let unconfirmed =
        |have: &str| have.eq_ignore_ascii_case("unknown") || have.eq_ignore_ascii_case("universal");
    let fits = |want: &str, have: &str, unknown_fits: bool| {
        want == "*"
            || (want.eq_ignore_ascii_case(have) && !unconfirmed(have))
            || (unknown_fits && unconfirmed(have))
    };
    let listed = |unknown_fits: bool| {
        advisory.platforms.iter().any(|platform| {
            fits(&platform.os, &input.os, unknown_fits)
                && fits(&platform.arch, &input.arch, unknown_fits)
        })
    };
    if listed(false) {
        None
    } else if listed(true) {
        Some(Some(Match::Unknown("platform_unknown")))
    } else {
        Some(None)
    }
}

pub(super) fn advisory_verdict(
    request: &Request,
    artifacts: &BTreeMap<&str, Artifact<'_>>,
    locations: &BTreeMap<&str, &LocationInput>,
    advisory: &AdvisoryInput,
    by_artifact: &BTreeMap<&str, Match>,
) -> Value {
    let ids_where = |wanted: fn(&Match) -> bool| -> BTreeSet<&str> {
        by_artifact
            .iter()
            .filter(|(_, found)| wanted(found))
            .map(|(id, _)| *id)
            .collect()
    };
    let affected = ids_where(|found| matches!(found, Match::Affected(_)));
    let cleared = ids_where(|found| matches!(found, Match::NotAffected(_)));
    let unknown_match = by_artifact
        .values()
        .any(|found| matches!(found, Match::Unknown(_)));

    let live_affected: Vec<&InstanceInput> = request
        .instances
        .iter()
        .filter(|instance| {
            affected.contains(instance.artifact_id.as_str())
                && instance.state != InstanceState::Exited
        })
        .collect();
    let running_affected: Vec<&InstanceInput> = live_affected
        .iter()
        .copied()
        .filter(|instance| instance.state == InstanceState::Running)
        .collect();
    let replacements: Vec<&str> = request
        .instances
        .iter()
        .filter(|instance| {
            instance.state == InstanceState::Running
                && instance.coverage == Coverage::BoundLaunch
                && cleared.contains(instance.artifact_id.as_str())
                && artifacts
                    .get(instance.artifact_id.as_str())
                    .is_some_and(|artifact| artifact.assurance.trusted())
        })
        .map(|instance| instance.instance_id.as_str())
        .collect();
    let holds_affected = |location: &&&LocationInput| {
        location
            .artifact_id
            .as_deref()
            .is_some_and(|id| affected.contains(id))
    };
    let installed_affected = locations
        .values()
        .filter(holds_affected)
        .any(|location| location.state == LocationState::Present);
    let affected_location_unknown = locations
        .values()
        .filter(holds_affected)
        .any(|location| location.state == LocationState::Unknown);
    // A file Guard saw but could not identify may still be the affected build.
    let unidentified_location = locations
        .values()
        .any(|location| location.state != LocationState::Missing && location.artifact_id.is_none());
    // The file at an affected process's location has already been replaced by
    // a cleared build: the process still runs the old one.
    let replaced_on_disk = |instance: &&InstanceInput| {
        instance
            .location_id
            .as_deref()
            .and_then(|id| locations.get(id))
            .is_some_and(|location| {
                location.state == LocationState::Present
                    && location
                        .artifact_id
                        .as_deref()
                        .is_some_and(|id| cleared.contains(id))
            })
    };

    let mut reasons: Vec<&str> = Vec::new();
    let verdict = if affected.is_empty() {
        if unknown_match {
            reasons.push("match_unknown");
            "unknown"
        } else if by_artifact.is_empty() {
            "not_observed"
        } else {
            "not_affected"
        }
    } else if !running_affected.is_empty() {
        let all_replaced = running_affected.iter().all(replaced_on_disk);
        reasons.push(if all_replaced {
            "affected_instance_running_after_replacement"
        } else {
            "affected_instance_running"
        });
        if live_affected.len() > running_affected.len() {
            reasons.push("affected_instance_state_unknown");
        }
        // A restart only clears the risk when no affected build is left to
        // relaunch, including one at a location Guard could not read or
        // identify; otherwise the advisory is still plainly affected.
        if installed_affected {
            reasons.push("affected_artifact_installed");
        }
        if affected_location_unknown {
            reasons.push("affected_location_state_unknown");
        }
        if unidentified_location {
            reasons.push("location_unidentified");
        }
        if all_replaced
            && !installed_affected
            && !affected_location_unknown
            && !unidentified_location
        {
            "restart_required"
        } else {
            "affected"
        }
    } else if installed_affected {
        reasons.push("affected_artifact_installed");
        if !live_affected.is_empty() {
            reasons.push("affected_instance_state_unknown");
        }
        "affected"
    } else if !live_affected.is_empty() || affected_location_unknown {
        reasons.push(if live_affected.is_empty() {
            "affected_location_state_unknown"
        } else {
            "affected_instance_state_unknown"
        });
        "unknown"
    } else {
        if !request.scope_complete {
            reasons.push("scope_incomplete");
        }
        if unidentified_location {
            reasons.push("location_unidentified");
        }
        if replacements.is_empty() {
            reasons.push("no_bound_trusted_replacement");
        }
        if unknown_match {
            reasons.push("match_unknown");
        }
        if reasons.is_empty() {
            "fixed_verified"
        } else {
            "fix_unverified"
        }
    };

    json!({
        "advisory_id": advisory.advisory_id,
        "severity": advisory.severity,
        "known_exploited": advisory.known_exploited,
        "title": advisory.title,
        "verdict": verdict,
        "reasons": reasons,
        "affected_artifact_ids": affected,
        "affected_instance_ids": live_affected
            .iter()
            .map(|instance| instance.instance_id.as_str())
            .collect::<Vec<_>>(),
        "replacement_instance_ids": replacements,
    })
}

pub(super) fn parse_intervals(advisory: &AdvisoryInput) -> Result<Vec<Interval>, String> {
    let invalid = || "runtime_identity_advisory_invalid".to_owned();
    let names_ok = text_ok(&advisory.advisory_id)
        && text_ok(&advisory.family)
        && advisory.vendor.as_deref().is_none_or(text_ok)
        && advisory.backport_build_ids.iter().all(|id| text_ok(id));
    if !names_ok {
        return Err(invalid());
    }
    if advisory.version_scheme != "semver" {
        return Ok(Vec::new());
    }
    advisory
        .ranges
        .iter()
        .map(|range| {
            let parse = |text: &Option<String>| match text {
                None => Ok(None),
                Some(raw) => SemVer::parse(raw).map(Some).ok_or_else(invalid),
            };
            let upper = match (parse(&range.fixed)?, parse(&range.last_affected)?) {
                (Some(_), Some(_)) => return Err(invalid()),
                (Some(fixed), None) => Upper::Fixed(fixed),
                (None, Some(last)) => Upper::LastAffected(last),
                (None, None) => Upper::Unbounded,
            };
            let interval = Interval {
                introduced: parse(&range.introduced)?,
                upper,
            };
            if !interval.is_ordered() {
                return Err(invalid());
            }
            Ok(interval)
        })
        .collect()
}
