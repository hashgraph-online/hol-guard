//! Which runtime versions the cached advisories leave clean, for upgrade
//! advice. A version is clean when no high or critical advisory for its
//! family matches it by version on any platform: a range that names another
//! platform still counts, so the advice never names a release that the launch
//! check could hold somewhere.

use super::super::verdict::parse_intervals;
use super::super::AdvisoryInput;
use super::LaunchAdvisories;
use crate::runtime_identity_range::{Interval, SemVer};

impl LaunchAdvisories {
    /// Whether `version` of `family` is free of every high or critical
    /// advisory. A prerelease never counts as clean.
    pub(crate) fn version_is_clean(&self, family: &str, version: &SemVer) -> bool {
        !version.is_prerelease()
            && self
                .serious(family)
                .all(|(_, intervals)| !intervals.iter().any(|range| range.contains(version)))
    }

    /// The first clean release at or above `current`: the lowest fix on its
    /// own major line, else the lowest fix on a later line. `None` when the
    /// advisories name no such fix.
    pub(crate) fn patched_release(&self, family: &str, current: &SemVer) -> Option<String> {
        let mut fixes: Vec<(SemVer, String)> = self
            .serious(family)
            .flat_map(|(advisory, _)| advisory.ranges.iter())
            .filter_map(|range| range.fixed.as_deref())
            .filter_map(|raw| SemVer::parse(raw).map(|version| (version, raw.to_owned())))
            .filter(|(version, _)| version >= current && self.version_is_clean(family, version))
            .collect();
        fixes.sort_by(|left, right| left.0.cmp(&right.0));
        fixes
            .iter()
            .find(|(version, _)| version.major() == current.major())
            .or_else(|| fixes.first())
            .map(|(_, raw)| raw.clone())
    }

    fn serious<'a>(
        &'a self,
        family: &'a str,
    ) -> impl Iterator<Item = (&'a AdvisoryInput, Vec<Interval>)> + 'a {
        self.advisories
            .iter()
            .filter(move |advisory| advisory.family == family)
            .filter(|advisory| matches!(advisory.severity.as_deref(), Some("high" | "critical")))
            .filter_map(|advisory| Some((advisory, parse_intervals(advisory).ok()?)))
    }
}

#[cfg(test)]
#[path = "runtime_identity_fixes_tests.rs"]
mod tests;
