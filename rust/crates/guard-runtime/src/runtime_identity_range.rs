//! Release-line matching for runtime advisories.
//!
//! Only `semver` versions are compared. A runtime that reports anything else,
//! or a prerelease the advisory did not opt into, is unknown rather than
//! guessed. Ranges are numeric intervals: `introduced` is inclusive, `fixed` is
//! exclusive and `last_affected` is inclusive.

use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SemVer {
    core: [u64; 3],
    prerelease: Vec<Identifier>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Identifier {
    Numeric(u64),
    Text(String),
}

impl SemVer {
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        let text = raw.strip_prefix('v').unwrap_or(raw);
        let text = match text.split_once('+') {
            Some((version, build)) => {
                // Build metadata never orders versions, but a malformed tail
                // means the whole string is not semver.
                if !build.split('.').all(|part| {
                    !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                }) {
                    return None;
                }
                version
            }
            None => text,
        };
        let (core_text, prerelease_text) = match text.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (text, None),
        };
        let mut parts = core_text.split('.');
        let mut core = [0_u64; 3];
        for slot in &mut core {
            *slot = numeric_identifier(parts.next()?)?;
        }
        if parts.next().is_some() {
            return None;
        }
        let prerelease = match prerelease_text {
            None => Vec::new(),
            Some(pre) => pre
                .split('.')
                .map(prerelease_identifier)
                .collect::<Option<Vec<_>>>()?,
        };
        Some(Self { core, prerelease })
    }

    pub(crate) fn is_prerelease(&self) -> bool {
        !self.prerelease.is_empty()
    }
}

fn numeric_identifier(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if text.len() > 1 && text.starts_with('0') {
        return None;
    }
    text.parse().ok()
}

fn prerelease_identifier(text: &str) -> Option<Identifier> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return None;
    }
    if text.bytes().all(|b| b.is_ascii_digit()) {
        return numeric_identifier(text).map(Identifier::Numeric);
    }
    Some(Identifier::Text(text.to_owned()))
}

impl Ord for Identifier {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Numeric(a), Self::Numeric(b)) => a.cmp(b),
            (Self::Numeric(_), Self::Text(_)) => Ordering::Less,
            (Self::Text(_), Self::Numeric(_)) => Ordering::Greater,
            (Self::Text(a), Self::Text(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for Identifier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> Ordering {
        self.core.cmp(&other.core).then_with(|| {
            match (self.prerelease.is_empty(), other.prerelease.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.prerelease.cmp(&other.prerelease),
            }
        })
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// One affected interval, already parsed.
#[derive(Debug, Clone)]
pub(crate) struct Interval {
    pub(crate) introduced: Option<SemVer>,
    pub(crate) upper: Upper,
}

#[derive(Debug, Clone)]
pub(crate) enum Upper {
    Unbounded,
    Fixed(SemVer),
    LastAffected(SemVer),
}

impl Interval {
    /// An interval whose upper bound sits at or below its lower bound matches
    /// nothing, which would read as "not affected"; such ranges are refused.
    pub(crate) fn is_ordered(&self) -> bool {
        let Some(low) = &self.introduced else {
            return true;
        };
        match &self.upper {
            Upper::Unbounded => true,
            Upper::Fixed(fixed) => low < fixed,
            Upper::LastAffected(last) => low <= last,
        }
    }

    pub(crate) fn contains(&self, version: &SemVer) -> bool {
        if self.introduced.as_ref().is_some_and(|low| version < low) {
            return false;
        }
        match &self.upper {
            Upper::Unbounded => true,
            Upper::Fixed(fixed) => version < fixed,
            Upper::LastAffected(last) => version <= last,
        }
    }
}
