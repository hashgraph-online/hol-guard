//! Bounded npm-compatible selectors with same-clause prerelease admission.

use std::cmp::Ordering;

const MAX_SAFE: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Version<'a> {
    base: [u64; 3],
    pre: Option<&'a str>,
}

impl Ord for Version<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        let base = self.base.cmp(&other.base);
        if base != Ordering::Equal {
            return base;
        }
        match (self.pre, other.pre) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(left), Some(right)) => {
                let mut left = left.split('.');
                let mut right = right.split('.');
                loop {
                    match (left.next(), right.next()) {
                        (None, None) => return Ordering::Equal,
                        (None, Some(_)) => return Ordering::Less,
                        (Some(_), None) => return Ordering::Greater,
                        (Some(a), Some(b)) => {
                            let an = a.bytes().all(|b| b.is_ascii_digit());
                            let bn = b.bytes().all(|b| b.is_ascii_digit());
                            let order = match (an, bn) {
                                (true, true) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
                                (true, false) => Ordering::Less,
                                (false, true) => Ordering::Greater,
                                (false, false) => a.cmp(b),
                            };
                            if order != Ordering::Equal {
                                return order;
                            }
                        }
                    }
                }
            }
        }
    }
}
impl PartialOrd for Version<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy)]
struct RangeVersion<'a> {
    base: [Option<u64>; 3],
    pre: Option<&'a str>,
}
impl<'a> RangeVersion<'a> {
    fn complete(self) -> bool {
        self.base.iter().all(Option::is_some)
    }
    fn lower(self) -> Option<Version<'a>> {
        Some(Version {
            base: [
                self.base[0]?,
                self.base[1].unwrap_or(0),
                self.base[2].unwrap_or(0),
            ],
            pre: self.pre,
        })
    }
    fn upper(self) -> Version<'a> {
        let base = match self.base {
            [None, _, _] => [0, 0, 0],
            [Some(major), None, _] => [major + 1, 0, 0],
            [Some(major), Some(minor), _] => [major, minor + 1, 0],
        };
        Version {
            base,
            pre: Some("0"),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Op {
    Eq,
    Lt,
    Le,
    Gt,
    Ge,
}
#[derive(Clone, Copy)]
struct Comparator<'a> {
    op: Op,
    version: Version<'a>,
}
impl Comparator<'_> {
    fn matches(self, candidate: Version<'_>) -> bool {
        match self.op {
            Op::Eq => candidate == self.version,
            Op::Lt => candidate < self.version,
            Op::Le => candidate <= self.version,
            Op::Gt => candidate > self.version,
            Op::Ge => candidate >= self.version,
        }
    }
}

fn python_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}
fn trim(value: &str) -> &str {
    value.trim_matches(python_space)
}
fn identifiers(value: &str, forbid_zero: bool) -> bool {
    value.split('.').all(|id| {
        !id.is_empty()
            && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !(forbid_zero
                && id.len() > 1
                && id.starts_with('0')
                && id.bytes().all(|b| b.is_ascii_digit()))
    })
}
fn range_version(value: &str) -> Option<RangeVersion<'_>> {
    if value.is_empty() || value.len() > 256 || trim(value) != value {
        return None;
    }
    let value = value.strip_prefix('v').unwrap_or(value);
    let (core_pre, build) = value
        .split_once('+')
        .map_or((value, None), |(c, b)| (c, Some(b)));
    if build.is_some_and(|b| !identifiers(b, false)) {
        return None;
    }
    let (core, pre) = core_pre
        .split_once('-')
        .map_or((core_pre, None), |(c, p)| (c, Some(p)));
    if pre.is_some_and(|p| !identifiers(p, true)) {
        return None;
    }
    let mut base = [None; 3];
    let mut wildcard = false;
    let mut count = 0;
    for (index, part) in core.split('.').enumerate() {
        if index >= 3 || part.is_empty() {
            return None;
        }
        count += 1;
        if matches!(part, "*" | "x" | "X") {
            wildcard = true;
            continue;
        }
        if wildcard
            || !part.bytes().all(|b| b.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return None;
        }
        let number = part.parse::<u64>().ok()?;
        if number > MAX_SAFE {
            return None;
        }
        base[index] = Some(number);
    }
    let parsed = RangeVersion { base, pre };
    if count == 0 || ((pre.is_some() || build.is_some()) && !parsed.complete()) {
        return None;
    }
    Some(parsed)
}
fn version(value: &str) -> Option<Version<'_>> {
    let parsed = range_version(value)?;
    if !parsed.complete() {
        return None;
    }
    parsed.lower()
}

struct Selector<'a> {
    comparators: Vec<Comparator<'a>>,
    clauses: Vec<std::ops::Range<usize>>,
}
impl<'a> Selector<'a> {
    fn parse(raw: &'a str) -> Option<Self> {
        if raw.len() > 1024 && raw.chars().count() > 1024 {
            return None;
        }
        let normalized = trim(raw);
        let normalized = if normalized.is_empty() || normalized == "latest" {
            "*"
        } else {
            normalized
        };
        let mut result = Self {
            comparators: Vec::new(),
            clauses: Vec::new(),
        };
        for clause in normalized.split("||") {
            if result.clauses.len() == 32 {
                return None;
            }
            let clause = trim(clause);
            if clause.is_empty() || clause.contains(',') {
                return None;
            }
            let start = result.comparators.len();
            let tokens = clause.split(python_space).filter(|t| !t.is_empty());
            let mut probe = tokens.clone();
            let lower = probe.next()?;
            let middle = probe.next();
            let upper = probe.next();
            if middle == Some("-") && upper.is_some() && probe.next().is_none() {
                let lower = range_version(lower)?;
                let upper = range_version(upper?)?;
                if let Some(v) = lower.lower() {
                    result.push(Op::Ge, v)?;
                }
                if let Some(v) = upper.lower() {
                    result.push(
                        if upper.complete() { Op::Le } else { Op::Lt },
                        if upper.complete() { v } else { upper.upper() },
                    )?;
                }
            } else {
                let mut token_count = 0;
                for token in tokens {
                    token_count += 1;
                    if token_count > 64 {
                        return None;
                    }
                    result.expand(token)?;
                    if result.comparators.len() - start > 64 {
                        return None;
                    }
                }
            }
            // Remove redundant stable >=0.0.0 only after enforcing limits.
            let mut retained = start;
            for index in start..result.comparators.len() {
                let comparator = result.comparators[index];
                if comparator.op == Op::Ge
                    && comparator.version
                        == (Version {
                            base: [0; 3],
                            pre: None,
                        })
                {
                    continue;
                }
                result.comparators[retained] = comparator;
                retained += 1;
            }
            result.comparators.truncate(retained);
            result.clauses.push(start..retained);
        }
        Some(result)
    }
    fn push(&mut self, op: Op, version: Version<'a>) -> Option<()> {
        if version.base.iter().any(|&v| v > MAX_SAFE) {
            return None;
        }
        self.comparators.push(Comparator { op, version });
        Some(())
    }
    fn expand(&mut self, token: &'a str) -> Option<()> {
        if let Some(raw) = token.strip_prefix('^').or_else(|| token.strip_prefix('~')) {
            let parsed = range_version(raw)?;
            let Some(lower) = parsed.lower() else {
                return Some(());
            };
            let [major, minor, patch] = lower.base;
            let base = if token.starts_with('~') {
                if parsed.base[1].is_none() {
                    [major + 1, 0, 0]
                } else {
                    [major, minor + 1, 0]
                }
            } else if major > 0 || parsed.base[1].is_none() {
                [major + 1, 0, 0]
            } else if minor > 0 || parsed.base[2].is_none() {
                [0, minor + 1, 0]
            } else {
                [0, 0, patch + 1]
            };
            self.push(Op::Ge, lower)?;
            return self.push(
                Op::Lt,
                Version {
                    base,
                    pre: Some("0"),
                },
            );
        }
        let (op, raw) = if let Some(v) = token.strip_prefix(">=") {
            (Op::Ge, v)
        } else if let Some(v) = token.strip_prefix("<=") {
            (Op::Le, v)
        } else if let Some(v) = token.strip_prefix('>') {
            (Op::Gt, v)
        } else if let Some(v) = token.strip_prefix('<') {
            (Op::Lt, v)
        } else {
            (Op::Eq, token.strip_prefix('=').unwrap_or(token))
        };
        let parsed = range_version(raw)?;
        let Some(lower) = parsed.lower() else {
            return if matches!(op, Op::Eq | Op::Ge | Op::Le) {
                Some(())
            } else {
                self.push(
                    Op::Lt,
                    Version {
                        base: [0; 3],
                        pre: Some("0"),
                    },
                )
            };
        };
        if parsed.complete() {
            return self.push(op, lower);
        }
        match op {
            Op::Eq => {
                self.push(Op::Ge, lower)?;
                self.push(Op::Lt, parsed.upper())
            }
            Op::Ge => self.push(Op::Ge, lower),
            Op::Gt => self.push(
                Op::Ge,
                Version {
                    pre: None,
                    ..parsed.upper()
                },
            ),
            Op::Le => self.push(Op::Lt, parsed.upper()),
            Op::Lt => self.push(
                Op::Lt,
                Version {
                    pre: Some("0"),
                    ..lower
                },
            ),
        }
    }
    fn matches(&self, candidate: Version<'_>) -> bool {
        self.clauses.iter().any(|range| {
            let comparators = &self.comparators[range.clone()];
            comparators.iter().all(|&c| c.matches(candidate))
                && (candidate.pre.is_none()
                    || comparators
                        .iter()
                        .any(|c| c.version.pre.is_some() && c.version.base == candidate.base))
        })
    }
}

pub fn version_matches_js_selector(candidate: &str, selector: &str) -> bool {
    let Some(candidate) = version(candidate) else {
        return false;
    };
    Selector::parse(selector).is_some_and(|s| s.matches(candidate))
}

pub fn highest_js_version_for_selector<'a>(
    versions: &'a [String],
    selector: &str,
) -> Option<&'a str> {
    let selector = Selector::parse(selector)?;
    let mut best: Option<(Version<'a>, &'a str)> = None;
    for raw in versions {
        let Some(candidate) = version(raw) else {
            continue;
        };
        if !selector.matches(candidate) {
            continue;
        }
        if best.is_none_or(|(previous, previous_raw)| {
            candidate > previous || (candidate == previous && raw.as_str() > previous_raw)
        }) {
            best = Some((candidate, raw));
        }
    }
    best.map(|(_, raw)| raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prereleases_require_admission_in_the_matching_clause() {
        assert!(!version_matches_js_selector(
            "1.2.3-beta.2",
            "^1.2.3 || >=2.0.0-beta.1"
        ));
        assert!(version_matches_js_selector(
            "1.2.3-beta.2",
            ">=1.2.3-beta.1 <2.0.0"
        ));
        assert!(!version_matches_js_selector(
            "1.3.0-beta.1",
            ">=1.2.3-beta.1 <2.0.0"
        ));
        assert!(version_matches_js_selector("0.0.0-beta", "* >=0.0.0-alpha"));
    }
    #[test]
    fn malformed_clauses_and_overflow_invalidate_the_entire_selector() {
        assert!(!version_matches_js_selector("1.2.3", "^1 || nonsense"));
        assert!(!version_matches_js_selector("1.2.3", "^1 ||"));
        assert!(!version_matches_js_selector(
            "1.2.3",
            "^1 || ^9007199254740991"
        ));
        assert!(!version_matches_js_selector("01.2.3", "*"));
        assert!(!version_matches_js_selector("1.2.3-01", "*"));
        assert!(!version_matches_js_selector(
            "1.2.3",
            &vec!["*"; 33].join("||")
        ));
    }
    #[test]
    fn partial_caret_tilde_and_hyphen_boundaries_are_not_approximated() {
        for (selector, inside, outside) in [
            ("^0.0.3", "0.0.3", "0.0.4"),
            ("^0.2.3", "0.2.9", "0.3.0"),
            ("~1.2.3", "1.2.9", "1.3.0"),
            ("1.2.x", "1.2.9", "1.3.0"),
            ("1.2 - 2.3", "2.3.99", "2.4.0"),
            (">1.2", "1.3.0", "1.2.99"),
        ] {
            assert!(version_matches_js_selector(inside, selector));
            assert!(!version_matches_js_selector(outside, selector));
        }
    }
    #[test]
    fn highest_version_obeys_prerelease_order_and_raw_tie_breaking() {
        let values: Vec<String> = [
            "1.0.0-beta.11",
            "1.0.0-beta.2",
            "1.0.0-beta.11+aaa",
            "1.0.0-beta.11+zzz",
            "2.0.0-alpha",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert_eq!(
            highest_js_version_for_selector(&values, ">=1.0.0-beta.1 <2.0.0"),
            Some("1.0.0-beta.11+zzz")
        );
        assert_eq!(highest_js_version_for_selector(&values, "*"), None);
    }
}
