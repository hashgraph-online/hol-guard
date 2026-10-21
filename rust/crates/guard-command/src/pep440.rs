//! PEP 440 package versions and Python-compatible specifier membership.
//! Keep canonical rendering beside the parsed version; package results consume
//! the rendering, while comparisons and membership never reparse it.

use pep440_rs::{Operator, VersionSpecifier};
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct Version {
    pub normalized: String,
    parsed: pep440_rs::Version,
}
impl Version {
    pub fn parse(value: &str) -> Result<Self, String> {
        let parsed = pep440_rs::Version::from_str(value.trim_matches(python_space))
            .map_err(|e| e.to_string())?;
        Ok(Self {
            normalized: parsed.to_string(),
            parsed,
        })
    }
    pub fn release(&self) -> &[u64] {
        self.parsed.release()
    }
}
impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.parsed == other.parsed
    }
}
impl Eq for Version {}
impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.parsed.cmp(&other.parsed)
    }
}
impl Hash for Version {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.parsed.hash(state);
    }
}

#[derive(Debug, Clone)]
pub struct SpecifierSet {
    standard: Vec<VersionSpecifier>,
    exact: Vec<String>,
}
fn python_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}
impl SpecifierSet {
    pub fn parse(value: &str) -> Result<Self, String> {
        let mut result = Self {
            standard: Vec::new(),
            exact: Vec::new(),
        };
        for raw in value.split(',') {
            let raw = raw.trim_matches(python_space);
            if raw.is_empty() {
                continue;
            }
            if let Some(exact) = raw.strip_prefix("===") {
                let exact = exact.trim_matches(python_space);
                if exact
                    .chars()
                    .any(|c| python_space(c) || matches!(c, ';' | ')'))
                {
                    return Err("invalid arbitrary equality specifier".into());
                }
                // Arbitrary equality compares canonical candidate spelling,
                // not PEP 440 ordering (1.0 and 1.0.0 must remain distinct).
                result.exact.push(exact.to_lowercase());
            } else {
                let specifier = VersionSpecifier::from_str(raw).map_err(|e| e.to_string())?;
                result.standard.push(specifier);
            }
        }
        Ok(result)
    }
    pub fn contains(&self, candidate: &Version) -> bool {
        // packaging 26 single-candidate membership permits matching prereleases.
        // Exclusive comparison operators still apply their PEP 440 exclusions.
        self.standard
            .iter()
            .all(|s| standard_matches(s, &candidate.parsed))
            && self.exact.iter().all(|s| s == &candidate.normalized)
    }
}

fn standard_matches(specifier: &VersionSpecifier, candidate: &pep440_rs::Version) -> bool {
    match specifier.operator() {
        Operator::EqualStar | Operator::NotEqualStar => {
            let bound = specifier.version();
            let prefix_matches = candidate.epoch() == bound.epoch()
                && bound.release().iter().enumerate().all(|(index, number)| {
                    candidate.release().get(index).copied().unwrap_or(0) == *number
                });
            if specifier.operator() == &Operator::EqualStar {
                prefix_matches
            } else {
                !prefix_matches
            }
        }
        _ => specifier.contains(candidate),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn matches(candidate: &str, selector: &str) -> bool {
        SpecifierSet::parse(selector)
            .unwrap()
            .contains(&Version::parse(candidate).unwrap())
    }
    #[test]
    fn ordering_includes_epochs_prereleases_and_local_numeric_segments() {
        let values = [
            "1.0.dev1",
            "1.0a1",
            "1.0b1",
            "1.0rc1",
            "1.0",
            "1.0+abc",
            "1.0+1",
            "1.0.post1",
            "1!0.1",
        ];
        for pair in values.windows(2) {
            assert!(Version::parse(pair[0]).unwrap() < Version::parse(pair[1]).unwrap());
        }
        assert_eq!(
            Version::parse("1.0").unwrap(),
            Version::parse("1.0.0").unwrap()
        );
        assert!(Version::parse("garbage").is_err());
        assert_eq!(Version::parse("v01.02RC3").unwrap().release(), [1, 2]);
    }
    #[test]
    fn single_candidate_membership_preserves_matching_prereleases() {
        assert!(matches("1.5a1", ">=1.0"));
        assert!(matches("1.5a1", "!=1.2a1"));
        assert!(matches("1.5a1", ">=1.0a1"));
        assert!(matches("1.5a1", "<2.0a1"));
        assert!(matches("1.5a1", ""));
        assert!(!matches("1.5a1", "!=1.5a1"));
        assert!(!matches("1.5a1", "<1.5"));
    }
    #[test]
    fn wildcard_compatible_and_exclusive_bounds_follow_pep440() {
        assert!(matches("1.4.9", "~=1.4.5"));
        assert!(!matches("1.5.0", "~=1.4.5"));
        assert!(matches("1.2.9+local", "==1.2.*"));
        assert!(!matches("1", "==1.2.*"));
        assert!(matches("1", "==1.0.*"));
        assert!(matches("1", "!=1.2.*"));
        assert!(!matches("1!1.2", "==1.2.*"));
        assert!(!matches("1.2.post1", ">1.2"));
        assert!(!matches("1.2rc1", "<1.2,>=1.0rc1"));
        assert!(matches("1.2+local", "==1.2"));
        assert!(SpecifierSet::parse("^1.2").is_err());
        assert!(SpecifierSet::parse("~=1").is_err());
    }
    #[test]
    fn arbitrary_equality_preserves_spelling_instead_of_release_equivalence() {
        assert!(matches("1.0", "===1.0"));
        assert!(!matches("1.0.0", "===1.0"));
        assert!(!matches("1.0", "===01.0"));
        assert!(!matches("1.0", "===not-a-version"));
        assert!(matches("1.0rc1", "===1.0RC1"));
        assert!(matches("1.0+kk", "===1.0+kK"));
    }
}
