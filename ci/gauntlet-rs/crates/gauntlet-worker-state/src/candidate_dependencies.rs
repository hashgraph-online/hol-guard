//! Pure PEP 508/440 dependency evaluation for an inert candidate METADATA.
//! Filesystem custody and interpreter identity are separate caller duties.

use gauntlet_evidence::valid_package_version;
use pep508_rs::pep440_rs::Version;
use pep508_rs::{MarkerEnvironment, Requirement, VerbatimUrl, VersionOrUrl};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

const MAX_METADATA: usize = 128 * 1024;
const MAX_REQUIREMENTS: usize = 256;
const MAX_REQUIREMENT: usize = 4096;
const MAX_IDENTITY: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateDependencyError {
    InvalidMetadata,
    WrongProduct,
    InvalidRequirement,
    UnsupportedMarker,
    DirectUrl,
    MissingBaseline,
    InvalidBaselineVersion,
    VersionMismatch,
}

impl fmt::Display for CandidateDependencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidMetadata => "bounded candidate distribution metadata required",
            Self::WrongProduct => "candidate distribution name or version differs",
            Self::InvalidRequirement => "candidate dependency declaration is malformed",
            Self::UnsupportedMarker => "candidate dependency marker has an ambiguous evaluation",
            Self::DirectUrl => "candidate dependency requires an unreviewed direct URL",
            Self::MissingBaseline => "candidate dependency is absent from reviewed baseline",
            Self::InvalidBaselineVersion => "reviewed baseline dependency version is malformed",
            Self::VersionMismatch => "reviewed baseline dependency violates candidate specifier",
        })
    }
}

impl std::error::Error for CandidateDependencyError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateDependencyProof {
    pub requirements: usize,
    pub active: usize,
    pub inactive: usize,
    pub active_names: Vec<String>,
}

pub(crate) fn metadata_headers(
    raw: &[u8],
) -> Result<Vec<(String, String)>, CandidateDependencyError> {
    if raw.is_empty() || raw.len() > MAX_METADATA {
        return Err(CandidateDependencyError::InvalidMetadata);
    }
    let text = std::str::from_utf8(raw).map_err(|_| CandidateDependencyError::InvalidMetadata)?;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut terminated = false;
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            terminated = true;
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            let Some((key, value)) = headers.last_mut() else {
                return Err(CandidateDependencyError::InvalidMetadata);
            };
            if key.eq_ignore_ascii_case("Name") || key.eq_ignore_ascii_case("Version") {
                return Err(CandidateDependencyError::InvalidMetadata);
            }
            let limit = if key.eq_ignore_ascii_case("Requires-Dist") {
                MAX_REQUIREMENT
            } else {
                MAX_METADATA
            };
            if value.len() + 1 + line.trim().len() > limit {
                return Err(CandidateDependencyError::InvalidMetadata);
            }
            value.push(' ');
            value.push_str(line.trim());
            continue;
        }
        let (key, value) = line
            .split_once(':')
            .ok_or(CandidateDependencyError::InvalidMetadata)?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || headers.len() >= 1024
        {
            return Err(CandidateDependencyError::InvalidMetadata);
        }
        let limit = if key.eq_ignore_ascii_case("Name") || key.eq_ignore_ascii_case("Version") {
            MAX_IDENTITY
        } else if key.eq_ignore_ascii_case("Requires-Dist") {
            MAX_REQUIREMENT
        } else {
            MAX_METADATA
        };
        if value.len() > limit {
            return Err(CandidateDependencyError::InvalidMetadata);
        }
        headers.push((key.to_owned(), value.trim().to_owned()));
    }
    if !terminated {
        return Err(CandidateDependencyError::InvalidMetadata);
    }
    Ok(headers)
}

pub(crate) fn normalize_name(name: &str) -> String {
    name.to_ascii_lowercase().replace('_', "-")
}

/// Evaluate the candidate's declared requirements against already inventoried
/// baseline versions. This function does not read files or import packages.
pub fn check_candidate_dependencies(
    metadata: &[u8],
    expected_version: &str,
    installed_versions: &BTreeMap<String, String>,
    environment: &MarkerEnvironment,
) -> Result<CandidateDependencyProof, CandidateDependencyError> {
    if !valid_package_version(expected_version) {
        return Err(CandidateDependencyError::WrongProduct);
    }
    let headers = metadata_headers(metadata)?;
    let mut name = None;
    let mut version = None;
    let mut requirements = Vec::new();
    for (key, value) in headers {
        if key.eq_ignore_ascii_case("Name") {
            if name.replace(value).is_some() {
                return Err(CandidateDependencyError::InvalidMetadata);
            }
        } else if key.eq_ignore_ascii_case("Version") {
            if version.replace(value).is_some() {
                return Err(CandidateDependencyError::InvalidMetadata);
            }
        } else if key.eq_ignore_ascii_case("Requires-Dist") {
            if requirements.len() >= MAX_REQUIREMENTS || value.is_empty() {
                return Err(CandidateDependencyError::InvalidMetadata);
            }
            requirements.push(value);
        }
    }
    if name.as_deref() != Some("hol-guard") || version.as_deref() != Some(expected_version) {
        return Err(CandidateDependencyError::WrongProduct);
    }
    let mut active_names = BTreeSet::new();
    let mut active = 0;
    let mut inactive = 0;
    for raw in &requirements {
        let requirement = Requirement::<VerbatimUrl>::from_str(raw)
            .map_err(|_| CandidateDependencyError::InvalidRequirement)?;
        let (applies, warnings) = requirement.evaluate_markers_and_report(environment, &[]);
        if !warnings.is_empty() {
            return Err(CandidateDependencyError::UnsupportedMarker);
        }
        if !applies {
            inactive += 1;
            continue;
        }
        active += 1;
        let key = normalize_name(requirement.name.as_ref());
        let installed = installed_versions
            .get(&key)
            .ok_or(CandidateDependencyError::MissingBaseline)?;
        let installed = Version::from_str(installed)
            .map_err(|_| CandidateDependencyError::InvalidBaselineVersion)?;
        match requirement.version_or_url {
            Some(VersionOrUrl::Url(_)) => return Err(CandidateDependencyError::DirectUrl),
            Some(VersionOrUrl::VersionSpecifier(specifiers))
                if !specifiers.contains(&installed) =>
            {
                return Err(CandidateDependencyError::VersionMismatch);
            }
            _ => (),
        }
        active_names.insert(key);
    }
    Ok(CandidateDependencyProof {
        requirements: requirements.len(),
        active,
        inactive,
        active_names: active_names.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pep508_rs::MarkerEnvironmentBuilder;

    fn environment() -> MarkerEnvironment {
        MarkerEnvironment::try_from(MarkerEnvironmentBuilder {
            implementation_name: "cpython",
            implementation_version: "3.12.3",
            os_name: "posix",
            platform_machine: "aarch64",
            platform_python_implementation: "CPython",
            platform_release: "6.8.0",
            platform_system: "Linux",
            platform_version: "#1",
            python_full_version: "3.12.3",
            python_version: "3.12",
            sys_platform: "linux",
        })
        .unwrap()
    }

    fn metadata() -> Vec<u8> {
        b"Metadata-Version: 2.4\nName: hol-guard\nVersion: 3.48.0\nRequires-Dist: cryptography>=50.0.0\nRequires-Dist: idna==3.15\nRequires-Dist: mcp<2,>=1.28.1; python_version >= '3.10'\nRequires-Dist: tomli>=2.0; python_version < '3.11'\nRequires-Dist: cisco-ai-skill-scanner~=2.0.12; extra == 'cisco'\n\n"
            .to_vec()
    }

    fn baseline() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("cryptography".to_owned(), "50.0.0".to_owned()),
            ("idna".to_owned(), "3.15".to_owned()),
            ("mcp".to_owned(), "1.28.1".to_owned()),
        ])
    }

    #[test]
    fn active_python312_requirements_pass_and_inactive_extras_do_not_need_install() {
        let proof =
            check_candidate_dependencies(&metadata(), "3.48.0", &baseline(), &environment())
                .unwrap();
        assert_eq!(proof.requirements, 5);
        assert_eq!(proof.active, 3);
        assert_eq!(proof.inactive, 2);
        assert_eq!(proof.active_names, ["cryptography", "idna", "mcp"]);
    }

    #[test]
    fn wrong_identity_missing_or_unsatisfied_dependency_and_url_refuse() {
        assert_eq!(
            check_candidate_dependencies(&metadata(), "3.49.0", &baseline(), &environment()),
            Err(CandidateDependencyError::WrongProduct)
        );
        let mut missing = baseline();
        missing.remove("idna");
        assert_eq!(
            check_candidate_dependencies(&metadata(), "3.48.0", &missing, &environment()),
            Err(CandidateDependencyError::MissingBaseline)
        );
        let mut stale = baseline();
        stale.insert("idna".to_owned(), "3.14".to_owned());
        assert_eq!(
            check_candidate_dependencies(&metadata(), "3.48.0", &stale, &environment()),
            Err(CandidateDependencyError::VersionMismatch)
        );
        let url = b"Name: hol-guard\nVersion: 3.48.0\nRequires-Dist: idna @ https://example.invalid/idna.whl\n\n";
        assert_eq!(
            check_candidate_dependencies(url, "3.48.0", &baseline(), &environment()),
            Err(CandidateDependencyError::DirectUrl)
        );
    }

    #[test]
    fn unrelated_long_folded_metadata_is_bounded_but_does_not_block_identity() {
        let mut raw = b"Name: hol-guard\nVersion: 3.48.0\nDescription: details\n".to_vec();
        raw.extend_from_slice(b" ");
        raw.extend(std::iter::repeat_n(b'a', 5000));
        raw.extend_from_slice(b"\nRequires-Dist: idna==3.15\n\n");
        let proof =
            check_candidate_dependencies(&raw, "3.48.0", &baseline(), &environment()).unwrap();
        assert_eq!(proof.requirements, 1);
        assert_eq!(proof.active_names, ["idna"]);
    }
}
