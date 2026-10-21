//! Rust port of `runtime/supply_chain_package_identity.py` — canonical
//! identities for supply-chain package records and targets.
//!
//! `CanonicalPackageIdentity` mirrors the frozen, order-able dataclass: the
//! tuple ordering (ecosystem, namespace, name, version) is preserved via
//! derived `Ord` on an `Option<String>` namespace, which matches Python's
//! `None < any str` tuple ordering for the comparisons this port performs.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::LazyLock;

use regex::Regex;

/// `_LOWERCASE_ECOSYSTEMS` (:8).
fn lowercase_ecosystems() -> &'static BTreeSet<&'static str> {
    static SET: LazyLock<BTreeSet<&'static str>> =
        LazyLock::new(|| ["npm", "packagist", "pypi"].into_iter().collect());
    &SET
}

/// `_NPM_SCOPE_RE` (:9) — `re.compile(r"^@[^/@]+$")`.
static NPM_SCOPE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^@[^/@]+$").expect("NPM_SCOPE_RE"));

/// `re.sub(r"[-_.]+", "-", value)` for PyPI normalization (:41).
static PYPI_SEPARATOR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[-_.]+").expect("PYPI_SEPARATOR_RE"));

/// `PackageIdentityError(ValueError)` (:12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageIdentityError(pub String);

impl fmt::Display for PackageIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PackageIdentityError {}

pub type PackageIdentityResult<T> = Result<T, PackageIdentityError>;

/// `CanonicalPackageIdentity` (:16) — frozen + order-able dataclass mirror.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalPackageIdentity {
    pub ecosystem: String,
    pub namespace: Option<String>,
    pub name: String,
    pub version: String,
}

impl CanonicalPackageIdentity {
    /// `qualified_name` (:27).
    pub fn qualified_name(&self) -> String {
        match &self.namespace {
            Some(namespace) => format!("{}/{}", namespace, self.name),
            None => self.name.clone(),
        }
    }

    /// `display` (:31).
    pub fn display(&self) -> String {
        format!(
            "{}:{}@{}",
            self.ecosystem,
            self.qualified_name(),
            self.version
        )
    }
}

/// `normalize_ecosystem(ecosystem)` (:34).
pub fn normalize_ecosystem(ecosystem: &str) -> PackageIdentityResult<String> {
    let normalized = ecosystem.trim().to_lowercase();
    if normalized.is_empty() {
        return Err(PackageIdentityError(
            "Package ecosystem cannot be empty".to_string(),
        ));
    }
    Ok(normalized)
}

/// `normalize_package_component(ecosystem, value)` (:43).
pub fn normalize_package_component(ecosystem: &str, value: &str) -> PackageIdentityResult<String> {
    let normalized_ecosystem = normalize_ecosystem(ecosystem)?;
    let mut normalized = value.trim().to_string();
    if normalized.is_empty() {
        return Err(PackageIdentityError(
            "Package name components cannot be empty".to_string(),
        ));
    }
    if lowercase_ecosystems().contains(normalized_ecosystem.as_str()) {
        normalized = normalized.to_lowercase();
    }
    if normalized_ecosystem == "pypi" {
        normalized = PYPI_SEPARATOR_RE.replace_all(&normalized, "-").to_string();
    }
    Ok(normalized)
}

/// `canonical_package_identity(ecosystem=, namespace=, name=, version=)` (:51).
pub fn canonical_package_identity(
    ecosystem: &str,
    namespace: Option<&str>,
    name: &str,
    version: &str,
) -> PackageIdentityResult<CanonicalPackageIdentity> {
    let normalized_ecosystem = normalize_ecosystem(ecosystem)?;
    let normalized_version = version.trim().to_string();
    if normalized_version.is_empty() {
        return Err(PackageIdentityError(
            "Package version cannot be empty".to_string(),
        ));
    }
    let normalized_namespace = match namespace {
        Some(value) => Some(normalize_package_component(&normalized_ecosystem, value)?),
        None => None,
    };
    let normalized_name = normalize_package_component(&normalized_ecosystem, name)?;
    match normalized_ecosystem.as_str() {
        "npm" => {
            if let Some(ns) = &normalized_namespace {
                if !NPM_SCOPE_RE.is_match(ns) {
                    return Err(PackageIdentityError(
                        "npm namespace must be one non-empty @scope".to_string(),
                    ));
                }
            }
            if normalized_name.starts_with('@') || normalized_name.contains('/') {
                return Err(PackageIdentityError(
                    "npm name must be an unqualified leaf name".to_string(),
                ));
            }
        }
        "pypi" => {
            if normalized_namespace.is_some() || normalized_name.contains('/') {
                return Err(PackageIdentityError(
                    "PyPI package identities cannot contain a namespace".to_string(),
                ));
            }
        }
        "packagist" => {
            let invalid = match &normalized_namespace {
                None => true,
                Some(ns) => ns.contains('/') || normalized_name.contains('/'),
            };
            if invalid {
                return Err(PackageIdentityError(
                    "Packagist identity must contain vendor and package components".to_string(),
                ));
            }
        }
        _ => {}
    }
    Ok(CanonicalPackageIdentity {
        ecosystem: normalized_ecosystem,
        namespace: normalized_namespace,
        name: normalized_name,
        version: normalized_version,
    })
}

/// `parse_package_identity(ecosystem=, package_name=, version=)` (:91).
pub fn parse_package_identity(
    ecosystem: &str,
    package_name: &str,
    version: &str,
) -> PackageIdentityResult<CanonicalPackageIdentity> {
    let normalized_ecosystem = normalize_ecosystem(ecosystem)?;
    let value = package_name.trim().to_string();
    if value.is_empty() {
        return Err(PackageIdentityError(
            "Package name cannot be empty".to_string(),
        ));
    }
    let mut namespace: Option<&str> = None;
    let mut name: &str = value.as_str();
    match normalized_ecosystem.as_str() {
        "npm" => {
            if value.starts_with('@') {
                if value.matches('/').count() != 1 {
                    return Err(PackageIdentityError(
                        "Scoped npm name must be exactly @scope/name".to_string(),
                    ));
                }
                let (ns, leaf) = value.split_once('/').expect("count-checked slash");
                namespace = Some(ns);
                name = leaf;
            } else if value.contains('/') {
                return Err(PackageIdentityError(
                    "Unscoped npm name cannot contain a slash".to_string(),
                ));
            }
        }
        "packagist" => {
            if value.matches('/').count() != 1 {
                return Err(PackageIdentityError(
                    "Packagist name must be exactly vendor/package".to_string(),
                ));
            }
            let (ns, leaf) = value.split_once('/').expect("count-checked slash");
            namespace = Some(ns);
            name = leaf;
        }
        _ => {}
    }
    canonical_package_identity(&normalized_ecosystem, namespace, name, version)
}

/// `normalize_qualified_package_name(ecosystem, package_name)` (:117).
pub fn normalize_qualified_package_name(
    ecosystem: &str,
    package_name: &str,
) -> PackageIdentityResult<String> {
    Ok(parse_package_identity(ecosystem, package_name, "*")?.qualified_name())
}
