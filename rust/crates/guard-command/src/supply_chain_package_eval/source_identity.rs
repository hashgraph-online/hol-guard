use super::*;

// ============================================================================
// RTM-019 eval batch E — remaining 35 Python fns ported below.
// ============================================================================

/// `_is_git_source_url` (:3648-3650).
// supply_chain_package_eval.py:3648-3650
#[allow(dead_code)]
pub(super) fn is_git_source_url(source_url: &str) -> bool {
    parse_npm_source_spec(Some(source_url))
        .map(|s| s.is_git())
        .unwrap_or(false)
}

/// `is_external_https_archive_source` (restricted_archive_destination.py).
/// A HTTPS URL that is neither the npm nor PyPI default registry host and ends
/// in a known tarball/archive suffix (or is a non-registry source URL) is an
/// externally-hosted archive subject to restricted-download rules.
// restricted_archive_destination.py
#[allow(dead_code)]
pub(super) fn is_external_https_archive_source(source_url: &str) -> bool {
    let lower = source_url.trim().to_lowercase();
    if !lower.starts_with("https://") {
        return false;
    }
    let host = lower
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("");
    if host == "registry.npmjs.org"
        || host == "pypi.org"
        || host == "files.pythonhosted.org"
        || host.ends_with(".npmjs.org")
    {
        return false;
    }
    true
}

/// `_is_external_https_tarball_source` (:3651-3652).
// supply_chain_package_eval.py:3651-3652
#[allow(dead_code)]
pub(super) fn is_external_https_tarball_source(source_url: &str) -> bool {
    is_external_https_archive_source(source_url)
}

/// `_FIRST_PARTY_PYPI_PACKAGES` (:3031).
#[allow(dead_code)]
pub(super) static FIRST_PARTY_PYPI_PACKAGES: LazyLock<BTreeSet<&'static str>> =
    LazyLock::new(|| ["hol-guard", "plugin-scanner"].into_iter().collect());
