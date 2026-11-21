//! Native direct-tool validation helpers.
use super::*;

// ===========================================================================
// Routing and loader controls shared by the baseline diagnostic recognizer.
// ===========================================================================

static EXECUTION_ROUTING_ENVIRONMENT: &[&str] = &[
    "BASH_ENV",
    "CURL_CA_BUNDLE",
    "ENV",
    "GH_CONFIG_DIR",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "ALL_PROXY",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "ZDOTDIR",
    "all_proxy",
    "https_proxy",
    "http_proxy",
];

static LOADER_PATH_ENVIRONMENT: &[&str] = &[
    "DYLD_FALLBACK_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
];

pub(super) fn shell_read_execution_environment_is_safe(
    cwd: &Path,
    authority: &dyn DirectToolAuthority,
) -> bool {
    if EXECUTION_ROUTING_ENVIRONMENT.iter().any(|key| {
        authority
            .environment()
            .get(*key)
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
    }) {
        return false;
    }
    for (key, value) in authority.environment() {
        if value.is_empty()
            || !(key.starts_with("BASH_FUNC_")
                || key.starts_with("DYLD_")
                || key.starts_with("LD_"))
        {
            continue;
        }
        if !LOADER_PATH_ENVIRONMENT.contains(&key.as_str())
            || !trusted_loader_paths(value, cwd, authority)
        {
            return false;
        }
    }
    true
}

pub(super) fn trusted_loader_paths(
    value: &str,
    cwd: &Path,
    authority: &dyn DirectToolAuthority,
) -> bool {
    let paths: Vec<&str> = value.split(if cfg!(windows) { ';' } else { ':' }).collect();
    if paths.is_empty() || paths.iter().any(|item| item.is_empty()) {
        return false;
    }
    for item in paths {
        let mut candidate = PathBuf::from(item);
        if !candidate.is_absolute() {
            candidate = cwd.join(candidate);
        }
        let resolved = match candidate.canonicalize() {
            Ok(resolved) => resolved,
            Err(_) => return false,
        };
        if authority
            .temp_directory()
            .canonicalize()
            .is_ok_and(|root| resolved.starts_with(root))
            || !authority.trusted_path(&resolved, cwd)
        {
            return false;
        }
    }
    true
}
