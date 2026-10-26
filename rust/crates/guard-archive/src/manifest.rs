//! Manifest and build-hook risk policy for archive members.
//!
//! Ported from `offline_archive_policy.py`; every code/message pair is
//! load-bearing for the caller's stable result contract.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

static NPM_REGISTRY_ALIAS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^npm:(?:@[a-z0-9][a-z0-9._~-]*/[a-z0-9][a-z0-9._~-]*|[a-z0-9][a-z0-9._~-]*)(?:@[^\s:/\\]+)?$",
    )
    .expect("npm alias regex is a compile-time constant")
});
static CREDENTIAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:npm_token|node_auth_token|_authtoken|pypi_token)\b|\.npmrc|\.pypirc")
        .expect("credential regex is a compile-time constant")
});
static EXFIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:curl|wget|axios|urllib)\b|\bhttps?\.request\b|\bfetch\s*\(|\brequests\.")
        .expect("exfiltration regex is a compile-time constant")
});
static EXTERNAL_SPEC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"@(?:https?|file|link|git\+https?|git\+ssh):")
        .expect("external specifier regex is a compile-time constant")
});

const DEPENDENCY_GROUPS: [&str; 4] = [
    "dependencies",
    "optionalDependencies",
    "peerDependencies",
    "devDependencies",
];

const INSTALL_SCRIPT_KEYS: [&str; 7] = [
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
];

const MANIFEST_INVALID: (&str, &str) = (
    "external_archive_manifest_invalid",
    "External archive contains an invalid package manifest.",
);

/// `_install_script_risk`: dependency-source and install-script policy for a
/// bounded `package.json` payload.
pub fn install_script_risk(payload: &[u8]) -> Option<(&'static str, &'static str)> {
    // Parity note: the retired worker decoded UTF-8 then called json.loads,
    // which rejects a BOM-prefixed manifest; serde_json does the same.
    let parsed: Value = match serde_json::from_slice(payload) {
        Ok(value) => value,
        Err(_) => return Some(MANIFEST_INVALID),
    };
    let Some(object) = parsed.as_object() else {
        return Some(MANIFEST_INVALID);
    };
    for group in DEPENDENCY_GROUPS {
        // JSON null is a present-but-absent field, matching `get() is None`.
        let Some(dependencies) = object.get(group).filter(|value| !value.is_null()) else {
            continue;
        };
        let Some(table) = dependencies.as_object() else {
            return Some((
                "external_archive_manifest_invalid",
                "External archive contains an invalid dependency declaration.",
            ));
        };
        if table
            .iter()
            .any(|(_name, specifier)| !specifier.is_string())
        {
            return Some((
                "external_archive_manifest_invalid",
                "External archive contains an invalid dependency declaration.",
            ));
        }
        if table.values().any(|specifier| {
            specifier
                .as_str()
                .is_some_and(npm_specifier_requires_external_fetch)
        }) {
            return Some((
                "external_archive_nested_source_dependency",
                "External archive declares a non-registry source dependency that cannot be digest-bound.",
            ));
        }
    }
    let scripts = object.get("scripts").filter(|value| !value.is_null())?;
    let Some(table) = scripts.as_object() else {
        return Some((
            "external_archive_manifest_invalid",
            "External archive contains an invalid package script declaration.",
        ));
    };
    for key in INSTALL_SCRIPT_KEYS {
        let Some(value) = table.get(key) else {
            continue;
        };
        let Some(command) = value.as_str() else {
            continue;
        };
        if command.trim().is_empty() {
            continue;
        }
        let normalized = command.to_lowercase();
        if CREDENTIAL_RE.is_match(&normalized) && EXFIL_RE.is_match(&normalized) {
            return Some((
                "credential_theft_install_script",
                "External archive install script attempts to read credentials and exfiltrate them.",
            ));
        }
        return Some((
            "tarball_install_script",
            "External archive declares install-time scripts and was blocked.",
        ));
    }
    None
}

/// `_npm_dependency_specifier_requires_external_fetch`: registry-only
/// specifiers return false; anything that could fetch elsewhere returns true.
fn npm_specifier_requires_external_fetch(specifier: &str) -> bool {
    let normalized = specifier.trim().to_lowercase();
    if normalized.is_empty() {
        return true;
    }
    const EXTERNAL_PREFIXES: [&str; 17] = [
        "http:",
        "https:",
        "file:",
        "link:",
        "git:",
        "git+",
        "github:",
        "gitlab:",
        "bitbucket:",
        "ssh:",
        "workspace:",
        "portal:",
        "patch:",
        "./",
        "../",
        "/",
        "~",
    ];
    if EXTERNAL_PREFIXES
        .iter()
        .any(|prefix| normalized.starts_with(prefix))
    {
        return true;
    }
    if normalized.starts_with("git@") {
        return true;
    }
    if normalized.starts_with("npm:") {
        // npm aliases remain registry-only only when both the aliased package
        // and optional selector are plain registry syntax. Nested protocols
        // such as npm:pkg@exec:... must not inherit this exception.
        return !NPM_REGISTRY_ALIAS_RE.is_match(&normalized);
    }
    if normalized.contains(':') || normalized.contains('\\') {
        return true;
    }
    if normalized.contains('/') {
        return true;
    }
    EXTERNAL_SPEC_RE.is_match(&normalized)
}

/// `_python_build_script_risk`: the presence of Python build metadata is the
/// risk; the payload is never inspected (parity with the Python policy).
pub fn python_build_script_risk(filename: &str) -> Option<(&'static str, &'static str)> {
    match filename {
        "setup.py" => Some((
            "python_build_script_risk",
            "External archive contains executable legacy Python build metadata.",
        )),
        "pyproject.toml" => Some((
            "python_build_backend_risk",
            "External archive declares Python build hooks that cannot be safely executed offline.",
        )),
        _ => None,
    }
}
