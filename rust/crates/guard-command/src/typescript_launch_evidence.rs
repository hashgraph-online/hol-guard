//! `typescript_launch_evidence.py` — typed evidence for reviewable local
//! TypeScript compiler launches (252 lines — verbatim port).

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

static VERSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:[~^])?(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?$").unwrap());

const SAFE_COMPILER_FLAGS: &[&str] = &[
    "--diagnostics",
    "--extendedDiagnostics",
    "--explainFiles",
    "--listFiles",
    "--listFilesOnly",
    "--noEmit",
    "--noErrorTruncation",
    "--pretty",
    "--skipLibCheck",
    "--traceResolution",
];

const UNSAFE_SOURCE_PREFIXES: &[&str] = &[
    "file:",
    "git+",
    "git://",
    "github:",
    "http://",
    "https://",
    "npm:",
    "workspace:",
];

/// `TypeScriptLaunchStatus = Literal["complete", "incomplete"]`.
pub type TypeScriptLaunchStatus = &'static str;

/// `TypeScriptLaunchInputs` (:35-51).
#[derive(Clone, Debug)]
pub struct TypeScriptLaunchInputs {
    pub tokens: Vec<String>,
    pub manager_name: String,
    pub local_only_requested: bool,
    pub package_name: Option<String>,
    pub executable_name: Option<String>,
    pub declared_version: Option<String>,
    pub manager_path: Option<String>,
    pub manager_hash: Option<String>,
    pub executable_path: Option<String>,
    pub executable_hash: Option<String>,
    pub manifest_paths: Vec<String>,
    pub manifest_hashes: Vec<String>,
    pub lockfile_paths: Vec<String>,
    pub lockfile_hashes: Vec<String>,
}

impl TypeScriptLaunchInputs {
    /// `asdict(inputs)` — sorted-key `Value` (binding payload uses
    /// `sort_keys=True` so order doesn't matter).
    fn to_value(&self) -> Value {
        json!({
            "tokens": self.tokens,
            "manager_name": self.manager_name,
            "local_only_requested": self.local_only_requested,
            "package_name": self.package_name,
            "executable_name": self.executable_name,
            "declared_version": self.declared_version,
            "manager_path": self.manager_path,
            "manager_hash": self.manager_hash,
            "executable_path": self.executable_path,
            "executable_hash": self.executable_hash,
            "manifest_paths": self.manifest_paths,
            "manifest_hashes": self.manifest_hashes,
            "lockfile_paths": self.lockfile_paths,
            "lockfile_hashes": self.lockfile_hashes,
        })
    }
}

/// `TypeScriptLaunchEvidence` (:54-75).
#[derive(Clone, Debug)]
pub struct TypeScriptLaunchEvidence {
    pub schema_version: u32,
    pub status: TypeScriptLaunchStatus,
    pub reasons: Vec<String>,
    pub binding_digest: String,
    pub manager_name: String,
    pub package_name: Option<String>,
    pub executable_name: Option<String>,
    pub declared_version: Option<String>,
    pub locked_version: Option<String>,
    pub installed_version: Option<String>,
    pub config_mode: String,
    pub source_files: Vec<String>,
    /// `evidence_scope: Literal["launch_identity"] = "launch_identity"`.
    pub evidence_scope: &'static str,
    /// `review_disposition: Literal["review_required"] = "review_required"`.
    pub review_disposition: &'static str,
    /// `direct_silent_verification: bool = False`.
    pub direct_silent_verification: bool,
}

impl TypeScriptLaunchEvidence {
    /// `asdict(self)` → dict with fields in declaration order.
    pub fn to_dict(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "status": self.status,
            "reasons": self.reasons,
            "binding_digest": self.binding_digest,
            "manager_name": self.manager_name,
            "package_name": self.package_name,
            "executable_name": self.executable_name,
            "declared_version": self.declared_version,
            "locked_version": self.locked_version,
            "installed_version": self.installed_version,
            "config_mode": self.config_mode,
            "source_files": self.source_files,
            "evidence_scope": self.evidence_scope,
            "review_disposition": self.review_disposition,
            "direct_silent_verification": self.direct_silent_verification,
        })
    }
}

/// `require` (package_evidence_common.py :90-92).
fn require(condition: bool, reason: &str, reasons: &mut Vec<String>) {
    if !condition {
        reasons.push(reason.to_owned());
    }
}

/// `build_typescript_launch_evidence` (:78-156).
pub fn build_typescript_launch_evidence(
    inputs: &TypeScriptLaunchInputs,
) -> Option<TypeScriptLaunchEvidence> {
    let package_ok = inputs
        .package_name
        .as_deref()
        .map(|n| matches!(n, "tsc" | "typescript"))
        .unwrap_or(false);
    if !package_ok && inputs.executable_name.as_deref() != Some("tsc") {
        return None;
    }

    let mut reasons: Vec<String> = Vec::new();
    require(
        inputs.manager_name == "npx",
        "manager_mismatch",
        &mut reasons,
    );
    require(
        inputs.local_only_requested,
        "remote_install_not_disabled",
        &mut reasons,
    );
    require(package_ok, "package_mismatch", &mut reasons);
    require(
        inputs.executable_name.as_deref() == Some("tsc"),
        "executable_mismatch",
        &mut reasons,
    );
    require(
        inputs.manager_path.is_some() && inputs.manager_hash.is_some(),
        "manager_identity_incomplete",
        &mut reasons,
    );
    require(
        inputs.executable_path.is_some() && inputs.executable_hash.is_some(),
        "executable_identity_incomplete",
        &mut reasons,
    );

    let (compiler_args, explicit_package) = compiler_args(&inputs.tokens);
    if explicit_package {
        reasons.push("explicit_package_source".to_owned());
    }
    let (source_files, arguments_valid) = read_only_compiler_arguments(&compiler_args);
    require(
        arguments_valid,
        "compiler_arguments_not_read_only",
        &mut reasons,
    );
    require(
        !source_files.is_empty(),
        "implicit_or_config_driven_launch",
        &mut reasons,
    );

    let (manifest_version, manifest_source_ok, manifest_identity_ok) =
        manifest_typescript_version(&inputs.manifest_paths, &inputs.manifest_hashes);
    let (locked_version, lock_source_ok, lock_identity_ok) =
        locked_typescript_version(&inputs.lockfile_paths, &inputs.lockfile_hashes);
    let (installed_version, executable_matches, installed_manifest_hash) =
        installed_typescript_identity(inputs.executable_path.as_deref());
    require(
        manifest_version.is_some(),
        "manifest_dependency_missing",
        &mut reasons,
    );
    require(manifest_source_ok, "manifest_source_drift", &mut reasons);
    require(
        manifest_identity_ok,
        "manifest_identity_drift",
        &mut reasons,
    );
    require(
        locked_version.is_some(),
        "lock_dependency_missing",
        &mut reasons,
    );
    require(lock_source_ok, "lock_source_drift", &mut reasons);
    require(lock_identity_ok, "lock_identity_drift", &mut reasons);
    require(
        installed_version.is_some(),
        "installed_package_missing",
        &mut reasons,
    );
    require(
        executable_matches,
        "wrong_typescript_executable",
        &mut reasons,
    );
    require(
        inputs.declared_version == manifest_version,
        "declared_dependency_mismatch",
        &mut reasons,
    );
    require(
        version_spec_matches(
            manifest_version.as_deref(),
            locked_version.as_deref(),
            &VERSION_RE,
            false,
        ),
        "manifest_lock_version_drift",
        &mut reasons,
    );
    require(
        locked_version == installed_version,
        "lock_install_version_drift",
        &mut reasons,
    );
    require(
        inputs.manifest_paths.len() == inputs.manifest_hashes.len(),
        "manifest_identity_incomplete",
        &mut reasons,
    );
    require(
        inputs.lockfile_paths.len() == inputs.lockfile_hashes.len(),
        "lock_identity_incomplete",
        &mut reasons,
    );

    // `dict.fromkeys` — preserve insertion order, dedup.
    let mut seen = std::collections::HashSet::new();
    let normalized_reasons: Vec<String> = reasons
        .iter()
        .filter(|r| seen.insert((*r).clone()))
        .cloned()
        .collect();

    let config_mode = if !source_files.is_empty() {
        "explicit_sources"
    } else {
        "implicit_or_config_driven"
    };
    let binding_payload = json!({
        "schema_version": 1,
        "inputs": inputs.to_value(),
        "locked_version": locked_version,
        "installed_version": installed_version,
        "installed_manifest_hash": installed_manifest_hash,
        "config_mode": config_mode,
        "source_files": source_files,
        "reasons": normalized_reasons,
    });
    // Python `json.dumps(payload, sort_keys=True, separators=(",",":"))` —
    // canonical codec.
    let mut buf = Vec::new();
    guard_contracts::write_canonical_json(&binding_payload, &mut buf).ok()?;
    let mut frame = b"hol-guard:typescript-launch-evidence:v1\x00".to_vec();
    frame.extend_from_slice(&buf);
    let binding_digest = format!("sha256:{}", hex::encode(Sha256::digest(&frame)));

    Some(TypeScriptLaunchEvidence {
        schema_version: 1,
        status: if normalized_reasons.is_empty() {
            "complete"
        } else {
            "incomplete"
        },
        reasons: normalized_reasons,
        binding_digest,
        manager_name: inputs.manager_name.clone(),
        package_name: inputs.package_name.clone(),
        executable_name: inputs.executable_name.clone(),
        declared_version: inputs.declared_version.clone(),
        locked_version: locked_version.clone(),
        installed_version: installed_version.clone(),
        config_mode: config_mode.to_owned(),
        source_files,
        evidence_scope: "launch_identity",
        review_disposition: "review_required",
        direct_silent_verification: false,
    })
}

/// `version_spec_matches` (package_evidence_common.py :95-127) — `~/^`
/// specifier vs observed version; `caret_pins_zero_major=False` keeps `^`
/// scoped to major even for `^0.x`.
fn version_spec_matches(
    specifier: Option<&str>,
    version: Option<&str>,
    version_re: &Regex,
    caret_pins_zero_major: bool,
) -> bool {
    let (Some(specifier), Some(version)) = (specifier, version) else {
        return false;
    };
    let Some(spec_match) = version_re.captures(specifier) else {
        return false;
    };
    let Some(version_match) = version_re.captures(version) else {
        return false;
    };
    let spec_parts: Vec<u64> = (1..=3)
        .filter_map(|i| spec_match.get(i))
        .filter_map(|m| m.as_str().parse().ok())
        .collect();
    let version_parts: Vec<u64> = (1..=3)
        .filter_map(|i| version_match.get(i))
        .filter_map(|m| m.as_str().parse().ok())
        .collect();
    if spec_parts.len() != 3 || version_parts.len() != 3 {
        return false;
    }
    if specifier.starts_with('^') {
        if spec_parts[0] > 0 {
            return version_parts >= spec_parts && version_parts[0] == spec_parts[0];
        }
        if caret_pins_zero_major {
            if spec_parts[1] > 0 {
                return version_parts >= spec_parts && version_parts[0..2] == spec_parts[0..2];
            }
            return version_parts == spec_parts;
        }
        return version_parts >= spec_parts && version_parts[0] == spec_parts[0];
    }
    if specifier.starts_with('~') {
        return version_parts >= spec_parts && version_parts[0..2] == spec_parts[0..2];
    }
    version_parts == spec_parts
}

/// `_compiler_args` (:159-165).
fn compiler_args(tokens: &[String]) -> (Vec<String>, bool) {
    let explicit_package = tokens[1.min(tokens.len())..]
        .iter()
        .any(|token| token == "--package" || token.starts_with("--package="));
    let executable_index = tokens.iter().skip(1).position(|t| t == "tsc");
    match executable_index {
        None => (Vec::new(), explicit_package),
        Some(index) => (
            tokens[(index + 2).min(tokens.len())..].to_vec(),
            explicit_package,
        ),
    }
}

/// `_read_only_compiler_arguments` (:168-179).
fn read_only_compiler_arguments(arguments: &[String]) -> (Vec<String>, bool) {
    if !arguments.iter().any(|a| a == "--noEmit") {
        return (Vec::new(), false);
    }
    let mut sources: Vec<String> = Vec::new();
    for argument in arguments {
        if SAFE_COMPILER_FLAGS.contains(&argument.as_str()) {
            continue;
        }
        if (argument.ends_with(".cts")
            || argument.ends_with(".mts")
            || argument.ends_with(".ts")
            || argument.ends_with(".tsx"))
            && !argument.starts_with('-')
        {
            sources.push(argument.clone());
            continue;
        }
        return (sources, false);
    }
    (sources, true)
}

/// `_manifest_typescript_version` (:182-200).
fn manifest_typescript_version(
    paths: &[String],
    hashes: &[String],
) -> (Option<String>, bool, bool) {
    let mut identity_ok = paths.len() == hashes.len();
    for (raw_path, expected_hash) in paths.iter().zip(hashes.iter()) {
        if Path::new(raw_path).file_name().and_then(|n| n.to_str()) != Some("package.json") {
            continue;
        }
        let (payload, observed_hash) = read_json(Path::new(raw_path));
        let Some(payload) = payload else {
            continue;
        };
        identity_ok = identity_ok && observed_hash.as_deref() == Some(expected_hash.as_str());
        for group in [
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ] {
            let Some(dependencies) = payload.get(group).and_then(|v| v.as_object()) else {
                continue;
            };
            if let Some(value) = dependencies.get("typescript").and_then(|v| v.as_str()) {
                let normalized = value.trim();
                if !normalized.is_empty() {
                    let lower = normalized.to_lowercase();
                    let source_ok = !UNSAFE_SOURCE_PREFIXES.iter().any(|p| lower.starts_with(p));
                    return (Some(normalized.to_owned()), source_ok, identity_ok);
                }
            }
        }
    }
    (None, false, identity_ok)
}

/// `_locked_typescript_version` (:203-226).
fn locked_typescript_version(paths: &[String], hashes: &[String]) -> (Option<String>, bool, bool) {
    let mut identity_ok = paths.len() == hashes.len();
    for (raw_path, expected_hash) in paths.iter().zip(hashes.iter()) {
        if Path::new(raw_path).file_name().and_then(|n| n.to_str()) != Some("package-lock.json") {
            continue;
        }
        let (payload, observed_hash) = read_json(Path::new(raw_path));
        identity_ok = identity_ok && observed_hash.as_deref() == Some(expected_hash.as_str());
        let Some(payload) = payload else {
            continue;
        };
        let Some(packages) = payload.get("packages").and_then(|v| v.as_object()) else {
            continue;
        };
        let Some(entry) = packages
            .get("node_modules/typescript")
            .and_then(|v| v.as_object())
        else {
            continue;
        };
        let Some(version) = entry.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        if version.trim().is_empty() {
            continue;
        }
        let resolved = entry.get("resolved").and_then(|v| v.as_str());
        let source_ok = entry.get("link").and_then(|v| v.as_bool()) != Some(true)
            && (resolved.is_none()
                || !resolved
                    .map(|r| {
                        r.to_lowercase().starts_with("file:")
                            || r.to_lowercase().starts_with("git+")
                            || r.to_lowercase().starts_with("git://")
                    })
                    .unwrap_or(false));
        return (Some(version.trim().to_owned()), source_ok, identity_ok);
    }
    (None, false, identity_ok)
}

/// `_installed_typescript_identity` (:229-243).
fn installed_typescript_identity(
    executable_path: Option<&str>,
) -> (Option<String>, bool, Option<String>) {
    let Some(executable_path) = executable_path else {
        return (None, false, None);
    };
    let executable = Path::new(executable_path);
    let name_ok = executable.file_name().and_then(|n| n.to_str()) == Some("tsc");
    let bin_parent_ok = executable
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        == Some("bin");
    let pkg_parent_ok = executable
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        == Some("typescript");
    if !(name_ok && bin_parent_ok && pkg_parent_ok) {
        return (None, false, None);
    }
    let package_manifest = executable
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("package.json"));
    let Some(package_manifest) = package_manifest else {
        return (None, false, None);
    };
    let (payload, manifest_hash) = read_json(&package_manifest);
    let Some(payload) = payload else {
        return (None, false, manifest_hash);
    };
    let version = payload.get("version").and_then(|v| v.as_str());
    let bin_target = payload
        .get("bin")
        .and_then(|v| v.as_object())
        .and_then(|m| m.get("tsc"))
        .and_then(|v| v.as_str());
    let resolved_manifest_parent = package_manifest
        .parent()
        .map(|p| p.join(bin_target.unwrap_or("")))
        .and_then(|p| std::fs::canonicalize(p).ok());
    let resolved_executable = std::fs::canonicalize(executable).ok();
    let target_ok = bin_target.is_some()
        && resolved_manifest_parent.is_some()
        && resolved_executable.is_some()
        && resolved_manifest_parent == resolved_executable;
    let version_norm = version
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty());
    (version_norm, target_ok, manifest_hash)
}

/// `_read_json` (:246-252).
fn read_json(path: &Path) -> (Option<Map<String, Value>>, Option<String>) {
    let content = match std::fs::read(path) {
        Ok(c) => c,
        Err(_) => return (None, None),
    };
    let payload: Value = match serde_json::from_slice(&content) {
        Ok(v) => v,
        Err(_) => return (None, None),
    };
    let Some(obj) = payload.as_object() else {
        return (None, None);
    };
    (
        Some(obj.clone()),
        Some(format!("sha256:{}", hex::encode(Sha256::digest(&content)))),
    )
}

// `PathBuf` referenced for doc parity; unused import lint suppression via `_`.
#[allow(dead_code)]
fn _pathbuf_marker(_: &PathBuf) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_spec_caret_matches_major() {
        assert!(version_spec_matches(
            Some("^5.4.0"),
            Some("5.4.0"),
            &VERSION_RE,
            false
        ));
        assert!(version_spec_matches(
            Some("^5.4.0"),
            Some("5.7.1"),
            &VERSION_RE,
            false
        ));
        assert!(!version_spec_matches(
            Some("^5.4.0"),
            Some("6.0.0"),
            &VERSION_RE,
            false
        ));
    }

    #[test]
    fn version_spec_tilde_pins_minor() {
        assert!(version_spec_matches(
            Some("~5.4.0"),
            Some("5.4.9"),
            &VERSION_RE,
            false
        ));
        assert!(!version_spec_matches(
            Some("~5.4.0"),
            Some("5.5.0"),
            &VERSION_RE,
            false
        ));
    }

    #[test]
    fn version_spec_exact() {
        assert!(version_spec_matches(
            Some("5.4.0"),
            Some("5.4.0"),
            &VERSION_RE,
            false
        ));
        assert!(!version_spec_matches(
            Some("5.4.0"),
            Some("5.4.1"),
            &VERSION_RE,
            false
        ));
    }

    #[test]
    fn compiler_args_explicit_package_flag() {
        let tokens = vec![
            "npx".to_owned(),
            "--package=typescript".to_owned(),
            "tsc".to_owned(),
            "--noEmit".to_owned(),
            "index.ts".to_owned(),
        ];
        let (args, explicit) = compiler_args(&tokens);
        assert!(explicit);
        assert_eq!(args, vec!["--noEmit", "index.ts"]);
    }

    #[test]
    fn read_only_requires_noemit() {
        let args = vec!["--noEmit".to_owned(), "index.ts".to_owned()];
        let (sources, ok) = read_only_compiler_arguments(&args);
        assert!(ok);
        assert_eq!(sources, vec!["index.ts"]);

        let bad = vec!["--emit".to_owned()];
        let (_, ok) = read_only_compiler_arguments(&bad);
        assert!(!ok);
    }

    #[test]
    fn non_tsc_returns_none() {
        let inputs = TypeScriptLaunchInputs {
            tokens: vec!["npx".to_owned(), "eslint".to_owned()],
            manager_name: "npx".to_owned(),
            local_only_requested: true,
            package_name: Some("eslint".to_owned()),
            executable_name: Some("eslint".to_owned()),
            declared_version: None,
            manager_path: None,
            manager_hash: None,
            executable_path: None,
            executable_hash: None,
            manifest_paths: Vec::new(),
            manifest_hashes: Vec::new(),
            lockfile_paths: Vec::new(),
            lockfile_hashes: Vec::new(),
        };
        assert!(build_typescript_launch_evidence(&inputs).is_none());
    }
}
