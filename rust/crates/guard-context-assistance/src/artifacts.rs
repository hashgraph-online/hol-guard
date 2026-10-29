use crate::release::RuntimeRelease;
use crate::RuntimeError;
#[cfg(test)]
use crate::{CIGAR_PROTOCOL, CIGAR_VERSION};
use guard_cigar_release::{ReleaseBinding, ResolvedRelease};
use guard_secure_fs::read_stable;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_FILES: usize = 8192;
const MAX_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILE_BYTES: usize = 128 * 1024 * 1024;

/// Private host-selected paths. Never derive these from an agent context call.
/// Retain the invocation spelling, because resolving a venv symlink for launch
/// can select the base interpreter's environment instead of the selected venv.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSelection {
    pub python: PathBuf,
    pub site_packages: PathBuf,
    pub work_dir: PathBuf,
    /// Only an actual complete byte verification creates this cache. Never
    /// serialized; status/registry reads must not initialize it.
    #[serde(skip)]
    pub verified_python: Option<std::sync::Arc<guard_cigar_artifacts::VerifiedPythonSnapshot>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub python_bundle: Option<crate::PrivatePythonSelection>,
}

/// Installation receipt for approved bytes, independent of the runtime's own
/// claims. The host must load it from its private installation registry; public
/// HTTP/MCP clients may not supply or replace it. A development receipt is not
/// a signed public release or qualification of another OS/architecture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleApproval {
    pub schema: String,
    pub platform: String,
    pub python_sha256: String,
    pub package_tree_sha256: String,
    pub worker_sha256: String,
    pub files: usize,
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<ReleaseBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub python_bundle: Option<guard_cigar_release::InterpreterBinding>,
}

pub fn inspect_bundle(
    selection: &RuntimeSelection,
    platform: &str,
) -> Result<BundleApproval, RuntimeError> {
    inspect(selection, platform, &RuntimeRelease::legacy()?, None)
}

/// Inspect catalog-pinned SDK/dependency bytes without launching Python.
pub fn inspect_release_bundle(
    selection: &RuntimeSelection,
    release: &ResolvedRelease,
) -> Result<BundleApproval, RuntimeError> {
    let expected = RuntimeRelease::catalog(release)?;
    inspect(selection, &release.platform().platform, &expected, None)
}

pub(crate) fn inspect_cancellable(
    selection: &RuntimeSelection,
    platform: &str,
    expected: &RuntimeRelease,
    cancel: &AtomicBool,
) -> Result<BundleApproval, RuntimeError> {
    inspect(selection, platform, expected, Some(cancel))
}

fn cancelled(cancel: Option<&AtomicBool>) -> Result<(), RuntimeError> {
    if cancel.is_some_and(|flag| flag.load(Ordering::Acquire)) {
        Err(RuntimeError::Cancelled)
    } else {
        Ok(())
    }
}

fn inspect(
    selection: &RuntimeSelection,
    platform: &str,
    expected: &RuntimeRelease,
    cancel: Option<&AtomicBool>,
) -> Result<BundleApproval, RuntimeError> {
    cancelled(cancel)?;
    if expected
        .platform
        .as_deref()
        .is_some_and(|value| value != platform)
    {
        return Err(RuntimeError::ApprovalMismatch);
    }
    if !matches!(
        platform,
        "darwin-arm64"
            | "darwin-x64"
            | "linux-x64-gnu"
            | "linux-arm64-gnu"
            | "linux-x64-musl"
            | "linux-arm64-musl"
            | "win32-x64"
    ) {
        return Err(RuntimeError::PlatformUnqualified);
    }
    for path in [
        &selection.python,
        &selection.site_packages,
        &selection.work_dir,
    ] {
        if !path.is_absolute()
            || path
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir))
        {
            return Err(RuntimeError::SelectionInvalid);
        }
    }
    let python_bundle = crate::private_python::check_selection(selection, Some(platform), cancel)?;
    if expected.binding.is_none() && python_bundle.is_some() {
        return Err(RuntimeError::ApprovalMismatch);
    }
    let python_sha256 = match &python_bundle {
        Some(binding) => binding.executable_sha256.clone(),
        None => {
            read_stable(&selection.python, MAX_FILE_BYTES, true)
                .map_err(|_| RuntimeError::ArtifactUnreadable)?
                .sha256
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let python_mode = fs::metadata(&selection.python)
            .map_err(|_| RuntimeError::ArtifactUnreadable)?
            .permissions()
            .mode();
        let site_mode = fs::metadata(&selection.site_packages)
            .map_err(|_| RuntimeError::ArtifactUnreadable)?
            .permissions()
            .mode();
        let work_mode = fs::metadata(&selection.work_dir)
            .map_err(|_| RuntimeError::ArtifactUnreadable)?
            .permissions()
            .mode();
        if python_mode & 0o022 != 0 || site_mode & 0o022 != 0 || work_mode & 0o077 != 0 {
            return Err(RuntimeError::PackageUnsafe);
        }
    }
    let root =
        fs::canonicalize(&selection.site_packages).map_err(|_| RuntimeError::SelectionInvalid)?;
    if !root.is_dir() || !selection.work_dir.is_dir() {
        return Err(RuntimeError::SelectionInvalid);
    }
    let mut files = Vec::new();
    collect(&root, &root, &mut files, 0, cancel)?;
    files.sort();
    let mut digest = Sha256::new();
    digest.update(b"guard-cigar-package-tree.v1\0");
    let mut total = 0_u64;
    for path in &files {
        cancelled(cancel)?;
        let read = read_stable(path, MAX_FILE_BYTES, false)
            .map_err(|_| RuntimeError::ArtifactUnreadable)?;
        total = total
            .checked_add(read.bytes.len() as u64)
            .ok_or(RuntimeError::BundleTooLarge)?;
        if total > MAX_BUNDLE_BYTES {
            return Err(RuntimeError::BundleTooLarge);
        }
        let relative = path
            .strip_prefix(&root)
            .map_err(|_| RuntimeError::SelectionInvalid)?;
        let name = relative
            .to_str()
            .ok_or(RuntimeError::SelectionInvalid)?
            .replace('\\', "/");
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update(read.sha256.as_bytes());
    }
    let release = read_json(&root.join("cigar_sdk/release.json"))?;
    if release["schema_version"] != "cigar.sdk-release.v1"
        || release["name"] != "hol-cigar"
        || release["version"] != expected.sdk_version
        || release["local_context_core_version"] != expected.core_version
        || release["local_context_protocol"] != expected.worker_protocol
    {
        return Err(RuntimeError::PackageMismatch);
    }
    let inventory = read_json(&root.join("cigar_sdk/native-platforms.v1.json"))?;
    if inventory["schema"] != "cigar.native-platforms.v1" {
        return Err(RuntimeError::PackageMismatch);
    }
    let metadata = inventory["platforms"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|item| item["id"].as_str() == Some(platform))
        })
        .ok_or(RuntimeError::PlatformUnqualified)?;
    let executable = metadata["executable"]
        .as_str()
        .ok_or(RuntimeError::PackageMismatch)?;
    if !matches!(
        executable,
        "cigar-context-worker" | "cigar-context-worker.exe"
    ) {
        return Err(RuntimeError::PackageMismatch);
    }
    let directory = root.join("cigar_sdk/_native").join(platform);
    let manifest = read_json(&directory.join("manifest.json"))?;
    let worker = read_stable(&directory.join(executable), MAX_FILE_BYTES, false)
        .map_err(|_| RuntimeError::ArtifactUnreadable)?;
    if manifest["core_version"] != expected.core_version
        || manifest["sdk_release"] != expected.sdk_version
        || manifest["protocol"] != expected.worker_protocol
        || manifest["target"] != metadata["target"]
        || manifest["sha256"].as_str() != Some(&worker.sha256)
    {
        return Err(RuntimeError::PackageMismatch);
    }
    let tree_sha256 = format!("{:x}", digest.finalize());
    if expected
        .package_tree_sha256
        .as_deref()
        .is_some_and(|value| value != tree_sha256)
        || expected
            .worker_sha256
            .as_deref()
            .is_some_and(|value| value != worker.sha256)
    {
        return Err(RuntimeError::ApprovalMismatch);
    }
    Ok(BundleApproval {
        schema: match (expected.binding.is_some(), python_bundle.is_some()) {
            (true, true) => "guard-cigar-bundle-approval.v3",
            (true, false) => "guard-cigar-bundle-approval.v2",
            (false, _) => "guard-cigar-bundle-approval.v1",
        }
        .into(),
        platform: platform.into(),
        python_sha256,
        package_tree_sha256: tree_sha256,
        worker_sha256: worker.sha256,
        files: files.len(),
        bytes: total,
        release: expected.binding.clone(),
        python_bundle,
    })
}

#[cfg(test)]
#[path = "artifact_tests.rs"]
mod tests;

fn read_json(path: &Path) -> Result<serde_json::Value, RuntimeError> {
    let data = read_stable(path, 64 * 1024, false).map_err(|_| RuntimeError::ArtifactUnreadable)?;
    serde_json::from_slice(&data.bytes).map_err(|_| RuntimeError::PackageMismatch)
}

fn collect(
    root: &Path,
    dir: &Path,
    files: &mut Vec<PathBuf>,
    depth: usize,
    cancel: Option<&AtomicBool>,
) -> Result<(), RuntimeError> {
    if depth > 24 {
        return Err(RuntimeError::BundleTooLarge);
    }
    for entry in fs::read_dir(dir).map_err(|_| RuntimeError::ArtifactUnreadable)? {
        cancelled(cancel)?;
        let entry = entry.map_err(|_| RuntimeError::ArtifactUnreadable)?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| RuntimeError::ArtifactUnreadable)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o022 != 0 {
                return Err(RuntimeError::PackageUnsafe);
            }
        }
        if metadata.file_type().is_symlink() {
            return Err(RuntimeError::PackageUnsafe);
        }
        let name = entry.file_name();
        let name = name.to_str().ok_or(RuntimeError::PackageUnsafe)?;
        if name.ends_with(".pth") || name.ends_with(".egg-link") {
            return Err(RuntimeError::PackageUnsafe);
        }
        if metadata.is_dir() {
            collect(root, &path, files, depth + 1, cancel)?;
        } else if metadata.is_file() && path.starts_with(root) {
            files.push(path);
            if files.len() > MAX_FILES {
                return Err(RuntimeError::BundleTooLarge);
            }
        } else {
            return Err(RuntimeError::PackageUnsafe);
        }
    }
    Ok(())
}
