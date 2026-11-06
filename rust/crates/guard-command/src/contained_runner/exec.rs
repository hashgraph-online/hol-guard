//! OS-enforced snapshot execution for contained runner requests.
//!
//! Faithful port of `runtime/containment_executor.py` and
//! `runtime/containment_backend_status.py` for requests without declared
//! outputs: inputs are copied into a private snapshot, the executable is pinned,
//! and exactly one process runs under a hash-verified `sandbox-exec` or
//! `bwrap` backend with no network and no live-workspace access.

use std::collections::BTreeMap;
use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::common::{file_sha256, text_digest};
use super::contract::{Attestation, Backend, Failure, Request};
use super::input_snapshot::{pin_executable, snapshot_inputs};
use super::process::run_process;
use super::sandbox_argv::{linux_argv, macos_argv, write_linux_name_service_files};

#[derive(Debug, Clone)]
pub(crate) struct ExecutionResult {
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) timed_out: bool,
    pub(crate) attestation: Attestation,
}

impl ExecutionResult {
    pub(crate) fn enforced(&self) -> bool {
        self.attestation.enforced
    }
}

struct BackendIdentity {
    kind: Backend,
    path: String,
    digest: String,
}

fn platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "other"
    }
}

/// Execute exactly once under a verified platform backend or fail closed.
pub(crate) fn execute_contained(
    request: &Request,
    timeout_seconds: f64,
) -> Result<ExecutionResult, String> {
    if !(0.1..=600.0).contains(&timeout_seconds) {
        return Err("timeout_seconds must be between 0.1 and 600".to_owned());
    }
    let Some(backend) = select_backend(platform()) else {
        return failure_result(
            request,
            Failure::UnsupportedPlatform,
            Backend::Unsupported,
            None,
        );
    };
    let actual = match file_sha256(Path::new(&backend.path)) {
        Ok(actual) => actual,
        Err(_) => return failure_result(request, Failure::BackendUnavailable, backend.kind, None),
    };
    if actual != backend.digest {
        return failure_result(
            request,
            Failure::BackendIdentityMismatch,
            backend.kind,
            Some(actual),
        );
    }
    match run_in_snapshot(request, &backend, timeout_seconds) {
        Ok(result) => Ok(result),
        Err(message) => Ok(ExecutionResult {
            exit_code: None,
            stdout: String::new(),
            stderr: super::process::bounded_text(&message),
            timed_out: false,
            attestation: Attestation::new(
                backend.kind,
                &backend.digest,
                request,
                Some(Failure::ApplyFailed),
            )?,
        }),
    }
}

fn run_in_snapshot(
    request: &Request,
    backend: &BackendIdentity,
    timeout_seconds: f64,
) -> Result<ExecutionResult, String> {
    let temp = TempRoot::create("guard-contained-")?;
    let root = fs::canonicalize(&temp.0).map_err(|error| error.to_string())?;
    let snapshot_cwd = snapshot_inputs(request, &root)?;
    let (argv, cwd, home, temporary) = if backend.kind == Backend::MacosSandbox {
        let pinned = pin_executable(request, &root, backend.kind)?;
        (
            macos_argv(&backend.path, request, &pinned, &root),
            snapshot_cwd.to_string_lossy().into_owned(),
            root.join("home").to_string_lossy().into_owned(),
            root.join("tmp").to_string_lossy().into_owned(),
        )
    } else {
        pin_executable(request, &root, backend.kind)?;
        let linux_etc = write_linux_name_service_files(&root)?;
        (
            linux_argv(&backend.path, request, &root, &linux_etc)?,
            root.to_string_lossy().into_owned(),
            "/guard/home".to_owned(),
            "/guard/tmp".to_owned(),
        )
    };
    let mut environment: BTreeMap<String, String> = request.environment.iter().cloned().collect();
    environment.insert("HOME".to_owned(), home);
    environment.insert("TMPDIR".to_owned(), temporary);
    let outcome = run_process(
        &argv,
        &cwd,
        &environment,
        timeout_seconds,
        &root,
        backend.kind,
    )?;
    if !outcome.execution_completed {
        let stderr = if outcome.stderr.is_empty() {
            "containment backend did not confirm execution".to_owned()
        } else {
            outcome.stderr
        };
        return Ok(ExecutionResult {
            exit_code: None,
            stdout: outcome.stdout,
            stderr,
            timed_out: outcome.timed_out,
            attestation: Attestation::new(
                backend.kind,
                &backend.digest,
                request,
                Some(Failure::ApplyFailed),
            )?,
        });
    }
    Ok(ExecutionResult {
        exit_code: outcome.exit_code,
        stdout: outcome.stdout,
        stderr: outcome.stderr,
        timed_out: outcome.timed_out,
        attestation: Attestation::new(backend.kind, &backend.digest, request, None)?,
    })
}

fn select_backend(platform: &str) -> Option<BackendIdentity> {
    if platform == "darwin" {
        return backend_at(Backend::MacosSandbox, "/usr/bin/sandbox-exec");
    }
    if platform.starts_with("linux") {
        return ["/usr/bin/bwrap", "/bin/bwrap"]
            .into_iter()
            .find_map(|path| backend_at(Backend::LinuxBwrap, path));
    }
    None
}

fn backend_at(kind: Backend, path: &str) -> Option<BackendIdentity> {
    let candidate = Path::new(path);
    let metadata = fs::symlink_metadata(candidate).ok()?;
    if metadata.file_type().is_symlink()
        || !candidate.is_file()
        || nix::unistd::access(candidate, nix::unistd::AccessFlags::X_OK).is_err()
    {
        return None;
    }
    let digest = file_sha256(candidate).ok()?;
    Some(BackendIdentity {
        kind,
        path: path.to_owned(),
        digest,
    })
}

fn failure_result(
    request: &Request,
    failure: Failure,
    backend: Backend,
    backend_digest: Option<String>,
) -> Result<ExecutionResult, String> {
    let digest =
        backend_digest.unwrap_or_else(|| text_digest(&format!("unavailable:{}", backend.as_str())));
    Ok(ExecutionResult {
        exit_code: None,
        stdout: String::new(),
        stderr: failure.as_str().to_owned(),
        timed_out: false,
        attestation: Attestation::new(backend, &digest, request, Some(failure))?,
    })
}

/// Private `guard-contained-*` directory removed on drop, including children a
/// sandboxed process left without owner write permission.
pub(super) struct TempRoot(pub(super) PathBuf);

impl TempRoot {
    pub(super) fn create(prefix: &str) -> Result<Self, String> {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
        for _ in 0..100 {
            let mut random = [0u8; 8];
            getrandom::fill(&mut random).map_err(|error| error.to_string())?;
            let suffix: String = random
                .iter()
                .map(|byte| ALPHABET[usize::from(*byte) % ALPHABET.len()] as char)
                .collect();
            let path = std::env::temp_dir().join(format!("{prefix}{suffix}"));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.to_string()),
            }
        }
        Err("could not create a private containment directory".to_owned())
    }
}

fn restore_owner_access(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_symlink() {
        return;
    }
    let mode = metadata.permissions().mode();
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o700));
    if metadata.is_dir() {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                restore_owner_access(&entry.path());
            }
        }
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        if fs::remove_dir_all(&self.0).is_err() {
            restore_owner_access(&self.0);
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

/// Backend selection and the refusals that precede any spawn.
#[cfg(test)]
mod backend_selection_tests {
    use super::super::contract::Policy;
    use super::super::vector_support::Workspace;
    use super::*;

    fn request(workspace: &Workspace) -> Request {
        let path = workspace.path.to_string_lossy().into_owned();
        let tool = workspace.path.join("tool");
        fs::write(&tool, b"#!/bin/sh\nexit 0\n").expect("write tool");
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).expect("tool mode");
        Request::new(
            &[tool.to_string_lossy().into_owned()],
            &path,
            &[],
            Policy::new(&path).expect("policy"),
            Vec::new(),
            &"1".repeat(64),
            &file_sha256(&tool).expect("digest"),
            "op.contained.exec",
        )
        .expect("request")
    }

    #[test]
    fn a_platform_without_a_backend_has_no_selection() {
        // There is no soft landing for an unknown platform: with no backend
        // there is nothing to enforce with, so selection returns nothing and
        // the caller fails closed rather than running the command bare.
        for platform in ["win32", "freebsd", "sunos", "", "darwinish"] {
            assert!(select_backend(platform).is_none(), "{platform}");
        }
    }

    #[test]
    fn a_selected_backend_is_an_executable_file_with_a_digest() {
        let Some(backend) = select_backend(platform()) else {
            // A host without bubblewrap installed has nothing to describe.
            return;
        };
        assert!(Path::new(&backend.path).is_file());
        assert_eq!(backend.digest.len(), 64);
        assert_eq!(
            backend.digest,
            file_sha256(Path::new(&backend.path)).expect("backend digest")
        );
        assert_ne!(backend.kind, Backend::Unsupported);
    }

    #[test]
    fn an_unsupported_platform_reports_a_failure_attestation() {
        let workspace = Workspace::new();
        let request = request(&workspace);

        let result = failure_result(
            &request,
            Failure::UnsupportedPlatform,
            Backend::Unsupported,
            None,
        )
        .expect("failure result");

        assert!(!result.enforced());
        assert_eq!(result.stderr, "unsupported-platform");
        assert_eq!(result.exit_code, None);
        assert!(!result.timed_out);
        assert_eq!(
            result.attestation.failure,
            Some(Failure::UnsupportedPlatform)
        );
        assert_eq!(
            result.attestation.backend_digest,
            text_digest("unavailable:unsupported")
        );
    }

    #[test]
    fn a_timeout_outside_the_supported_range_is_refused() {
        let workspace = Workspace::new();
        let request = request(&workspace);

        for timeout in [0.0, 0.09, 600.1, f64::NAN] {
            let refusal = match execute_contained(&request, timeout) {
                Err(message) => message,
                Ok(_) => panic!("{timeout} must be refused before any spawn"),
            };
            assert_eq!(refusal, "timeout_seconds must be between 0.1 and 600");
        }
    }
}
