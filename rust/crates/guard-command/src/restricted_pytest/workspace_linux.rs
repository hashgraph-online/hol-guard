//! Linux backend for `workspace-contained-v1`.
//!
//! Landlock grants directories but cannot deny writes below a granted one, so
//! it cannot express the macOS profile's protected paths at any depth.
//! Bubblewrap instead runs the command in fresh user, mount, PID, network, IPC
//! and UTS namespaces, with the workspace as the lower layer of an overlay.
//! Every write lands in a private upper directory, which `workspace_overlay`
//! checks against the same denials before applying it to the workspace.
//! Credential files the workspace already holds are hidden for the run.

use super::credentials::patterns;
use super::*;
use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Value};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// System directories the command may read and execute from, as on macOS.
const SYSTEM_ROOTS: &[&str] = &["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64"];
/// Configuration files ordinary tools read; no credential store is listed.
const SYSTEM_FILES: &[&str] = &[
    "/etc/alternatives",
    "/etc/group",
    "/etc/hosts",
    "/etc/ld.so.cache",
    "/etc/localtime",
    "/etc/nsswitch.conf",
    "/etc/passwd",
    "/etc/protocols",
    "/etc/services",
];
/// Where the launcher and the probe keep overlay directories. One fixed
/// place, so the probe proves the filesystem the launcher will use.
pub(crate) const OVERLAY_PARENT: &str = "/tmp";
/// Workspace entries walked to find credentials to hide.
const MAX_ENTRIES: usize = 500_000;
const MAX_MASKS: usize = 256;
const PROBE_SECONDS: u64 = 5;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    backend_executable: PathBuf,
    workspace: PathBuf,
    private_root: PathBuf,
    upper: PathBuf,
    work: PathBuf,
    exec_roots: Vec<PathBuf>,
    command: Vec<String>,
    /// A linked worktree's shared Git directory, with its overlay layers.
    #[serde(default)]
    linked_git: Option<super::workspace_linked::LinkedGit>,
    #[serde(default)]
    shared_upper: Option<PathBuf>,
    #[serde(default)]
    shared_work: Option<PathBuf>,
    /// Added to every request by the Python bridge; unused here.
    #[serde(default, rename = "search_path")]
    _search_path: String,
}

fn unavailable(message: &str) -> RestrictedPytestError {
    RestrictedPytestError::new(PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE, message)
}

fn invalid() -> RestrictedPytestError {
    RestrictedPytestError::new(
        PYTEST_INVALID_COMMAND_REASON_CODE,
        "Invalid workspace sandbox request.",
    )
}

/// Whether this host can run the workspace sandbox: a trusted bubblewrap that
/// can mount an overlay in an unprivileged user namespace, with whiteouts and
/// opaque directories recorded in the upper layer. Probed once per process.
pub(crate) fn available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| cfg!(target_os = "linux") && probe().is_some())
}

fn probe() -> Option<()> {
    let (_, bwrap) = select_backend("linux", None, "/usr/bin:/bin").ok()?;
    let root = Path::new(OVERLAY_PARENT).join(format!(
        "hol-guard-overlay-probe-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_nanos()
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&root).ok()?;
    let result = run_probe(&bwrap, &root);
    remove_overlay_root(&root);
    result
}

fn run_probe(bwrap: &Path, root: &Path) -> Option<()> {
    let (lower, upper, work) = (root.join("lower"), root.join("upper"), root.join("work"));
    for directory in [&lower, &upper, &work, &lower.join("d")] {
        std::fs::create_dir_all(directory).ok()?;
    }
    std::fs::write(lower.join("d/old"), b"").ok()?;
    std::fs::write(lower.join("gone"), b"").ok()?;
    let mut argv = base_argv(bwrap, &[]);
    let lower_text = lower.to_string_lossy().into_owned();
    argv.extend(overlay_argv(&lower_text, &upper, &work));
    argv.extend(
        [
            "--chdir",
            &lower_text,
            "--",
            "/bin/sh",
            "-c",
            "echo x > new && rm gone && rm -rf d && mkdir d",
        ]
        .map(str::to_owned),
    );
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_secs(PROBE_SECONDS);
    let status = loop {
        if let Some(status) = child.try_wait().ok()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let changes = super::workspace_overlay::probe_changes(&upper)?;
    (status.success() && changes).then_some(())
}

/// The namespace, filesystem and device arguments every launch shares.
fn base_argv(bwrap: &Path, exec_roots: &[PathBuf]) -> Vec<String> {
    let mut argv = vec![bwrap.to_string_lossy().into_owned()];
    argv.extend(
        [
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--cap-drop",
            "ALL",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
        ]
        .map(str::to_owned),
    );
    for root in SYSTEM_ROOTS {
        let path = Path::new(root);
        match path.symlink_metadata() {
            // Merged-/usr systems link `/bin` to `usr/bin`; keep the link.
            Ok(metadata) if metadata.file_type().is_symlink() => {
                if let Ok(target) = std::fs::read_link(path) {
                    argv.extend([
                        "--symlink".to_owned(),
                        target.to_string_lossy().into_owned(),
                        (*root).to_owned(),
                    ]);
                }
            }
            Ok(_) => argv.extend([
                "--ro-bind".to_owned(),
                (*root).to_owned(),
                (*root).to_owned(),
            ]),
            Err(_) => {}
        }
    }
    for file in SYSTEM_FILES {
        argv.extend([
            "--ro-bind-try".to_owned(),
            (*file).to_owned(),
            (*file).to_owned(),
        ]);
    }
    for root in exec_roots {
        let root = root.to_string_lossy().into_owned();
        argv.extend(["--ro-bind-try".to_owned(), root.clone(), root]);
    }
    argv
}

fn overlay_argv(lower: &str, upper: &Path, work: &Path) -> Vec<String> {
    vec![
        "--overlay-src".to_owned(),
        lower.to_owned(),
        "--overlay".to_owned(),
        upper.to_string_lossy().into_owned(),
        work.to_string_lossy().into_owned(),
        lower.to_owned(),
    ]
}

/// Credential files and directories already in the workspace. Each is hidden
/// behind an empty read-only mount, which also keeps it from being renamed or
/// deleted. `None` when the workspace is too large to walk or holds too many.
fn credential_masks(workspace: &Path) -> Option<Vec<(PathBuf, bool)>> {
    let credentials: Vec<Regex> = patterns()
        .iter()
        .map(|pattern| Regex::new(pattern).ok())
        .collect::<Option<_>>()?;
    let mut masks = Vec::new();
    let mut pending = vec![workspace.to_path_buf()];
    let mut visited = 0usize;
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).ok()? {
            visited += 1;
            if visited > MAX_ENTRIES {
                return None;
            }
            let entry = entry.ok()?;
            let path = entry.path();
            let file_type = entry.file_type().ok()?;
            let text = path.to_string_lossy();
            if credentials.iter().any(|pattern| pattern.is_match(&text)) {
                if file_type.is_dir() || file_type.is_file() {
                    masks.push((path, file_type.is_dir()));
                    if masks.len() > MAX_MASKS {
                        return None;
                    }
                }
            } else if file_type.is_dir() {
                pending.push(path);
            }
        }
    }
    masks.sort();
    Some(masks)
}

fn workspace_argv(input: &Input) -> Result<Vec<String>, RestrictedPytestError> {
    let paths = [
        &input.workspace,
        &input.private_root,
        &input.upper,
        &input.work,
    ];
    if paths.iter().any(|path| !path.is_absolute())
        || input.command.is_empty()
        || [&input.private_root, &input.upper, &input.work]
            .iter()
            .any(|path| path.starts_with(&input.workspace) || input.workspace.starts_with(path))
        || input.upper.starts_with(&input.private_root)
        || input.work.starts_with(&input.private_root)
    {
        return Err(invalid());
    }
    let shared = shared_layers(input)?;
    let backend = trusted_backend_executable(&input.backend_executable)
        .ok_or_else(|| unavailable("The workspace sandbox backend is not trusted."))?;
    let too_large = || unavailable("The workspace is too large for the workspace sandbox.");
    let mut masks = credential_masks(&input.workspace).ok_or_else(too_large)?;
    if let Some((linked, _, _)) = shared {
        masks.extend(credential_masks(linked.checkout()).ok_or_else(too_large)?);
        masks.sort();
        masks.dedup();
    }
    let exec_roots: Vec<PathBuf> = input
        .exec_roots
        .iter()
        .filter(|root| !root.starts_with(&input.workspace))
        .cloned()
        .collect();
    let mut argv = base_argv(&backend, &exec_roots);
    let private = input.private_root.to_string_lossy().into_owned();
    argv.extend(["--bind".to_owned(), private.clone(), private]);
    if let Some((linked, upper, work)) = shared {
        // The main checkout is readable; only its shared `.git` takes writes,
        // which the overlay check confines to objects, refs and the entry.
        let checkout = linked.checkout().to_string_lossy().into_owned();
        argv.extend(["--ro-bind".to_owned(), checkout.clone(), checkout]);
        argv.extend(overlay_argv(&linked.common.to_string_lossy(), upper, work));
    }
    let workspace = input.workspace.to_string_lossy().into_owned();
    argv.extend(overlay_argv(&workspace, &input.upper, &input.work));
    for (path, directory) in masks {
        let path = path.to_string_lossy().into_owned();
        if directory {
            argv.extend([
                "--tmpfs".to_owned(),
                path.clone(),
                "--remount-ro".to_owned(),
                path,
            ]);
        } else {
            argv.extend(["--ro-bind".to_owned(), "/dev/null".to_owned(), path]);
        }
    }
    argv.extend(["--chdir".to_owned(), workspace, "--".to_owned()]);
    argv.extend(input.command.iter().cloned());
    Ok(argv)
}

/// The linked worktree's shared directory and its overlay layers, when the
/// request names all three, each apart from the other run directories.
fn shared_layers(
    input: &Input,
) -> Result<Option<(&super::workspace_linked::LinkedGit, &Path, &Path)>, RestrictedPytestError> {
    match (&input.linked_git, &input.shared_upper, &input.shared_work) {
        (None, None, None) => Ok(None),
        (Some(linked), Some(upper), Some(work)) => {
            let others = [input.private_root.as_path(), &input.upper, &input.work];
            let linked = linked.with_layers(&input.workspace, &[upper, work], &others)?;
            Ok(Some((linked, upper, work)))
        }
        _ => Err(invalid()),
    }
}

/// Remove an overlay root. The kernel leaves the work directory's inner
/// directory unreadable, so it is made traversable first.
pub(super) fn remove_overlay_root(root: &Path) {
    let inner = root.join("work").join("work");
    if inner
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.is_dir())
    {
        let _ = fs::set_permissions(&inner, fs::Permissions::from_mode(0o700));
    }
    let _ = fs::remove_dir_all(root);
}

pub(super) fn evaluate(operation: &str, input: &Value) -> Option<Value> {
    if operation != "workspace_bubblewrap_argv" {
        return None;
    }
    let result = serde_json::from_value::<Input>(input.clone())
        .map_err(|_| invalid())
        .and_then(|input| workspace_argv(&input));
    Some(match result {
        Ok(value) => json!({"value": value}),
        Err(error) => crate::restricted_command::error_reply(error),
    })
}

#[cfg(test)]
#[path = "workspace_linux_tests.rs"]
mod tests;
