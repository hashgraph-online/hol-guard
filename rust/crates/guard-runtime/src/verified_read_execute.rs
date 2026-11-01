//! Guard-owned execution of one bounded workspace read.
//!
//! Port of `runtime/verified_read_execution.py`. The plan names the read; this
//! module establishes the working directory's repository identity, opens the
//! target beneath that repository one component at a time without following a
//! symlink, slices the text it read, binds a proof to the repository, target
//! and output identity, and composes the decision. Any doubt about the
//! filesystem ends the verified read, and the command goes back to ordinary
//! review.

use std::ffi::OsStr;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use guard_command::effect_decision::{effect_decision_to_payload, FinalDisposition};
use guard_command::verified_read_decision::verified_workspace_read_decision;
use guard_command::verified_read_plan::verified_read_plan;
use guard_contracts::VerifiedReadSelectionV1;

use crate::verified_read_lines::selected;
use nix::fcntl::{open, openat, OFlag};
use nix::sys::stat::Mode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const EXECUTION_VERSION: &str = "guard.verified-read-execution.v1";
const POLICY_VERSION: &str = "guard.verified-read-policy.v1";
const RULE_VERSION: &str = "guard.verified-read.local.v1";
/// Names the executor in the proof. The Python executor bound its own source
/// digest here; the executor now ships inside the runtime binary.
const EXECUTOR_SOURCE: &str = "guard-runtime:verified-read-execute.v1";
pub(crate) const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_OUTPUT_BYTES: usize = 1_048_576;
const MAX_GIT_FILE_BYTES: u64 = 4_096;
const SECRET_CHECK_BUDGET: Duration = Duration::from_secs(2);
/// How long one verified read may hold a worker of the resident's bounded
/// pool. A read that cannot finish inside it falls back to ordinary review.
/// The budget is checked between steps and between chunks; a filesystem that
/// blocks inside a single syscall cannot be interrupted from here.
const EXECUTION_BUDGET: Duration = Duration::from_secs(5);
const READ_CHUNK_BYTES: usize = 64 * 1024;

/// Why a verified read did not happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The plan, the target or its path is outside what a verified read may
    /// show: a secret, a symlink, parent traversal, or a path leaving the
    /// repository.
    Refused,
    /// The workspace could not be established, the file could not be read
    /// within its bounds, or something changed while it was read.
    Unavailable,
}

impl From<io::Error> for Failure {
    fn from(_: io::Error) -> Self {
        Failure::Unavailable
    }
}

impl From<nix::Error> for Failure {
    fn from(_: nix::Error) -> Self {
        Failure::Unavailable
    }
}

type Outcome<T> = Result<T, Failure>;

/// Stop a read that has outlived its budget rather than hold the worker.
fn within(deadline: Instant) -> Outcome<()> {
    if Instant::now() >= deadline {
        return Err(Failure::Unavailable);
    }
    Ok(())
}

/// What a completed read hands back to the host.
#[derive(Debug)]
pub(crate) struct ReadOutcome {
    pub(crate) operation_id: String,
    pub(crate) stdout: String,
    pub(crate) binding_digest: String,
    pub(crate) decision: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspaceContext {
    repository: PathBuf,
    cwd: PathBuf,
    identity: String,
    repository_file_identity: (u64, u64),
}

struct ReadOutput {
    operation_id: String,
    stdout: String,
    targets: Vec<Value>,
}

/// `try_execute_verified_local_read`: perform one bounded read in `cwd`.
pub(crate) fn execute(argv: &[String], cwd: &str, home_dir: Option<&str>) -> Outcome<ReadOutcome> {
    let deadline = Instant::now() + EXECUTION_BUDGET;
    let plan = verified_read_plan(argv).map_err(|_| Failure::Refused)?;
    let context = workspace_context(Path::new(cwd))?;
    let output = match &plan.selection {
        VerifiedReadSelectionV1::WorkingDirectory {} => ReadOutput {
            operation_id: plan.operation_id.clone(),
            stdout: format!("{cwd}\n"),
            targets: vec![directory_target(&context.cwd, &context)?],
        },
        selection => {
            let value = plan.target.as_deref().ok_or(Failure::Refused)?;
            let (text, target) = read_target(value, &context, home_dir, deadline)?;
            let stdout = selected(&text, selection).to_owned();
            ReadOutput {
                operation_id: plan.operation_id.clone(),
                stdout,
                targets: vec![target],
            }
        }
    };
    if output.stdout.len() > MAX_OUTPUT_BYTES {
        return Err(Failure::Unavailable);
    }
    within(deadline)?;
    if workspace_context(Path::new(cwd))? != context {
        return Err(Failure::Unavailable);
    }
    let binding_digest = proof_digest(&context, argv, &output)?;
    let decision = verified_workspace_read_decision(&output.operation_id, &binding_digest)
        .map_err(|_| Failure::Unavailable)?;
    if decision.disposition != FinalDisposition::SilentVerified {
        return Err(Failure::Unavailable);
    }
    Ok(ReadOutcome {
        operation_id: output.operation_id,
        stdout: output.stdout,
        binding_digest,
        decision: effect_decision_to_payload(&decision),
    })
}

/// `_current_workspace_context`: the nearest enclosing Git checkout of a
/// canonical working directory.
fn workspace_context(cwd: &Path) -> Outcome<WorkspaceContext> {
    if !cwd.is_absolute() {
        return Err(Failure::Unavailable);
    }
    let metadata = fs::symlink_metadata(cwd)?;
    // Path equality compares components, so `/repo/./x`, `/repo//x` and
    // `/repo/x/` all equal the canonical path; the bytes must match too,
    // because the working directory is echoed to the caller verbatim.
    if !metadata.is_dir() || fs::canonicalize(cwd)?.as_os_str() != cwd.as_os_str() {
        return Err(Failure::Unavailable);
    }
    for candidate in cwd.ancestors() {
        let Ok(git_identity) = repository_git_identity(candidate) else {
            continue;
        };
        let repository_metadata = fs::symlink_metadata(candidate)?;
        let identity = verified_read_digest(&json!({
            "repository": path_identity(&repository_metadata)?,
            "git": git_identity,
        }))?;
        return Ok(WorkspaceContext {
            repository: candidate.to_path_buf(),
            cwd: cwd.to_path_buf(),
            identity,
            repository_file_identity: (repository_metadata.dev(), repository_metadata.ino()),
        });
    }
    Err(Failure::Unavailable)
}

/// `_repository_git_identity`: a `.git` directory, or a linked worktree's
/// `.git` file together with the directories it names.
fn repository_git_identity(path: &Path) -> Outcome<Value> {
    let marker = path.join(".git");
    let metadata = fs::symlink_metadata(&marker)?;
    if metadata.file_type().is_symlink() {
        return Err(Failure::Unavailable);
    }
    if metadata.is_dir() {
        return Ok(json!({
            "kind": "directory",
            "identity": path_identity(&metadata)?,
            "head": regular_file_digest(&marker.join("HEAD"), MAX_GIT_FILE_BYTES)?,
            "config": optional_regular_file_digest(&marker.join("config"))?,
        }));
    }
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.size() > MAX_GIT_FILE_BYTES {
        return Err(Failure::Unavailable);
    }
    let payload = read_regular_file(&marker, MAX_GIT_FILE_BYTES)?;
    let text = std::str::from_utf8(&payload).map_err(|_| Failure::Unavailable)?;
    let named = gitdir_line(text).ok_or(Failure::Unavailable)?;
    let git_directory = path.join(named);
    let canonical = fs::canonicalize(&git_directory)?;
    if fs::symlink_metadata(&git_directory)?
        .file_type()
        .is_symlink()
        || !fs::metadata(&canonical)?.is_dir()
    {
        return Err(Failure::Unavailable);
    }
    let commondir = read_regular_file(&canonical.join("commondir"), MAX_GIT_FILE_BYTES)?;
    let commondir = std::str::from_utf8(&commondir).map_err(|_| Failure::Unavailable)?;
    if commondir.is_empty()
        || commondir.contains('\0')
        || commondir.trim_end_matches(['\r', '\n']).contains('\n')
    {
        return Err(Failure::Unavailable);
    }
    let common_directory = fs::canonicalize(canonical.join(commondir.trim()))?;
    if !fs::metadata(&common_directory)?.is_dir() {
        return Err(Failure::Unavailable);
    }
    Ok(json!({
        "kind": "worktree",
        "marker": hex::encode(Sha256::digest(&payload)),
        "directory": path_identity(&fs::symlink_metadata(&canonical)?)?,
        "head": regular_file_digest(&canonical.join("HEAD"), MAX_GIT_FILE_BYTES)?,
        "common_directory": path_identity(&fs::symlink_metadata(&common_directory)?)?,
        "common_config": optional_regular_file_digest(&common_directory.join("config"))?,
    }))
}

/// `gitdir: ([^\r\n]+)\r?\n?` matched against the whole marker.
fn gitdir_line(text: &str) -> Option<&str> {
    let body = text.strip_prefix("gitdir: ")?;
    let body = body.strip_suffix('\n').unwrap_or(body);
    let body = body.strip_suffix('\r').unwrap_or(body);
    (!body.is_empty() && !body.contains(['\r', '\n'])).then_some(body)
}

/// `_resolve_target` then `_open_beneath_repository`: the text of the target
/// and its proof entry.
fn read_target(
    value: &str,
    context: &WorkspaceContext,
    home_dir: Option<&str>,
    deadline: Instant,
) -> Outcome<(String, Value)> {
    let target = resolve_target(value, context, home_dir, deadline)?;
    let relative = target
        .strip_prefix(&context.repository)
        .map_err(|_| Failure::Refused)?;
    let mut file = open_beneath_repository(relative, context)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.size() > MAX_FILE_BYTES {
        return Err(Failure::Unavailable);
    }
    let identity = stable_file_identity(&metadata)?;
    let mut payload = Vec::new();
    let mut chunk = [0u8; READ_CHUNK_BYTES];
    loop {
        within(deadline)?;
        let read = file.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        if payload.len() as u64 + read as u64 > MAX_FILE_BYTES {
            return Err(Failure::Unavailable);
        }
        payload.extend_from_slice(&chunk[..read]);
    }
    if stable_file_identity(&file.metadata()?)? != identity {
        return Err(Failure::Unavailable);
    }
    let text = String::from_utf8(payload).map_err(|_| Failure::Unavailable)?;
    let entry = json!({
        "path": verified_read_digest(&json!(posix(relative)?))?,
        "identity": path_identity(&metadata)?,
    });
    Ok((text, entry))
}

fn resolve_target(
    value: &str,
    context: &WorkspaceContext,
    home_dir: Option<&str>,
    deadline: Instant,
) -> Outcome<PathBuf> {
    let lexical = context.cwd.join(value);
    if is_secret_path(value, &context.cwd, home_dir, deadline)? {
        return Err(Failure::Refused);
    }
    reject_symlink_components(&lexical, &context.repository)?;
    let target = fs::canonicalize(&lexical)?;
    let relative = target
        .strip_prefix(&context.repository)
        .map_err(|_| Failure::Refused)?;
    if is_secret_path(posix(relative)?, &context.repository, home_dir, deadline)? {
        return Err(Failure::Refused);
    }
    Ok(target)
}

/// `classify_secret_path`, answered by the same tables the hook path reads.
fn is_secret_path(
    value: &str,
    cwd: &Path,
    home_dir: Option<&str>,
    deadline: Instant,
) -> Outcome<bool> {
    let cwd = cwd.to_str().ok_or(Failure::Unavailable)?;
    let answer = guard_command::content_sensitivity::evaluate(
        "path",
        &json!({"path": value, "cwd": cwd, "home_dir": home_dir}),
        deadline.min(Instant::now() + SECRET_CHECK_BUDGET),
    )
    .map_err(|_| Failure::Unavailable)?;
    match answer.get("ok") {
        Some(Value::Null) => Ok(false),
        Some(_) => Ok(true),
        None => Err(Failure::Unavailable),
    }
}

/// `_reject_symlink_components`: no symlink and no `..` from the repository
/// down to the target.
fn reject_symlink_components(path: &Path, root: &Path) -> Outcome<()> {
    let relative = path.strip_prefix(root).map_err(|_| Failure::Refused)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        match component {
            Component::CurDir => continue,
            Component::Normal(part) => {
                current.push(part);
                if fs::symlink_metadata(&current).is_ok_and(|found| found.file_type().is_symlink())
                {
                    return Err(Failure::Refused);
                }
            }
            _ => return Err(Failure::Refused),
        }
    }
    Ok(())
}

/// `_open_beneath_repository`: open the repository by descriptor, check it is
/// still the one the context identified, and walk down with `openat`, never
/// following a symlink.
fn open_beneath_repository(relative: &Path, context: &WorkspaceContext) -> Outcome<File> {
    let parts = relative
        .components()
        .map(|component| match component {
            Component::Normal(part) => Ok(part),
            _ => Err(Failure::Refused),
        })
        .collect::<Outcome<Vec<&OsStr>>>()?;
    let (last, directories) = parts.split_last().ok_or(Failure::Refused)?;
    let common = OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW;
    let directory_flags = common | OFlag::O_DIRECTORY;
    let mut current = File::from(open(
        context.repository.as_path(),
        directory_flags,
        Mode::empty(),
    )?);
    let root = current.metadata()?;
    if (root.dev(), root.ino()) != context.repository_file_identity {
        return Err(Failure::Unavailable);
    }
    for part in directories {
        current = File::from(openat(&current, *part, directory_flags, Mode::empty())?);
    }
    Ok(File::from(openat(
        &current,
        *last,
        common | OFlag::O_NONBLOCK,
        Mode::empty(),
    )?))
}

fn directory_target(path: &Path, context: &WorkspaceContext) -> Outcome<Value> {
    let relative = path
        .strip_prefix(&context.repository)
        .map_err(|_| Failure::Unavailable)?;
    let metadata = fs::symlink_metadata(path)?;
    Ok(json!({
        "path": verified_read_digest(&json!(posix(relative)?))?,
        "identity": path_identity(&metadata)?,
    }))
}

/// `PurePath.as_posix` of a repository-relative path; the repository itself
/// is `.`.
fn posix(relative: &Path) -> Outcome<&str> {
    let text = relative.to_str().ok_or(Failure::Unavailable)?;
    Ok(if text.is_empty() { "." } else { text })
}

fn optional_regular_file_digest(path: &Path) -> Outcome<String> {
    match read_regular_file_raw(path, MAX_FILE_BYTES) {
        Ok(payload) => Ok(hex::encode(Sha256::digest(&payload))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            verified_read_digest(&json!("missing"))
        }
        Err(_) => Err(Failure::Unavailable),
    }
}

fn regular_file_digest(path: &Path, max_bytes: u64) -> Outcome<String> {
    Ok(hex::encode(Sha256::digest(read_regular_file(
        path, max_bytes,
    )?)))
}

fn read_regular_file(path: &Path, max_bytes: u64) -> Outcome<Vec<u8>> {
    read_regular_file_raw(path, max_bytes).map_err(Failure::from)
}

/// `_OpenRegularFile`: a singly linked regular file within `max_bytes`, read
/// without following a symlink, and unchanged while it was read.
fn read_regular_file_raw(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    let flags = OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK;
    let mut file = File::from(open(path, flags, Mode::empty()).map_err(io::Error::from)?);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.size() > max_bytes {
        return Err(io::Error::other("not a bounded regular file"));
    }
    let identity = stable_file_identity(&metadata).map_err(|_| io::Error::other("identity"))?;
    let mut payload = Vec::new();
    (&mut file).take(max_bytes + 1).read_to_end(&mut payload)?;
    if payload.len() as u64 > max_bytes
        || stable_file_identity(&file.metadata()?).map_err(|_| io::Error::other("identity"))?
            != identity
    {
        return Err(io::Error::other("file changed during read"));
    }
    Ok(payload)
}

fn proof_digest(
    context: &WorkspaceContext,
    argv: &[String],
    output: &ReadOutput,
) -> Outcome<String> {
    verified_read_digest(&json!({
        "schema_version": EXECUTION_VERSION,
        "policy_version": POLICY_VERSION,
        "rule_version": RULE_VERSION,
        "operation": output.operation_id,
        "workspace": context.identity,
        "repository": context.identity,
        "working_directory": directory_target(&context.cwd, context)?,
        "targets": output.targets,
        "request": verified_read_digest(&json!(argv))?,
        "executor_source": EXECUTOR_SOURCE,
        "parser": "guard-internal-direct-argv-v1",
        "io_flow": "guard-file-descriptor-to-bounded-output",
        "expected_effects": ["workspace-or-public-read"],
        "stdout": verified_read_digest(&json!(output.stdout))?,
    }))
}

/// `verified_read_digest`: SHA-256 over compact sorted-key JSON framed by its
/// eight-byte big-endian length.
fn verified_read_digest(value: &Value) -> Outcome<String> {
    let payload = serde_json::to_vec(value).map_err(|_| Failure::Unavailable)?;
    let mut hasher = Sha256::new();
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(&payload);
    Ok(hex::encode(hasher.finalize()))
}

fn modified_ns(metadata: &Metadata) -> Outcome<i64> {
    metadata
        .mtime()
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(metadata.mtime_nsec()))
        .ok_or(Failure::Unavailable)
}

fn path_identity(metadata: &Metadata) -> Outcome<Value> {
    Ok(json!({
        "device": metadata.dev(),
        "inode": metadata.ino(),
        "mode": metadata.mode() & 0o7777,
        "size": metadata.size(),
        "modified_ns": modified_ns(metadata)?,
    }))
}

fn stable_file_identity(metadata: &Metadata) -> Outcome<(u64, u64, u64, i64)> {
    Ok((
        metadata.dev(),
        metadata.ino(),
        metadata.size(),
        modified_ns(metadata)?,
    ))
}

#[cfg(test)]
#[path = "verified_read_execute_tests.rs"]
mod tests;
