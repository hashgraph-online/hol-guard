//! Finding and inspecting the native runtime a Codex repair would compare
//! against, ported from `inspect_codex_repair_native_runtime`.
//!
//! The inspection is read-only: it never restores an execute bit, installs or
//! overrides the selection. It walks the candidates in selection order, pins
//! the first that exists, admits a bundled runtime only against its manifest,
//! runs the runtime's own `capabilities --json` once under the isolated
//! environment inside the caller's deadline, compares what it answered with
//! the manifest and the package, and pins it again so a replaced file cannot
//! vouch for itself.
//!
//! Facts about the asking interpreter's install arrive in the request: the
//! launcher's mode and override, where the wheel bundles the runtime, the
//! files of a separately installed runtime distribution (force mode only), the
//! installed package version, and the interpreter's own package file that
//! group-write trust is judged against.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use guard_contracts::{
    decode_native_capabilities, decode_runtime_manifest, NativeRuntimeManifestV1,
};
use serde_json::{json, Map, Value};

use super::inspect::plain;
use super::publication::Call;
use super::publication_pin_executable::{alive, deadline_of, pin, Expect};
use super::publication_pin_stamp as stamp;
use super::publication_runtime_compare::compare_op;
use super::{Fault, Step};
use crate::hook_process_spawn::run_isolated_hook_process;
use crate::native_runtime_admission::{
    isolated_environment, MAX_MANIFEST_BYTES, NATIVE_MANIFEST_NAME,
    NATIVE_MANIFEST_PROTOCOL_VERSION, NATIVE_MANIFEST_SCHEMA,
};

const PROBE_CAP: Duration = Duration::from_secs(1);
const PROBE_OUTPUT_LIMIT: usize = 64 * 1024;
const FAILED: Fault = Fault::Transition("authority_repair_native_inspection_failed");
const UNAVAILABLE: Fault = Fault::Transition("authority_repair_native_unavailable");
const INVALID: Fault = Fault::Transition("files_invalid");
/// The wire protocol the runtime must answer with.
const PROTOCOL: i64 = 1;

/// What the asking interpreter knows about its own install.
struct Facts {
    force: bool,
    override_path: Option<PathBuf>,
    bundled: PathBuf,
    distribution: Vec<PathBuf>,
    version: Option<String>,
    checker: Option<PathBuf>,
    base_prefix: Option<PathBuf>,
}

fn text(args: &Map<String, Value>, key: &str) -> Step<Option<String>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(INVALID),
    }
}

impl Facts {
    fn read(args: &Map<String, Value>) -> Step<Self> {
        let distribution = match args.get("distribution") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| item.as_str().map(PathBuf::from).ok_or(INVALID))
                .collect::<Step<_>>()?,
            Some(_) => return Err(INVALID),
        };
        Ok(Self {
            force: text(args, "mode")?.as_deref() == Some("force"),
            override_path: text(args, "binary_override")?
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
            bundled: PathBuf::from(text(args, "bundled")?.ok_or(INVALID)?),
            distribution,
            version: text(args, "package_version")?,
            checker: text(args, "checker")?.map(PathBuf::from),
            base_prefix: text(args, "base_prefix")?.map(PathBuf::from),
        })
    }
}

/// `Path.expanduser()` for a leading `~`.
fn expand_user(path: &Path) -> PathBuf {
    let mut parts = path.components();
    match (parts.next(), std::env::var_os("HOME")) {
        (Some(first), Some(home)) if first.as_os_str() == "~" => {
            PathBuf::from(home).join(parts.as_path())
        }
        _ => path.to_path_buf(),
    }
}

/// `primary_candidates` then the force-mode distribution, without repeats.
fn candidates(facts: &Facts) -> Vec<PathBuf> {
    let mut ordered = Vec::new();
    if facts.force {
        if let Some(path) = &facts.override_path {
            let path = expand_user(path);
            if path.is_absolute() && path != facts.bundled {
                ordered.push(path);
            }
        }
    }
    ordered.push(facts.bundled.clone());
    if facts.force {
        ordered.extend(facts.distribution.iter().cloned());
    }
    let mut seen = BTreeSet::new();
    ordered
        .into_iter()
        .filter(|path| seen.insert(path.clone()))
        .collect()
}

/// `_is_bundled_candidate`: the candidate is the wheel's own runtime.
fn is_bundled(path: &Path, facts: &Facts) -> bool {
    matches!(
        (std::path::absolute(expand_user(path)), std::path::absolute(&facts.bundled)),
        (Ok(left), Ok(right)) if left == right
    )
}

#[cfg(unix)]
fn trusted(metadata: &fs::Metadata, path: &Path, checker: Option<&Path>) -> bool {
    use std::os::unix::fs::MetadataExt;
    let uid = nix::unistd::getuid().as_raw();
    (metadata.uid() == 0 || metadata.uid() == uid)
        && crate::group_write_trust::writable_only_by_owner(metadata, uid, path, checker)
}

/// Off POSIX the manifest's owner and mode carry no meaning.
#[cfg(not(unix))]
fn trusted(_metadata: &fs::Metadata, _path: &Path, _checker: Option<&Path>) -> bool {
    true
}

/// The manifest opened without following a link at the leaf, and without
/// blocking on a FIFO swapped in for it.
#[cfg(unix)]
fn open_manifest(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

/// A link at the leaf is refused before the open, the way the Python read did.
#[cfg(not(unix))]
fn open_manifest(path: &Path) -> std::io::Result<fs::File> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    fs::File::open(path)
}

/// `_manifest_for_bundled_identity`: the bundled runtime's manifest, read
/// without following a link, and the reason it does not vouch for `sha256`.
fn manifest_for(
    runtime: &Path,
    size: u64,
    sha256: &str,
    facts: &Facts,
) -> Result<NativeRuntimeManifestV1, &'static str> {
    const BAD: &str = "native_manifest_invalid";
    let path = runtime.with_file_name(NATIVE_MANIFEST_NAME);
    let missing = |error: std::io::Error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            "native_manifest_missing"
        } else {
            BAD
        }
    };
    // The checks run on the handle that supplies the bytes, so an entry swapped
    // in after a pathname check cannot be the file that was trusted.
    let mut file = open_manifest(&path).map_err(missing)?;
    let metadata = file.metadata().map_err(|_| BAD)?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_MANIFEST_BYTES as u64
        || !trusted(&metadata, &path, facts.checker.as_deref())
    {
        return Err(BAD);
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BAD)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES as u64 {
        return Err(BAD);
    }
    let payload: Value = serde_json::from_slice(&bytes).map_err(|_| BAD)?;
    let manifest = decode_runtime_manifest(
        &payload,
        NATIVE_MANIFEST_SCHEMA,
        NATIVE_MANIFEST_PROTOCOL_VERSION,
    )
    .ok_or(BAD)?;
    if i64::try_from(size).ok() != Some(manifest.runtime_size) || manifest.runtime_sha256 != sha256
    {
        return Err("native_manifest_runtime_mismatch");
    }
    if facts
        .version
        .as_deref()
        .is_some_and(|version| manifest.package_version != version)
    {
        return Err("native_manifest_version_mismatch");
    }
    Ok(manifest)
}

/// One stage of `publication_runtime_compare`, which decides every comparison
/// an inspection makes.
fn compare(call: &Call<'_>, stage: &str, fields: Value) -> Step<()> {
    let mut args = fields.as_object().cloned().unwrap_or_default();
    args.insert("stage".to_owned(), json!(stage));
    let mut inner = Call {
        args: &args,
        budget: call.budget,
        events: Vec::new(),
    };
    compare_op(&mut inner).map(|_| ())
}

fn environment() -> BTreeMap<String, String> {
    std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .collect()
}

/// `publication_inspect_runtime`: the identity (`path`, `size`, `mtime_ns`,
/// `sha256`) of the runtime a repair would be compared with, or why there is
/// none. The request carries the facts `Facts` names beside the caller's
/// `deadline` and `now`.
pub(super) fn inspect_op(call: &mut Call<'_>) -> Step<Value> {
    let deadline = deadline_of(call)?;
    let facts = Facts::read(call.args)?;
    for candidate in candidates(&facts) {
        alive(deadline)?;
        if fs::metadata(&candidate).is_err() && fs::symlink_metadata(&candidate).is_err() {
            continue;
        }
        let path = expand_user(&candidate);
        // The runtime's own status would repair a bundled executable's mode,
        // so it is deliberately not consulted.
        let pinned = pin(call, &path, deadline, &Expect::default())?;
        let sha256 = pinned["sha256"].as_str().unwrap_or_default().to_owned();
        let (size, mtime_ns) = stamp::observed(&path)?;
        let before = stamp::of_path(&path)?;
        let resolved = plain(fs::canonicalize(&path)?);
        let manifest = if is_bundled(&path, &facts) {
            let manifest = manifest_for(&resolved, size, &sha256, &facts);
            alive(deadline)?;
            Some(manifest.map_err(Fault::Transition)?)
        } else {
            None
        };
        let command = [
            resolved.to_string_lossy().into_owned(),
            "capabilities".to_owned(),
            "--json".to_owned(),
        ];
        let probe = run_isolated_hook_process(
            &command,
            "",
            resolved.parent().unwrap_or_else(|| Path::new(".")),
            &isolated_environment(&environment(), facts.base_prefix.as_deref(), &facts.bundled),
            None,
            Some(PROBE_OUTPUT_LIMIT),
            None,
            Some(deadline.min(Instant::now() + PROBE_CAP)),
        );
        alive(deadline)?;
        compare(
            call,
            "probe",
            json!({
                "returncode": probe.returncode,
                "timed_out": probe.timed_out,
                "containment_failed": probe.containment_failed,
                "output_limit_exceeded": probe.output_limit_exceeded,
            }),
        )?;
        let answered: Value = serde_json::from_str(&probe.stdout).map_err(|_| FAILED)?;
        let capabilities = decode_native_capabilities(&answered);
        compare(
            call,
            "capabilities",
            json!({
                "capabilities": capabilities.as_ref().map(|found| json!({
                    "protocol_version": found.protocol_version,
                    "runtime_version": found.runtime_version,
                    "rule_digest": found.rule_digest,
                    "build_sha": found.build_sha,
                })),
                "protocol": PROTOCOL,
                "manifest": manifest.as_ref().map(|found| json!({
                    "package_version": found.package_version,
                    "rule_digest": found.rule_digest,
                    "source_sha": found.source_sha,
                })),
            }),
        )?;
        let capabilities = capabilities.ok_or(FAILED)?;
        alive(deadline)?;
        compare(
            call,
            "version",
            json!({
                "mode": if facts.force { "force" } else { "auto" },
                "version": facts.version,
                "runtime_version": capabilities.runtime_version,
            }),
        )?;
        // A replaced runtime cannot vouch for itself, so a changed generation
        // is refused before the runtime is asked to pin it again.
        compare(
            call,
            "generation",
            json!({
                "before": before.to_value(),
                "after": stamp::of_path(&path).ok().map(|after| after.to_value()),
            }),
        )?;
        let identity = json!({
            "path": resolved.to_string_lossy(),
            "size": size,
            "mtime_ns": i64::try_from(mtime_ns).map_err(|_| FAILED)?,
            "sha256": sha256,
        });
        let wanted = identity
            .as_object()
            .map(|fields| {
                ["size", "mtime_ns", "sha256"]
                    .iter()
                    .filter_map(|key| Some((key.to_string(), fields.get(*key)?.clone())))
                    .collect::<Map<_, _>>()
            })
            .unwrap_or_default();
        pin(
            call,
            &path,
            deadline,
            &Expect {
                identity: Some(&wanted),
                sha256: None,
            },
        )?;
        alive(deadline)?;
        return Ok(json!({ "identity": identity }));
    }
    Err(UNAVAILABLE)
}
