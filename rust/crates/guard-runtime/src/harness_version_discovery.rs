//! `harness-version-discovery --stdin`: which version of a harness is
//! installed (`op: "observe"`), and whether a cached observation still
//! describes the installs on disk (`op: "identity-changed"`).
//!
//! Discovery reads trusted package metadata first and only falls back to a
//! bounded, fixed-argument `--version` probe for a standalone binary. When
//! more than one installation is found and they disagree, the result is
//! ambiguous: the caller must not pick the most favorable version. Raw
//! command output never leaves this module; reasons are bounded codes.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::manifest::{parse_version, Version};
use crate::grok_executable_paths::strip_verbatim;
use crate::runtime_identity_launch::{which, Environment};

#[path = "harness_version_probe.rs"]
mod probe;
use probe::{parse_banner, run_bounded, Probe};

const SCHEMA: &str = "harness-version-discovery.v1";
const MAX_REQUEST_BYTES: u64 = 256 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_PACKAGE_JSON_BYTES: u64 = 256 * 1024;
const MAX_PACKAGE_ROOT_DEPTH: usize = 6;
const MAX_BANNER_BYTES: usize = 4096;
const MAX_CANDIDATES: usize = 16;
/// The variables a `--version` probe sees, beside `HOME` and `NO_COLOR`.
const PROBE_ENVIRONMENT: [&str; 4] = ["PATH", "SYSTEMROOT", "TEMP", "TMP"];
/// `os.confstr("CS_PATH")`, which `shutil.which` searches without a `PATH`.
#[cfg(target_os = "macos")]
const DEFAULT_SEARCH_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
#[cfg(all(unix, not(target_os = "macos")))]
const DEFAULT_SEARCH_PATH: &str = "/bin:/usr/bin";
#[cfg(not(unix))]
const DEFAULT_SEARCH_PATH: &str = "";
const SCRIPT_SUFFIXES: [&str; 4] = ["js", "mjs", "cjs", "ts"];

/// A harness with a reliable version source: its npm package, executable,
/// and the banner prefixes its `--version` prints. Every other harness is an
/// explicit `discovery_unsupported`.
struct VersionSource {
    harness: &'static str,
    package: &'static str,
    executable: &'static str,
    banner_prefixes: &'static [&'static str],
}

const VERSION_SOURCES: [VersionSource; 1] = [VersionSource {
    harness: "omp",
    package: "@oh-my-pi/pi-coding-agent",
    executable: "omp",
    banner_prefixes: &["", "omp", "oh-my-pi", "@oh-my-pi/pi-coding-agent"],
}];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    harness: String,
    home_dir: String,
    guard_home: String,
    /// The caller's process variables the lookup and probe use.
    #[serde(default)]
    environment: BTreeMap<String, String>,
    #[serde(default)]
    now: f64,
    #[serde(default)]
    candidates: Vec<String>,
    #[serde(default)]
    identity: Vec<Identity>,
}

/// One file the observation read, as `[path, inode, size, mtime_ns]`.
type Identity = (String, u64, u64, i64);

pub(crate) fn is_command(command: &str) -> bool {
    command == "harness-version-discovery"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "harness_version_discovery_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("harness_version_discovery_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    answer(&request).map(|value| value.to_string().into_bytes())
}

fn invalid() -> String {
    "harness_version_discovery_request_invalid".to_owned()
}

fn answer(request: &Request) -> Result<Value, String> {
    let home_dir = PathBuf::from(&request.home_dir);
    let guard_home = PathBuf::from(&request.guard_home);
    if request.schema != SCHEMA
        || !home_dir.is_absolute()
        || !guard_home.is_absolute()
        || !request.now.is_finite()
        || request.candidates.len() > MAX_CANDIDATES
        || request.identity.len() > MAX_CANDIDATES
    {
        return Err(invalid());
    }
    let host = Host {
        home_dir: &home_dir,
        guard_home: &guard_home,
        environment: &request.environment,
    };
    match request.op.as_str() {
        "observe" => Ok(observe(&request.harness, &host, request.now)),
        "identity-changed" => Ok(json!({
            "changed": identity_changed(request, &host),
        })),
        _ => Err(invalid()),
    }
}

struct Host<'a> {
    home_dir: &'a Path,
    guard_home: &'a Path,
    environment: &'a BTreeMap<String, String>,
}

fn source_for(harness: &str) -> Option<&'static VersionSource> {
    VERSION_SOURCES
        .iter()
        .find(|source| source.harness == harness)
}

/// One installation's result: its version, where it came from, the reason
/// it has none, and the file the version was read from.
struct Found {
    version: Option<Version>,
    source: &'static str,
    reason: Option<&'static str>,
    read_from: PathBuf,
}

fn observe(harness: &str, host: &Host, now: f64) -> Value {
    let observation = |state: &str, source: &str, reason: Option<&str>| {
        json!({
            "state": state,
            "version": null,
            "source": source,
            "installation_id": null,
            "reason": reason,
            "observed_at": now,
            "identity": [],
            "candidates": [],
        })
    };
    let Some(source) = source_for(harness) else {
        return observation("unavailable", "none", Some("discovery_unsupported"));
    };
    let executables = candidate_executables(source, host);
    if executables.is_empty() {
        return observation("unavailable", "none", Some("executable_missing"));
    }
    let results: Vec<Found> = executables
        .iter()
        .map(|executable| observe_one(source, executable, host))
        .collect();
    let identity: Vec<Identity> = results
        .iter()
        .filter_map(|found| stat_identity(&found.read_from))
        .collect();
    let mut candidates: Vec<String> = executables.iter().map(|path| text(path)).collect();
    candidates.sort();
    let mut parts = vec![harness.to_owned()];
    parts.extend(candidates.iter().cloned());
    let installation_id = hex::encode(Sha256::digest(parts.join("\0").as_bytes()))[..24].to_owned();
    let mut payload = observation("observed", "none", None);
    payload["installation_id"] = json!(installation_id);
    payload["identity"] = json!(identity);
    payload["candidates"] = json!(candidates);
    if let Some(reason) = results.iter().find_map(|found| {
        found
            .version
            .is_none()
            .then_some(found.reason.unwrap_or("metadata_malformed"))
    }) {
        payload["state"] = json!("unavailable");
        payload["reason"] = json!(reason);
        return payload;
    }
    let mut versions: Vec<&str> = results
        .iter()
        .filter_map(|found| {
            found
                .version
                .as_ref()
                .map(|version| version.canonical.as_str())
        })
        .collect();
    versions.sort_unstable();
    versions.dedup();
    if versions.len() != 1 {
        payload["state"] = json!("ambiguous");
        payload["reason"] = json!("multiple_installations");
        return payload;
    }
    payload["version"] = json!(versions[0]);
    payload["source"] = json!(results[0].source);
    payload
}

/// Distinct real paths of every plausible user installation: the `PATH` hit,
/// then `~/.local/bin` and `~/.bun/bin`. A Guard launcher shim is not the
/// harness, so anything inside the Guard home is skipped.
fn candidate_executables(source: &VersionSource, host: &Host) -> Vec<PathBuf> {
    let environment = Environment(host.environment);
    let path = search_path(host.environment);
    let mut raw: Vec<PathBuf> = which(source.executable, path.as_deref(), &environment)
        .map(PathBuf::from)
        .into_iter()
        .collect();
    raw.push(
        host.home_dir
            .join(".local")
            .join("bin")
            .join(source.executable),
    );
    raw.push(
        host.home_dir
            .join(".bun")
            .join("bin")
            .join(source.executable),
    );
    let guard_home = real_path(host.guard_home).unwrap_or_else(|| host.guard_home.to_path_buf());
    let mut distinct: Vec<PathBuf> = Vec::new();
    for candidate in raw {
        if !fs::metadata(&candidate).is_ok_and(|meta| meta.is_file()) {
            continue;
        }
        let Some(real) = real_path(&candidate) else {
            continue;
        };
        if real.starts_with(&guard_home) {
            continue;
        }
        if !distinct.contains(&real) {
            distinct.push(real);
        }
    }
    distinct
}

/// The directories `shutil.which` walks: the platform default when `PATH` is
/// unset, and relative entries taken from this process's directory, which
/// the caller's process shares.
fn search_path(environment: &BTreeMap<String, String>) -> Option<String> {
    let path = environment
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("PATH"))
        .map_or(DEFAULT_SEARCH_PATH, |(_, value)| value.as_str());
    if path.is_empty() {
        return None;
    }
    let cwd = std::env::current_dir().ok();
    let entries = std::env::split_paths(path).filter_map(|entry| {
        if entry.is_absolute() {
            Some(entry)
        } else {
            cwd.as_ref().map(|cwd| cwd.join(entry))
        }
    });
    std::env::join_paths(entries).ok()?.into_string().ok()
}

fn real_path(path: &Path) -> Option<PathBuf> {
    fs::canonicalize(path).ok().map(strip_verbatim)
}

fn observe_one(source: &VersionSource, executable: &Path, host: &Host) -> Found {
    if let Some(found) = package_version(executable, source.package) {
        return found;
    }
    // No owning package: a standalone binary. Only now run the bounded probe.
    let is_script = executable
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            SCRIPT_SUFFIXES
                .iter()
                .any(|suffix| extension.eq_ignore_ascii_case(suffix))
        });
    if is_script {
        return Found {
            version: None,
            source: "none",
            reason: Some("metadata_unavailable"),
            read_from: executable.to_path_buf(),
        };
    }
    let (version, reason) = probe_version(source, executable, host);
    Found {
        version,
        source: "version-probe",
        reason,
        read_from: executable.to_path_buf(),
    }
}

/// The owning `package.json` above `executable`, when there is one. A
/// manifest for another package is skipped; an unreadable one is malformed.
fn package_version(executable: &Path, package: &str) -> Option<Found> {
    let mut directory = executable.parent()?;
    for _ in 0..MAX_PACKAGE_ROOT_DEPTH {
        let manifest = directory.join("package.json");
        if fs::metadata(&manifest).is_ok_and(|meta| meta.is_file()) {
            let found = |version: Option<Version>| Found {
                reason: version.is_none().then_some("metadata_malformed"),
                version,
                source: "package-metadata",
                read_from: manifest.clone(),
            };
            let Some(payload) = read_json(&manifest) else {
                return Some(found(None));
            };
            if payload.get("name").and_then(Value::as_str) == Some(package) {
                return Some(found(
                    payload
                        .get("version")
                        .and_then(Value::as_str)
                        .and_then(parse_version),
                ));
            }
        }
        directory = directory.parent()?;
    }
    None
}

fn read_json(manifest: &Path) -> Option<Value> {
    let mut bytes = Vec::new();
    fs::File::open(manifest)
        .ok()?
        .take(MAX_PACKAGE_JSON_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_PACKAGE_JSON_BYTES {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

fn probe_version(
    source: &VersionSource,
    executable: &Path,
    host: &Host,
) -> (Option<Version>, Option<&'static str>) {
    let probe_cwd = host
        .guard_home
        .join("runtime")
        .join("harness-version-probe");
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    if builder.create(&probe_cwd).is_err() {
        return (None, Some("probe_failed"));
    }
    let mut command = Command::new(executable);
    command
        .arg("--version")
        .current_dir(&probe_cwd)
        .env_clear()
        .env("HOME", host.home_dir)
        .env("NO_COLOR", "1")
        .env("PATH", "")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for name in PROBE_ENVIRONMENT {
        if let Some(value) = host.environment.get(name) {
            command.env(name, value);
        }
    }
    match run_bounded(command) {
        Probe::TimedOut => (None, Some("probe_timeout")),
        Probe::Failed => (None, Some("probe_failed")),
        Probe::Exited(stdout) => {
            let version = String::from_utf8(stdout)
                .ok()
                .and_then(|banner| parse_banner(source, &banner));
            let reason = version.is_none().then_some("banner_malformed");
            (version, reason)
        }
    }
}

/// What one file looks like on disk now, following symlinks.
fn stat_identity(path: &Path) -> Option<Identity> {
    let meta = fs::metadata(path).ok()?;
    #[cfg(unix)]
    let inode = std::os::unix::fs::MetadataExt::ino(&meta);
    #[cfg(not(unix))]
    let inode = 0u64;
    let mtime = meta
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .and_then(|elapsed| i64::try_from(elapsed.as_nanos()).ok())
        .unwrap_or(0);
    Some((text(path), inode, meta.len(), mtime))
}

/// A replaced executable or package, or a changed set of installs.
fn identity_changed(request: &Request, host: &Host) -> bool {
    if let Some(source) = source_for(&request.harness) {
        let mut current: Vec<String> = candidate_executables(source, host)
            .iter()
            .map(|path| text(path))
            .collect();
        current.sort();
        if current != request.candidates {
            return true;
        }
    }
    request
        .identity
        .iter()
        .any(|recorded| stat_identity(Path::new(&recorded.0)).as_ref() != Some(recorded))
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(all(test, unix))]
#[path = "harness_version_discovery_tests.rs"]
mod tests;
