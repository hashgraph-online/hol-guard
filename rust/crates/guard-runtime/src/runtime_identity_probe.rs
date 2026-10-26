//! `runtime-identity-probe --stdin`: describe candidate runtime executables
//! without starting them.
//!
//! For each path the probe follows symlinks, hashes the file it finds, reads
//! the header for operating system and architecture, and takes family,
//! version and, for known installers, vendor from the install layout. It never executes the file, so an
//! executable that prints a version, or does anything else when launched, is
//! never launched. Layout and name claims are `self_reported` at most; the
//! probe cannot produce a locally trusted or vendor verified identity.
//!
//! Paths must be absolute: the probe runs in its own working directory, so a
//! relative path would name a different file than the caller meant. Aliases of
//! one file are hashed once, and the bytes hashed per request are capped.
//!
//! A request may also carry launch specs (see `runtime_identity_launch`): the
//! probe resolves the executable each configured server would launch, adds a
//! launcher script's interpreter, and describes the admitted candidates with
//! the same rules as explicit paths. The reply's `launches` says what each spec
//! resolved to, and `candidate_limit_reached` whether the candidate cap dropped any.
//!
//! The reply's `artifacts` and `locations` are valid input for
//! `runtime-identity-assess`; `observations` carries the paths for display.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::Path;

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::runtime_identity_launch::{
    self as launch, Environment, LaunchSpec, DEFAULT_CANDIDATE_LIMIT, MAX_LAUNCHES,
};
use crate::runtime_identity_probe_format::{sniff, Format, HEADER_BYTES};
use crate::runtime_identity_probe_layout::hint_for;

pub(crate) const COMMAND: &str = "runtime-identity-probe";
pub(crate) const FEATURE: &str = "runtime-identity-probe-v1";
const RESULT_SCHEMA: &str = "guard.runtime-identity-probe.v1";

const MAX_PATHS: usize = 128;
const MAX_PATH_BYTES: usize = 4_096;
/// Runtimes are tens of megabytes; this bounds the read, not the policy.
const MAX_HASH_BYTES: u64 = 512 * 1024 * 1024;
/// Bounds the work one request can do so a large inventory cannot outlast the caller's deadline.
const MAX_TOTAL_HASH_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    launches: Vec<LaunchSpec>,
    /// Process environment values launches may read; never echoed back.
    #[serde(default)]
    environment: BTreeMap<String, String>,
    #[serde(default)]
    candidate_limit: Option<usize>,
}

pub(crate) fn run_command(bytes: &[u8]) -> Result<Value, String> {
    let request: Request = serde_json::from_slice(bytes)
        .map_err(|_| "runtime_identity_probe_request_invalid".to_owned())?;
    Ok(match probe(&request) {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(error) => json!({"ok": false, "error": error}),
    })
}

enum Outcome {
    Present {
        resolved: String,
        artifact: Box<Value>,
    },
    Missing,
    Unknown {
        resolved: Option<String>,
        reason: &'static str,
    },
}

fn probe(request: &Request) -> Result<Value, String> {
    if request.paths.len() > MAX_PATHS {
        return Err("runtime_identity_probe_too_many_paths".to_owned());
    }
    if request.paths.iter().any(|p| {
        p.is_empty() || p.len() > MAX_PATH_BYTES || p.contains('\0') || !Path::new(p).is_absolute()
    }) {
        return Err("runtime_identity_probe_path_invalid".to_owned());
    }
    if request.launches.len() > MAX_LAUNCHES {
        return Err("runtime_identity_probe_too_many_launches".to_owned());
    }
    let limit = request.candidate_limit.unwrap_or(DEFAULT_CANDIDATE_LIMIT);
    if limit == 0
        || limit > MAX_PATHS
        || request.launches.iter().any(|spec| !spec.is_valid())
        || request
            .environment
            .iter()
            .any(|(key, value)| key.contains('\0') || value.contains('\0'))
    {
        return Err("runtime_identity_probe_launch_invalid".to_owned());
    }
    let collected = launch::collect(&request.launches, &Environment(&request.environment), limit);
    let mut requested_paths: Vec<&String> = request.paths.iter().collect();
    requested_paths.extend(&collected.paths);
    if requested_paths.len() > MAX_PATHS {
        return Err("runtime_identity_probe_too_many_paths".to_owned());
    }
    let mut artifacts: BTreeMap<String, Value> = BTreeMap::new();
    let mut locations: Vec<Value> = Vec::new();
    let mut observations: Vec<Value> = Vec::new();
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();
    let mut hashing = Hashing::default();
    for requested in requested_paths {
        let location_id = location_id(requested);
        if seen.insert(location_id.clone(), ()).is_some() {
            continue;
        }
        let (state, artifact_id, resolved, reason) = match observe(requested, &mut hashing) {
            Outcome::Present { resolved, artifact } => {
                let id = artifact["artifact_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                artifacts.entry(id.clone()).or_insert(*artifact);
                ("present", Some(id), Some(resolved), None)
            }
            Outcome::Missing => ("missing", None, None, None),
            Outcome::Unknown { resolved, reason } => ("unknown", None, resolved, Some(reason)),
        };
        locations.push(json!({
            "location_id": location_id, "artifact_id": artifact_id, "state": state,
        }));
        observations.push(json!({
            "location_id": location_id, "requested_path": requested,
            "resolved_path": resolved, "state": state, "reason": reason,
            "artifact_id": artifact_id,
        }));
    }
    Ok(json!({
        "schema": RESULT_SCHEMA,
        "artifacts": artifacts.into_values().collect::<Vec<_>>(),
        "locations": locations,
        "observations": observations,
        "launches": collected.launches,
        "candidate_limit_reached": collected.truncated,
    }))
}

/// One executable for launch admission: its resolved path and artifact, or
/// `None` when it cannot be identified, which stays unknown and never clears.
pub(crate) fn probe_one(path: &Path) -> Option<(String, Value)> {
    match observe(&path.to_string_lossy(), &mut Hashing::default()) {
        Outcome::Present { resolved, artifact } => Some((resolved, *artifact)),
        Outcome::Missing | Outcome::Unknown { .. } => None,
    }
}

fn location_id(requested: &str) -> String {
    let digest = Sha256::digest(format!("guard.runtime-probe-location.v1\0{requested}").as_bytes());
    format!("path:{}", hex::encode(digest))
}

/// Hash results by resolved file, and what is left of the byte budget.
struct Hashing {
    done: BTreeMap<String, Option<(String, Format)>>,
    remaining: u64,
}

impl Default for Hashing {
    fn default() -> Self {
        Self {
            done: BTreeMap::new(),
            remaining: MAX_TOTAL_HASH_BYTES,
        }
    }
}

fn observe(requested: &str, hashing: &mut Hashing) -> Outcome {
    let resolved = match fs::canonicalize(requested) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Outcome::Missing,
        Err(_) => {
            return Outcome::Unknown {
                resolved: None,
                reason: "unresolvable",
            }
        }
    };
    let resolved_text = resolved.to_string_lossy().into_owned();
    let unknown = |reason| Outcome::Unknown {
        resolved: Some(resolved_text.clone()),
        reason,
    };
    // `canonicalize` follows links, so this is the file itself. Checked before
    // opening so a FIFO or device is never read.
    match fs::metadata(&resolved) {
        Ok(meta) if meta.is_file() => {}
        Ok(_) => return unknown("not_regular_file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Outcome::Missing,
        Err(_) => return unknown("unreadable"),
    }
    if !hashing.done.contains_key(&resolved_text) {
        match hash_and_format(&resolved, hashing.remaining) {
            Hashed::TooLarge => return unknown("too_large"),
            Hashed::OverBudget => return unknown("hash_budget_exhausted"),
            Hashed::Read { charged, digest } => {
                hashing.remaining -= charged;
                hashing.done.insert(resolved_text.clone(), digest);
            }
        }
    }
    let Some((sha256, format)) = hashing.done[&resolved_text].clone() else {
        return unknown("unreadable");
    };
    Outcome::Present {
        artifact: Box::new(artifact(&resolved_text, &sha256, &format)),
        resolved: resolved_text,
    }
}

pub(crate) fn open_read_only(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    options.open(path)
}

enum Hashed {
    TooLarge,
    OverBudget,
    /// `charged` is every byte actually read; `digest` is set only for a complete read.
    Read {
        charged: u64,
        digest: Option<(String, Format)>,
    },
}

fn hash_and_format(path: &Path, remaining: u64) -> Hashed {
    let unreadable = Hashed::Read {
        charged: 0,
        digest: None,
    };
    let Ok(file) = open_read_only(path) else {
        return unreadable;
    };
    // The size comes from the opened file, not the path, so a swap between the
    // two cannot make the read larger than what is charged.
    let length = match file.metadata() {
        Ok(meta) if meta.is_file() => meta.len(),
        _ => return unreadable,
    };
    if length > MAX_HASH_BYTES {
        return Hashed::TooLarge;
    }
    // The whole file plus one byte that must come back empty, which proves EOF.
    // Without it an empty or shrunk read would pass for a complete one.
    let limit = length + 1;
    if limit > remaining {
        return Hashed::OverBudget;
    }
    let mut reader = file.take(limit);
    let mut hasher = Sha256::new();
    let mut header = Vec::with_capacity(HEADER_BYTES);
    let mut buffer = [0_u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(read) => read,
            Err(_) => {
                return Hashed::Read {
                    charged: total,
                    digest: None,
                }
            }
        };
        if read == 0 {
            break;
        }
        total += read as u64;
        if header.len() < HEADER_BYTES {
            let room = HEADER_BYTES - header.len();
            header.extend_from_slice(&buffer[..read.min(room)]);
        }
        hasher.update(&buffer[..read]);
    }
    // A file that grew or shrank while it was read is not the file measured.
    let digest = (total == length).then(|| (hex::encode(hasher.finalize()), sniff(&header)));
    Hashed::Read {
        charged: total,
        digest,
    }
}

fn artifact(resolved: &str, sha256: &str, format: &Format) -> Value {
    let hint = hint_for(resolved);
    let family = hint.family.unwrap_or("unknown");
    let assurance = if hint.family.is_some() {
        "self_reported"
    } else {
        "unknown"
    };
    let fields = [
        "guard.runtime-probe-artifact.v1",
        sha256,
        family,
        hint.version.as_deref().unwrap_or(""),
        hint.vendor.unwrap_or(""),
        format.os,
        format.arch,
    ];
    let id = format!(
        "artifact:{}",
        hex::encode(Sha256::digest(fields.join("\0").as_bytes()))
    );
    json!({
        "artifact_id": id, "family": family, "vendor": hint.vendor, "version": hint.version,
        "build_id": null, "os": format.os, "arch": format.arch,
        "executable_sha256": sha256, "component_identity_sha256": null,
        "identity_assurance": assurance,
    })
}

#[cfg(test)]
#[path = "runtime_identity_probe_tests.rs"]
mod tests;
