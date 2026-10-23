//! Data-only fixed Podman run vector for the future source-bound builder.
//! Constructing this plan never installs a profile or starts a container.

use crate::hex;
use gauntlet_contracts::is_git_sha;
use serde_json::{json, Value};
use std::fmt;

const FIELDS: [&str; 8] = [
    "image_id",
    "job_id",
    "source_sha",
    "source_archive_sha256",
    "tag",
    "memory_gib",
    "local_version",
    "retest_build_job_id",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderRunError {
    InvalidRequest,
    InvalidIdentity,
    InvalidMemory,
}

impl fmt::Display for BuilderRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidRequest => "fixed builder run request required",
            Self::InvalidIdentity => "source-bound release, image and job identity required",
            Self::InvalidMemory => "bounded positive build memory required",
        })
    }
}

impl std::error::Error for BuilderRunError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderRunPlan {
    pub argv: Vec<String>,
    pub job_id: String,
    pub source_archive_sha256: String,
    pub execution_eligible: bool,
}

impl BuilderRunPlan {
    pub fn to_json(&self) -> Value {
        json!({
            "argv": self.argv,
            "job_id": self.job_id,
            "source_archive_sha256": self.source_archive_sha256,
            "execution_eligible": self.execution_eligible,
        })
    }
}

fn valid_local_version(value: &str) -> bool {
    let (base, alpha) = match value.split_once('a') {
        Some((base, alpha)) => (base, Some(alpha)),
        None => (value, None),
    };
    let mut parts = base.split('.');
    if !(0..3).all(|_| {
        parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    }) || parts.next().is_some()
    {
        return false;
    }
    alpha.is_none_or(|suffix| {
        suffix
            .as_bytes()
            .first()
            .is_some_and(|byte| (b'1'..=b'9').contains(byte))
            && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

/// Match the pinned Python `vm_build.container_command` vector on actual
/// execution paths, while requiring the same external request identities that
/// its Root supervisor checks. The caller still must authenticate the image,
/// archive, AppArmor policy, installed controller and one-time worker lease.
pub fn fixed_builder_run_plan(request: &Value) -> Result<BuilderRunPlan, BuilderRunError> {
    let object = request.as_object().ok_or(BuilderRunError::InvalidRequest)?;
    if object.len() != FIELDS.len() || FIELDS.iter().any(|name| !object.contains_key(*name)) {
        return Err(BuilderRunError::InvalidRequest);
    }
    let image_id = request["image_id"]
        .as_str()
        .ok_or(BuilderRunError::InvalidRequest)?;
    let job_id = request["job_id"]
        .as_str()
        .ok_or(BuilderRunError::InvalidRequest)?;
    let sha = request["source_sha"]
        .as_str()
        .ok_or(BuilderRunError::InvalidRequest)?;
    let archive_sha256 = request["source_archive_sha256"]
        .as_str()
        .ok_or(BuilderRunError::InvalidRequest)?;
    let tag = request["tag"]
        .as_str()
        .ok_or(BuilderRunError::InvalidRequest)?;
    let memory = request["memory_gib"]
        .as_i64()
        .ok_or(BuilderRunError::InvalidMemory)?;
    if !(1..=128).contains(&memory) {
        return Err(BuilderRunError::InvalidMemory);
    }
    let local_version = match &request["local_version"] {
        Value::Null => None,
        Value::String(value) => Some(value.as_str()),
        _ => return Err(BuilderRunError::InvalidRequest),
    };
    let retest = match &request["retest_build_job_id"] {
        Value::Null => false,
        Value::String(value) if hex(value, 16) => true,
        _ => return Err(BuilderRunError::InvalidIdentity),
    };
    let image_digest = image_id
        .strip_prefix("sha256:")
        .ok_or(BuilderRunError::InvalidIdentity)?;
    if !hex(image_digest, 64) || !hex(job_id, 16) || !is_git_sha(sha) || !hex(archive_sha256, 64) {
        return Err(BuilderRunError::InvalidIdentity);
    }
    match local_version {
        Some(version) if tag == format!("local-{sha}") && valid_local_version(version) => {}
        None if !retest && matches!(tag, "v3.48.0" | "v3.49.0") => {}
        _ => return Err(BuilderRunError::InvalidIdentity),
    }
    let root = format!("/var/lib/hol-gauntlet/builds/{job_id}");
    let mut argv = vec![
        "/usr/bin/podman".to_owned(),
        "run".to_owned(),
        "--rm".to_owned(),
        "--name".to_owned(),
        format!("hol-gauntlet-build-{job_id}"),
        "--user".to_owned(),
        "65532:65532".to_owned(),
        "--cap-drop=ALL".to_owned(),
        "--security-opt=no-new-privileges".to_owned(),
        format!("--security-opt=apparmor=hol-gauntlet-build-{job_id}"),
        format!("--memory={memory}g"),
        format!("--memory-swap={memory}g"),
        "--cpus=2".to_owned(),
        "--pids-limit=512".to_owned(),
        "--network=slirp4netns".to_owned(),
        "--ipc=private".to_owned(),
        "--volume".to_owned(),
        format!("{root}/source.tar.gz:/input/source.tar.gz:ro"),
        "--volume".to_owned(),
        format!("{root}/export:/output:rw"),
        "--env".to_owned(),
        format!("HOL_GUARD_BUILD_SHA={sha}"),
        "--env".to_owned(),
        format!("HOL_GUARD_RELEASE_TAG={tag}"),
    ];
    if retest {
        argv.extend([
            "--volume".to_owned(),
            format!("{root}/retest-candidate.zip:/input/candidate.zip:ro"),
            "--env".to_owned(),
            "HOL_GUARD_RETEST=1".to_owned(),
        ]);
    }
    if let Some(version) = local_version {
        argv.extend([
            "--env".to_owned(),
            format!("HOL_GUARD_LOCAL_VERSION={version}"),
        ]);
    }
    argv.push(image_id.to_owned());
    Ok(BuilderRunPlan {
        argv,
        job_id: job_id.to_owned(),
        source_archive_sha256: archive_sha256.to_owned(),
        execution_eligible: false,
    })
}
