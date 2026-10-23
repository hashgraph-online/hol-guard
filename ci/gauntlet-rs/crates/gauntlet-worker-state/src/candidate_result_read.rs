//! Read-only reconciliation of a Rust candidate builder result with retained
//! Root and unprivileged build files. No host trust anchor is created here.

use crate::builder_candidate_preflight::CandidateRuntimePins;
use crate::builder_candidate_source::{
    open_fixed_build_slot, same_file, unadmitted_export_identity, verify_captured_source,
};
use crate::builder_image_context::{python_worker_lock, verify_python_lock, RUST_STATE};
use crate::candidate_capture::{inactive, verify_captured};
use crate::candidate_host_anchor::{
    verify_running_binary, HostCandidateRunAnchor, HOST_ANCHOR_FILE,
};
use crate::{hex, RunReservationJournal};
use gauntlet_contracts::{canonicalize, is_git_sha};
use gauntlet_evidence::valid_package_version;
use rustix::fs::{fstat, openat, statat, AtFlags, FileType, Mode, OFlags};
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::Path;

const RESULT: &str = "candidate-run.result.json";
const MAX_RESULT: u64 = 8192;
const MAX_LOG: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateResultReadError {
    RootRequired,
    InvalidPins,
    LeaseUnavailable,
    UnsafeResult,
    ResultMismatch,
    InvalidResult,
    RetainedMismatch,
    CleanupUncertain,
    HostAnchorMismatch,
}

impl fmt::Display for CandidateResultReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux ARM Root required for candidate result reconciliation",
            Self::InvalidPins => "outside candidate result pins required",
            Self::LeaseUnavailable => "Rust or Python worker lease unavailable",
            Self::UnsafeResult => "Root candidate result file is unsafe or changed",
            Self::ResultMismatch => "candidate result differs from outside SHA-256",
            Self::InvalidResult => "candidate result schema or identity is invalid",
            Self::RetainedMismatch => {
                "candidate result differs from retained source, logs or archive"
            }
            Self::CleanupUncertain => "candidate container, cgroup or profile absence unproven",
            Self::HostAnchorMismatch => "host-bound candidate anchor or reader binary differs",
        })
    }
}

impl std::error::Error for CandidateResultReadError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateResultReadProof {
    job_id: String,
    source_sha: String,
    result_sha256: String,
    archive_sha256: String,
    wheel_sha256: String,
    version: String,
    client_pid: u32,
    client_start_ticks: u64,
    host_bound: Option<HostBoundProofFields>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostBoundProofFields {
    tag: Option<String>,
    host_pin_sha256: String,
    host_anchor_sha256: String,
    runner_binary_sha256: String,
    result_reader_binary_sha256: String,
    image_id: String,
    policy_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostBoundCandidateResultPins {
    pub job_id: String,
    pub source_sha: String,
    pub source_archive_sha256: String,
    pub result_sha256: String,
    pub archive_sha256: String,
    pub version: String,
    pub tag: Option<String>,
    pub controller_tree_sha256: String,
    pub image_id: String,
    pub policy_sha256: String,
    pub runtime: CandidateRuntimePins,
    pub anchor: HostCandidateRunAnchor,
}

impl HostBoundCandidateResultPins {
    fn valid(&self) -> bool {
        hex(&self.job_id, 16)
            && is_git_sha(&self.source_sha)
            && hex(&self.source_archive_sha256, 64)
            && hex(&self.result_sha256, 64)
            && hex(&self.archive_sha256, 64)
            && valid_package_version(&self.version)
            && match self.tag.as_deref() {
                None => self.anchor.tag.is_none(),
                Some(tag) => {
                    self.anchor.tag.as_deref() == Some(tag)
                        && (tag == format!("local-{}", self.source_sha)
                            || matches!(tag, "v3.48.0" | "v3.49.0")
                                && &tag[1..] == self.version.as_str())
                }
            }
            && hex(&self.controller_tree_sha256, 64)
            && self
                .image_id
                .strip_prefix("sha256:")
                .is_some_and(|digest| hex(digest, 64))
            && hex(&self.policy_sha256, 64)
            && self.policy_sha256 == self.anchor.policy_sha256
    }
}

impl CandidateResultReadProof {
    pub fn to_json(&self) -> Value {
        let mut body = json!({
            "schema":"hol-gauntlet-candidate-result-read-shadow.v1",
            "job_id":self.job_id,
            "source_sha":self.source_sha,
            "result_sha256":self.result_sha256,
            "archive_sha256":self.archive_sha256,
            "wheel_sha256":self.wheel_sha256,
            "version":self.version,
            "client_pid":self.client_pid,
            "client_start_ticks":self.client_start_ticks,
            "retained_files_match":true,
            "cleanup_absent":true,
            "host_anchor_present":false,
            "artifact_admitted":false,
            "execution_eligible":false,
        });
        if let Some(bound) = &self.host_bound {
            body["schema"] = json!(if bound.tag.is_some() {
                "hol-gauntlet-candidate-result-read-shadow.v3"
            } else {
                "hol-gauntlet-candidate-result-read-shadow.v2"
            });
            if let Some(tag) = &bound.tag {
                body["tag"] = json!(tag);
            }
            body["host_anchor_present"] = json!(true);
            body["host_pin_sha256"] = json!(bound.host_pin_sha256);
            body["host_anchor_sha256"] = json!(bound.host_anchor_sha256);
            body["runner_binary_sha256"] = json!(bound.runner_binary_sha256);
            body["result_reader_binary_sha256"] = json!(bound.result_reader_binary_sha256);
            body["image_id"] = json!(bound.image_id);
            body["policy_sha256"] = json!(bound.policy_sha256);
        }
        body
    }
}

fn root_file_hash(
    job: &OwnedFd,
    name: &str,
    maximum: u64,
    mode: u32,
    allow_empty: bool,
) -> Result<(Vec<u8>, String), CandidateResultReadError> {
    let descriptor = openat(
        job,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateResultReadError::UnsafeResult)?;
    let before = fstat(&descriptor).map_err(|_| CandidateResultReadError::UnsafeResult)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o777 != mode
        || before.st_size < 0
        || (!allow_empty && before.st_size == 0)
        || before.st_size as u64 > maximum
    {
        return Err(CandidateResultReadError::UnsafeResult);
    }
    let mut file = File::from(descriptor);
    let mut bytes = Vec::with_capacity(before.st_size as usize);
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CandidateResultReadError::UnsafeResult)?;
    let after = fstat(&file).map_err(|_| CandidateResultReadError::UnsafeResult)?;
    let visible = statat(job, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidateResultReadError::UnsafeResult)?;
    if bytes.len() as i64 != before.st_size
        || !same_file(&before, &after)
        || !same_file(&before, &visible)
    {
        return Err(CandidateResultReadError::UnsafeResult);
    }
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    Ok((bytes, sha256))
}

fn parse_result(
    raw: &[u8],
    job_id: &str,
    source_sha: &str,
    source_archive_sha256: &str,
    archive_sha256: &str,
    version: &str,
    host_bound: Option<&HostBoundCandidateResultPins>,
) -> Result<Value, CandidateResultReadError> {
    if canonicalize(raw).map_err(|_| CandidateResultReadError::InvalidResult)? != raw {
        return Err(CandidateResultReadError::InvalidResult);
    }
    let value: Value =
        serde_json::from_slice(raw).map_err(|_| CandidateResultReadError::InvalidResult)?;
    let object = value
        .as_object()
        .ok_or(CandidateResultReadError::InvalidResult)?;
    let keys = [
        "artifact_admitted",
        "build_profile_removed",
        "candidate_cgroup_drained",
        "client_pid",
        "client_start_ticks",
        "container_absent",
        "execution_eligible",
        "exit_code",
        "image_id",
        "job_id",
        "local_version",
        "policy_sha256",
        "runtime_pins",
        "schema",
        "source_archive_sha256",
        "source_bytes",
        "source_sha",
        "status",
        "stderr_sha256",
        "stdout_sha256",
        "unadmitted_export_bytes",
        "unadmitted_export_sha256",
    ];
    let host_keys = [
        "host_pin_sha256",
        "host_nonce_hex",
        "host_anchor_sha256",
        "runner_binary_sha256",
        "result_reader_binary_sha256",
    ];
    let extra_count = if host_bound.is_some() {
        host_keys.len()
    } else {
        0
    };
    let tag = host_bound.and_then(|bound| bound.tag.as_deref());
    if object.len() != keys.len() + extra_count + usize::from(tag.is_some())
        || !keys.iter().all(|key| object.contains_key(*key))
        || host_bound.is_some() && !host_keys.iter().all(|key| object.contains_key(*key))
    {
        return Err(CandidateResultReadError::InvalidResult);
    }
    let image = value["image_id"]
        .as_str()
        .ok_or(CandidateResultReadError::InvalidResult)?;
    let runtime = value["runtime_pins"]
        .as_object()
        .ok_or(CandidateResultReadError::InvalidResult)?;
    let schema = if tag.is_some() {
        "hol-gauntlet-candidate-build-result.v3"
    } else if host_bound.is_some() {
        "hol-gauntlet-candidate-build-result.v2"
    } else {
        "hol-gauntlet-candidate-build-result.v1"
    };
    if value["schema"] != schema
        || value["job_id"] != job_id
        || value["source_sha"] != source_sha
        || value["source_archive_sha256"] != source_archive_sha256
        || value["unadmitted_export_sha256"] != archive_sha256
        || value["local_version"]
            != if tag.is_some_and(|tag| !tag.starts_with("local-")) {
                Value::Null
            } else {
                json!(version)
            }
        || tag.is_some_and(|tag| value["tag"] != tag)
        || value["status"] != "exited-zero"
        || value["exit_code"] != 0
        || value["artifact_admitted"] != false
        || value["execution_eligible"] != false
        || value["container_absent"] != true
        || value["candidate_cgroup_drained"] != true
        || value["build_profile_removed"] != true
        || value["client_pid"]
            .as_u64()
            .is_none_or(|pid| pid == 0 || pid > u32::MAX as u64)
        || value["client_start_ticks"]
            .as_u64()
            .is_none_or(|ticks| ticks == 0)
        || value["source_bytes"]
            .as_u64()
            .is_none_or(|bytes| bytes == 0)
        || value["unadmitted_export_bytes"]
            .as_u64()
            .is_none_or(|bytes| bytes == 0 || bytes > 256 * 1024 * 1024)
        || image
            .strip_prefix("sha256:")
            .is_none_or(|digest| !hex(digest, 64))
        || !hex(value["policy_sha256"].as_str().unwrap_or(""), 64)
        || !hex(value["stdout_sha256"].as_str().unwrap_or(""), 64)
        || !hex(value["stderr_sha256"].as_str().unwrap_or(""), 64)
        || runtime.len() != 4
        || ![
            "podman_sha256",
            "slirp4netns_sha256",
            "apparmor_parser_sha256",
            "seccomp_sha256",
        ]
        .iter()
        .all(|key| {
            runtime
                .get(*key)
                .and_then(Value::as_str)
                .is_some_and(|raw| hex(raw, 64))
        })
    {
        return Err(CandidateResultReadError::InvalidResult);
    }
    if let Some(bound) = host_bound {
        if value["host_pin_sha256"] != bound.anchor.host_pin_sha256
            || value["host_nonce_hex"] != bound.anchor.host_nonce_hex
            || value["runner_binary_sha256"] != bound.anchor.runner_binary_sha256
            || value["result_reader_binary_sha256"] != bound.anchor.result_reader_binary_sha256
            || !hex(value["host_anchor_sha256"].as_str().unwrap_or(""), 64)
            || value["image_id"] != bound.image_id
            || value["policy_sha256"] != bound.policy_sha256
            || value["runtime_pins"] != bound.runtime.to_json()
        {
            return Err(CandidateResultReadError::HostAnchorMismatch);
        }
    }
    Ok(value)
}

pub fn read_fixed_candidate_result_ineligible(
    job_id: &str,
    source_sha: &str,
    source_archive_sha256: &str,
    result_sha256: &str,
    archive_sha256: &str,
    version: &str,
) -> Result<CandidateResultReadProof, CandidateResultReadError> {
    read_candidate_result_inner(
        job_id,
        source_sha,
        source_archive_sha256,
        result_sha256,
        archive_sha256,
        version,
        None,
    )
}

pub fn read_fixed_hostbound_candidate_result_ineligible(
    pins: &HostBoundCandidateResultPins,
) -> Result<CandidateResultReadProof, CandidateResultReadError> {
    if geteuid().as_raw() != 0 {
        return Err(CandidateResultReadError::RootRequired);
    }
    if !pins.valid() {
        return Err(CandidateResultReadError::InvalidPins);
    }
    verify_running_binary(&pins.anchor.result_reader_binary_sha256)
        .map_err(|_| CandidateResultReadError::HostAnchorMismatch)?;
    read_candidate_result_inner(
        &pins.job_id,
        &pins.source_sha,
        &pins.source_archive_sha256,
        &pins.result_sha256,
        &pins.archive_sha256,
        &pins.version,
        Some(pins),
    )
}

#[allow(clippy::too_many_arguments)]
fn read_candidate_result_inner(
    job_id: &str,
    source_sha: &str,
    source_archive_sha256: &str,
    result_sha256: &str,
    archive_sha256: &str,
    version: &str,
    host_bound: Option<&HostBoundCandidateResultPins>,
) -> Result<CandidateResultReadProof, CandidateResultReadError> {
    if geteuid().as_raw() != 0 {
        return Err(CandidateResultReadError::RootRequired);
    }
    if !hex(job_id, 16)
        || !is_git_sha(source_sha)
        || !hex(source_archive_sha256, 64)
        || !hex(result_sha256, 64)
        || !hex(archive_sha256, 64)
        || !valid_package_version(version)
    {
        return Err(CandidateResultReadError::InvalidPins);
    }
    let journal = RunReservationJournal::open_root_owned(Path::new(RUST_STATE))
        .map_err(|_| CandidateResultReadError::LeaseUnavailable)?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|_| CandidateResultReadError::LeaseUnavailable)?;
    let python_lock =
        python_worker_lock().map_err(|_| CandidateResultReadError::LeaseUnavailable)?;
    let job = open_fixed_build_slot(job_id).map_err(|_| CandidateResultReadError::UnsafeResult)?;
    inactive(job_id).map_err(|_| CandidateResultReadError::CleanupUncertain)?;
    let (raw, observed_sha) = root_file_hash(&job, RESULT, MAX_RESULT, 0o600, false)?;
    if observed_sha != result_sha256 {
        return Err(CandidateResultReadError::ResultMismatch);
    }
    let result = parse_result(
        &raw,
        job_id,
        source_sha,
        source_archive_sha256,
        archive_sha256,
        version,
        host_bound,
    )?;
    if let Some(bound) = host_bound {
        let (anchor_bytes, anchor_sha256) =
            root_file_hash(&job, HOST_ANCHOR_FILE, MAX_RESULT, 0o600, false)
                .map_err(|_| CandidateResultReadError::HostAnchorMismatch)?;
        let expected = bound.anchor.body(
            job_id,
            source_sha,
            source_archive_sha256,
            version,
            &bound.controller_tree_sha256,
            &bound.image_id,
            &bound.runtime,
        );
        let expected_bytes = canonicalize(expected.to_string().as_bytes())
            .map_err(|_| CandidateResultReadError::HostAnchorMismatch)?;
        if anchor_bytes != expected_bytes || result["host_anchor_sha256"] != anchor_sha256 {
            return Err(CandidateResultReadError::HostAnchorMismatch);
        }
    }
    let source_bytes = verify_captured_source(&job, source_archive_sha256)
        .map_err(|_| CandidateResultReadError::RetainedMismatch)?;
    let export = unadmitted_export_identity(&job)
        .map_err(|_| CandidateResultReadError::RetainedMismatch)?
        .ok_or(CandidateResultReadError::RetainedMismatch)?;
    if result["source_bytes"] != source_bytes
        || result["unadmitted_export_bytes"] != export.0
        || export.1 != archive_sha256
    {
        return Err(CandidateResultReadError::RetainedMismatch);
    }
    for (name, field) in [
        ("candidate-run.stdout.log", "stdout_sha256"),
        ("candidate-run.stderr.log", "stderr_sha256"),
    ] {
        let (_, digest) = root_file_hash(&job, name, MAX_LOG, 0o600, true)
            .map_err(|_| CandidateResultReadError::RetainedMismatch)?;
        if result[field] != digest {
            return Err(CandidateResultReadError::RetainedMismatch);
        }
    }
    let declaration = verify_captured(&job, archive_sha256, export.0, source_sha, version)
        .map_err(|_| CandidateResultReadError::RetainedMismatch)?;
    lease
        .verify(&journal.root)
        .map_err(|_| CandidateResultReadError::LeaseUnavailable)?;
    verify_python_lock(&python_lock).map_err(|_| CandidateResultReadError::LeaseUnavailable)?;
    inactive(job_id).map_err(|_| CandidateResultReadError::CleanupUncertain)?;
    let (_, final_sha) = root_file_hash(&job, RESULT, MAX_RESULT, 0o600, false)?;
    if final_sha != result_sha256 {
        return Err(CandidateResultReadError::ResultMismatch);
    }
    if host_bound.is_some() {
        let (_, final_anchor_sha256) =
            root_file_hash(&job, HOST_ANCHOR_FILE, MAX_RESULT, 0o600, false)
                .map_err(|_| CandidateResultReadError::HostAnchorMismatch)?;
        if result["host_anchor_sha256"] != final_anchor_sha256 {
            return Err(CandidateResultReadError::HostAnchorMismatch);
        }
    }
    Ok(CandidateResultReadProof {
        job_id: job_id.to_owned(),
        source_sha: source_sha.to_owned(),
        result_sha256: result_sha256.to_owned(),
        archive_sha256: archive_sha256.to_owned(),
        wheel_sha256: declaration.wheel_sha256,
        version: version.to_owned(),
        client_pid: result["client_pid"].as_u64().unwrap_or_default() as u32,
        client_start_ticks: result["client_start_ticks"].as_u64().unwrap_or_default(),
        host_bound: host_bound.map(|pins| HostBoundProofFields {
            tag: pins.tag.clone(),
            host_pin_sha256: pins.anchor.host_pin_sha256.clone(),
            host_anchor_sha256: result["host_anchor_sha256"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            runner_binary_sha256: pins.anchor.runner_binary_sha256.clone(),
            result_reader_binary_sha256: pins.anchor.result_reader_binary_sha256.clone(),
            image_id: pins.image_id.clone(),
            policy_sha256: pins.policy_sha256.clone(),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const JOB: &str = "c04e7f93a2b15d68";
    const SOURCE: &str = "76c31929833b5571d25a56d9783e24a0997d5422";
    const SOURCE_ARCHIVE: &str = "bedd98ab7da8ca728484799e1ef6b13c854f7fcbb31a17ebdcc469c4c772af43";
    const ARCHIVE: &str = "d9a3258818344e48c84808692c598ace45ec19bb1cb782bb958505795ec5ac04";

    fn fixture() -> Value {
        json!({
            "artifact_admitted":false,
            "build_profile_removed":true,
            "candidate_cgroup_drained":true,
            "client_pid":1253463,
            "client_start_ticks":31070585,
            "container_absent":true,
            "execution_eligible":false,
            "exit_code":0,
            "image_id":format!("sha256:{}", "a".repeat(64)),
            "job_id":JOB,
            "local_version":"3.49.0",
            "policy_sha256":"b".repeat(64),
            "runtime_pins":{
                "podman_sha256":"c".repeat(64),
                "slirp4netns_sha256":"d".repeat(64),
                "apparmor_parser_sha256":"e".repeat(64),
                "seccomp_sha256":"f".repeat(64),
            },
            "schema":"hol-gauntlet-candidate-build-result.v1",
            "source_archive_sha256":SOURCE_ARCHIVE,
            "source_bytes":45439546,
            "source_sha":SOURCE,
            "status":"exited-zero",
            "stderr_sha256":"1".repeat(64),
            "stdout_sha256":"2".repeat(64),
            "unadmitted_export_bytes":20274622,
            "unadmitted_export_sha256":ARCHIVE,
        })
    }

    fn parse(value: &Value) -> Result<Value, CandidateResultReadError> {
        let bytes = canonicalize(value.to_string().as_bytes()).expect("canonical fixture");
        parse_result(&bytes, JOB, SOURCE, SOURCE_ARCHIVE, ARCHIVE, "3.49.0", None)
    }

    #[test]
    fn candidate_result_schema_requires_outside_identity_and_ineligibility() {
        let valid = fixture();
        assert_eq!(parse(&valid), Ok(valid.clone()));
        for (name, altered) in [
            ("wrong job", json!("0000000000000000")),
            ("wrong source", json!("0".repeat(40))),
            ("wrong source archive", json!("0".repeat(64))),
            ("wrong export", json!("0".repeat(64))),
            ("wrong version", json!("3.50.0")),
        ] {
            let mut invalid = valid.clone();
            let field = match name {
                "wrong job" => "job_id",
                "wrong source" => "source_sha",
                "wrong source archive" => "source_archive_sha256",
                "wrong export" => "unadmitted_export_sha256",
                _ => "local_version",
            };
            invalid[field] = altered;
            assert_eq!(
                parse(&invalid),
                Err(CandidateResultReadError::InvalidResult),
                "{name}"
            );
        }
        for (field, altered) in [
            ("status", json!("build-failed")),
            ("exit_code", json!(1)),
            ("artifact_admitted", json!(true)),
            ("execution_eligible", json!(true)),
            ("container_absent", json!(false)),
            ("candidate_cgroup_drained", json!(false)),
            ("build_profile_removed", json!(false)),
            ("client_pid", json!(0)),
            ("unadmitted_export_bytes", json!(0)),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = altered;
            assert_eq!(
                parse(&invalid),
                Err(CandidateResultReadError::InvalidResult),
                "{field}"
            );
        }
        let mut extra = valid.clone();
        extra["surprise"] = json!(1);
        assert_eq!(parse(&extra), Err(CandidateResultReadError::InvalidResult));
        let noncanonical = format!(" {valid}");
        assert_eq!(
            parse_result(
                noncanonical.as_bytes(),
                JOB,
                SOURCE,
                SOURCE_ARCHIVE,
                ARCHIVE,
                "3.49.0",
                None
            ),
            Err(CandidateResultReadError::InvalidResult)
        );
    }

    #[test]
    fn hostbound_v2_result_requires_the_exact_host_tuple() {
        let runtime = CandidateRuntimePins::parse(
            &"c".repeat(64),
            &"d".repeat(64),
            &"e".repeat(64),
            &"f".repeat(64),
        )
        .unwrap();
        let anchor = HostCandidateRunAnchor::parse(
            &"b".repeat(64),
            &"4".repeat(64),
            &"5".repeat(64),
            &"6".repeat(64),
            &"7".repeat(64),
        )
        .unwrap();
        let bound = HostBoundCandidateResultPins {
            job_id: JOB.to_owned(),
            source_sha: SOURCE.to_owned(),
            source_archive_sha256: SOURCE_ARCHIVE.to_owned(),
            result_sha256: "8".repeat(64),
            archive_sha256: ARCHIVE.to_owned(),
            version: "3.49.0".to_owned(),
            tag: None,
            controller_tree_sha256: "9".repeat(64),
            image_id: format!("sha256:{}", "a".repeat(64)),
            policy_sha256: "b".repeat(64),
            runtime,
            anchor,
        };
        assert!(bound.valid());
        let mut value = fixture();
        value["schema"] = json!("hol-gauntlet-candidate-build-result.v2");
        value["host_pin_sha256"] = json!(bound.anchor.host_pin_sha256);
        value["host_nonce_hex"] = json!(bound.anchor.host_nonce_hex);
        value["host_anchor_sha256"] = json!("a".repeat(64));
        value["runner_binary_sha256"] = json!(bound.anchor.runner_binary_sha256);
        value["result_reader_binary_sha256"] = json!(bound.anchor.result_reader_binary_sha256);
        let check = |value: &Value| {
            let bytes = canonicalize(value.to_string().as_bytes()).unwrap();
            parse_result(
                &bytes,
                JOB,
                SOURCE,
                SOURCE_ARCHIVE,
                ARCHIVE,
                "3.49.0",
                Some(&bound),
            )
        };
        assert_eq!(check(&value), Ok(value.clone()));
        for field in [
            "host_pin_sha256",
            "host_nonce_hex",
            "runner_binary_sha256",
            "result_reader_binary_sha256",
            "image_id",
            "policy_sha256",
        ] {
            let mut wrong = value.clone();
            wrong[field] = json!("0".repeat(64));
            assert!(check(&wrong).is_err(), "{field}");
        }
        let mut bad_anchor_digest = value.clone();
        bad_anchor_digest["host_anchor_sha256"] = json!("not-a-digest");
        assert_eq!(
            check(&bad_anchor_digest),
            Err(CandidateResultReadError::HostAnchorMismatch)
        );
        let mut legacy = value.clone();
        legacy["schema"] = json!("hol-gauntlet-candidate-build-result.v1");
        assert_eq!(check(&legacy), Err(CandidateResultReadError::InvalidResult));
    }

    #[test]
    fn hostbound_v3_release_requires_tag_and_null_local_version() {
        let runtime = CandidateRuntimePins::parse(
            &"c".repeat(64),
            &"d".repeat(64),
            &"e".repeat(64),
            &"f".repeat(64),
        )
        .unwrap();
        let anchor = HostCandidateRunAnchor::parse_with_tag(
            &"b".repeat(64),
            &"4".repeat(64),
            &"5".repeat(64),
            &"6".repeat(64),
            &"7".repeat(64),
            "v3.49.0",
        )
        .unwrap();
        let bound = HostBoundCandidateResultPins {
            job_id: JOB.to_owned(),
            source_sha: SOURCE.to_owned(),
            source_archive_sha256: SOURCE_ARCHIVE.to_owned(),
            result_sha256: "8".repeat(64),
            archive_sha256: ARCHIVE.to_owned(),
            version: "3.49.0".to_owned(),
            tag: Some("v3.49.0".to_owned()),
            controller_tree_sha256: "9".repeat(64),
            image_id: format!("sha256:{}", "a".repeat(64)),
            policy_sha256: "b".repeat(64),
            runtime,
            anchor,
        };
        assert!(bound.valid());
        let mut value = fixture();
        value["schema"] = json!("hol-gauntlet-candidate-build-result.v3");
        value["tag"] = json!("v3.49.0");
        value["local_version"] = Value::Null;
        value["host_pin_sha256"] = json!(bound.anchor.host_pin_sha256);
        value["host_nonce_hex"] = json!(bound.anchor.host_nonce_hex);
        value["host_anchor_sha256"] = json!("a".repeat(64));
        value["runner_binary_sha256"] = json!(bound.anchor.runner_binary_sha256);
        value["result_reader_binary_sha256"] = json!(bound.anchor.result_reader_binary_sha256);
        let check = |value: &Value| {
            let bytes = canonicalize(value.to_string().as_bytes()).unwrap();
            parse_result(
                &bytes,
                JOB,
                SOURCE,
                SOURCE_ARCHIVE,
                ARCHIVE,
                "3.49.0",
                Some(&bound),
            )
        };
        assert_eq!(check(&value), Ok(value.clone()));
        let mut wrong = value.clone();
        wrong["tag"] = json!("v3.48.0");
        assert_eq!(check(&wrong), Err(CandidateResultReadError::InvalidResult));
        wrong = value;
        wrong["local_version"] = json!("3.49.0");
        assert_eq!(check(&wrong), Err(CandidateResultReadError::InvalidResult));
    }
}
