//! Root-owned one-use guest marker for a host-pinned candidate run. The
//! marker is written before the candidate Podman `run`, and an absent or
//! partial marker consumes this job. Host trust remains outside the guest.

use crate::builder_candidate_preflight::CandidateRuntimePins;
use crate::builder_candidate_receipt::{write_root_canonical_job_file, CandidateReceiptError};
use crate::builder_candidate_source::same_file;
use crate::hex;
use rustix::fs::{fstat, fsync, FileType};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;

pub(crate) const HOST_ANCHOR_FILE: &str = "candidate-run.host-anchor.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateBinaryError {
    InvalidPin,
    Mismatch,
}

impl fmt::Display for CandidateBinaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPin => "exact running binary SHA-256 required",
            Self::Mismatch => "running Root binary differs from outside digest or mode",
        })
    }
}

impl std::error::Error for CandidateBinaryError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCandidateRunAnchor {
    pub(crate) host_pin_sha256: String,
    pub(crate) host_nonce_hex: String,
    pub(crate) runner_binary_sha256: String,
    pub(crate) result_reader_binary_sha256: String,
    pub(crate) policy_sha256: String,
    pub(crate) tag: Option<String>,
}

/// Hash the actual running executable, not its caller-supplied argv path.
/// The host must separately pin the installed Root binary before launch.
pub fn verify_running_binary(expected_sha256: &str) -> Result<(), CandidateBinaryError> {
    if !hex(expected_sha256, 64) {
        return Err(CandidateBinaryError::InvalidPin);
    }
    let mut file = File::open("/proc/self/exe").map_err(|_| CandidateBinaryError::Mismatch)?;
    let before = fstat(&file).map_err(|_| CandidateBinaryError::Mismatch)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o777 != 0o500
        || before.st_size <= 0
        || before.st_size > 128 * 1024 * 1024
    {
        return Err(CandidateBinaryError::Mismatch);
    }
    let mut hash = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| CandidateBinaryError::Mismatch)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > 128 * 1024 * 1024 {
            return Err(CandidateBinaryError::Mismatch);
        }
        hash.update(&buffer[..n]);
    }
    let after = fstat(&file).map_err(|_| CandidateBinaryError::Mismatch)?;
    if count != before.st_size as u64
        || !same_file(&before, &after)
        || format!("{:x}", hash.finalize()) != expected_sha256
    {
        return Err(CandidateBinaryError::Mismatch);
    }
    Ok(())
}

impl HostCandidateRunAnchor {
    pub fn parse(
        policy_sha256: &str,
        result_reader_binary_sha256: &str,
        host_pin_sha256: &str,
        host_nonce_hex: &str,
        runner_binary_sha256: &str,
    ) -> Option<Self> {
        if [
            policy_sha256,
            result_reader_binary_sha256,
            host_pin_sha256,
            host_nonce_hex,
            runner_binary_sha256,
        ]
        .iter()
        .any(|value| !hex(value, 64))
        {
            return None;
        }
        Some(Self {
            policy_sha256: policy_sha256.to_owned(),
            result_reader_binary_sha256: result_reader_binary_sha256.to_owned(),
            host_pin_sha256: host_pin_sha256.to_owned(),
            host_nonce_hex: host_nonce_hex.to_owned(),
            runner_binary_sha256: runner_binary_sha256.to_owned(),
            tag: None,
        })
    }

    pub fn parse_with_tag(
        policy_sha256: &str,
        result_reader_binary_sha256: &str,
        host_pin_sha256: &str,
        host_nonce_hex: &str,
        runner_binary_sha256: &str,
        tag: &str,
    ) -> Option<Self> {
        if !(tag.starts_with("local-") && tag.len() == 46 && hex(&tag[6..], 40)
            || matches!(tag, "v3.48.0" | "v3.49.0"))
        {
            return None;
        }
        let mut anchor = Self::parse(
            policy_sha256,
            result_reader_binary_sha256,
            host_pin_sha256,
            host_nonce_hex,
            runner_binary_sha256,
        )?;
        anchor.tag = Some(tag.to_owned());
        Some(anchor)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn body(
        &self,
        job_id: &str,
        source_sha: &str,
        source_archive_sha256: &str,
        version: &str,
        controller_tree_sha256: &str,
        image_id: &str,
        runtime: &CandidateRuntimePins,
    ) -> Value {
        let mut body = json!({
            "schema":"hol-gauntlet-candidate-host-anchor.v1",
            "job_id":job_id,
            "source_sha":source_sha,
            "source_archive_sha256":source_archive_sha256,
            "version":version,
            "controller_tree_sha256":controller_tree_sha256,
            "image_id":image_id,
            "policy_sha256":self.policy_sha256,
            "runtime_pins":runtime.to_json(),
            "runner_binary_sha256":self.runner_binary_sha256,
            "result_reader_binary_sha256":self.result_reader_binary_sha256,
            "host_pin_sha256":self.host_pin_sha256,
            "host_nonce_hex":self.host_nonce_hex,
            "pre_candidate_run":true,
            "artifact_admitted":false,
            "execution_eligible":false,
        });
        if let Some(tag) = &self.tag {
            body["schema"] = json!("hol-gauntlet-candidate-host-anchor.v2");
            body["tag"] = json!(tag);
        }
        body
    }
}

pub(crate) fn write_host_anchor(
    job: &OwnedFd,
    body: &Value,
) -> Result<String, CandidateReceiptError> {
    let digest = write_root_canonical_job_file(job, HOST_ANCHOR_FILE, body)?;
    fsync(job).map_err(|_| CandidateReceiptError::WriteUncertain)?;
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_five_exact_lowercase_digests() {
        let valid = "a".repeat(64);
        assert!(HostCandidateRunAnchor::parse(&valid, &valid, &valid, &valid, &valid).is_some());
        assert!(HostCandidateRunAnchor::parse("bad", &valid, &valid, &valid, &valid).is_none());
        assert!(HostCandidateRunAnchor::parse(
            &valid,
            &valid,
            &valid,
            &valid,
            &valid.to_uppercase()
        )
        .is_none());
    }
}
