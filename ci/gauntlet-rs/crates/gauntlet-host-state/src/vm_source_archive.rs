//! Read-only check of the exact source archive retained in the Lima VM inbox.
//! This confirms transported bytes; it never starts a build or admits a job.

use crate::fixed_process::{run_fixed, FixedProcessError};
use crate::load_operations_bytes;
use gauntlet_contracts::canonicalize;
use serde_json::{json, Value};
use std::fmt;
use std::time::Duration;

const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 2048;
const GUEST_PROBE: &str = r#"import hashlib,json,os,stat,sys
p=sys.argv[1]
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
with os.fdopen(fd,'rb') as f:
 s=os.fstat(f.fileno())
 if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or not 0<s.st_size<=268435456 or stat.S_IMODE(s.st_mode)!=0o600: raise ValueError('unsafe source archive')
 h=hashlib.sha256()
 n=0
 for part in iter(lambda:f.read(1048576),b''):
  n+=len(part)
  if n>268435456: raise ValueError('source archive too large')
  h.update(part)
 t=os.fstat(f.fileno())
 u=os.stat(p,follow_symlinks=False)
 if n!=s.st_size or any(tuple(getattr(x,k) for x in (s,t,u))!=(getattr(s,k),)*3 for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')): raise ValueError('source archive changed')
 print(json.dumps({'sha256':h.hexdigest(),'bytes':n,'uid':s.st_uid,'mode':stat.S_IMODE(s.st_mode)}))"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmSourceArchiveError {
    InvalidInput,
    InvalidConfig,
    InvalidProbe,
    DigestMismatch,
    Unavailable,
    TimedOut,
    TooLarge,
}

impl fmt::Display for VmSourceArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid source archive job or outside digest",
            Self::InvalidConfig => "invalid reviewed VM source configuration",
            Self::InvalidProbe => "VM source archive probe returned invalid data",
            Self::DigestMismatch => "VM source archive differs from outside SHA-256 pin",
            Self::Unavailable => "VM source archive probe unavailable",
            Self::TimedOut => "VM source archive probe timed out",
            Self::TooLarge => "VM source archive probe exceeded byte limit",
        })
    }
}

impl std::error::Error for VmSourceArchiveError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmSourceArchiveProbePlan {
    pub argv: Vec<String>,
    pub job_id: String,
    pub guest_path: String,
    expected_sha256: String,
}

fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl VmSourceArchiveProbePlan {
    pub fn new(
        operations: &Value,
        job_id: &str,
        expected_sha256: &str,
    ) -> Result<Self, VmSourceArchiveError> {
        if !hex(job_id, 16) || !hex(expected_sha256, 64) {
            return Err(VmSourceArchiveError::InvalidInput);
        }
        let raw =
            serde_json::to_vec(operations).map_err(|_| VmSourceArchiveError::InvalidConfig)?;
        let config =
            load_operations_bytes(&raw).map_err(|_| VmSourceArchiveError::InvalidConfig)?;
        if config["release_build_backend"] != "local-vm" {
            return Err(VmSourceArchiveError::InvalidConfig);
        }
        let limactl = config["limactl"]
            .as_str()
            .ok_or(VmSourceArchiveError::InvalidConfig)?;
        let vm = config["vm"]
            .as_str()
            .ok_or(VmSourceArchiveError::InvalidConfig)?;
        let inbox = config["guest_inbox"]
            .as_str()
            .ok_or(VmSourceArchiveError::InvalidConfig)?;
        let guest_path = format!("{inbox}/hol-gauntlet-source-{job_id}.tar.gz");
        if guest_path.len() > 4096 || guest_path.as_bytes().contains(&0) {
            return Err(VmSourceArchiveError::InvalidConfig);
        }
        Ok(Self {
            argv: vec![
                limactl.to_owned(),
                "shell".to_owned(),
                vm.to_owned(),
                "--".to_owned(),
                "/usr/bin/python3".to_owned(),
                "-I".to_owned(),
                "-B".to_owned(),
                "-c".to_owned(),
                GUEST_PROBE.to_owned(),
                guest_path.clone(),
            ],
            job_id: job_id.to_owned(),
            guest_path,
            expected_sha256: expected_sha256.to_owned(),
        })
    }

    pub fn parse_response(&self, stdout: &[u8]) -> Result<Value, VmSourceArchiveError> {
        if stdout.len() > MAX_RESPONSE_BYTES {
            return Err(VmSourceArchiveError::TooLarge);
        }
        let canonical = canonicalize(stdout).map_err(|_| VmSourceArchiveError::InvalidProbe)?;
        let value: Value =
            serde_json::from_slice(&canonical).map_err(|_| VmSourceArchiveError::InvalidProbe)?;
        let object = value
            .as_object()
            .ok_or(VmSourceArchiveError::InvalidProbe)?;
        if object.len() != 4
            || value["sha256"]
                .as_str()
                .is_none_or(|digest| !hex(digest, 64))
            || value["bytes"]
                .as_u64()
                .is_none_or(|bytes| bytes == 0 || bytes > MAX_ARCHIVE_BYTES)
            || value["uid"].as_u64().is_none_or(|uid| uid == 0)
            || value["mode"].as_u64() != Some(0o600)
        {
            return Err(VmSourceArchiveError::InvalidProbe);
        }
        if value["sha256"] != self.expected_sha256 {
            return Err(VmSourceArchiveError::DigestMismatch);
        }
        Ok(json!({
            "schema":"hol-gauntlet-vm-source-archive-shadow.v1",
            "job_id":self.job_id,
            "guest_path":self.guest_path,
            "source_archive_sha256":self.expected_sha256,
            "bytes":value["bytes"],
            "owner_uid":value["uid"],
            "mode":value["mode"],
            "execution_eligible":false,
        }))
    }

    pub fn execute_read_only(&self) -> Result<Value, VmSourceArchiveError> {
        let output = run_fixed(
            &self.argv,
            Duration::from_secs(30),
            MAX_RESPONSE_BYTES,
            1000,
            &[],
        )
        .map_err(|error| match error {
            FixedProcessError::Unavailable | FixedProcessError::Failed => {
                VmSourceArchiveError::Unavailable
            }
            FixedProcessError::TimedOut => VmSourceArchiveError::TimedOut,
            FixedProcessError::TooLarge => VmSourceArchiveError::TooLarge,
        })?;
        self.parse_response(&output)
    }
}
