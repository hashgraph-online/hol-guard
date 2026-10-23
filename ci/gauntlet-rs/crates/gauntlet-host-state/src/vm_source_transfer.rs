//! One-use Rust-owned source upload into the fixed Lima VM inbox. Transport
//! loss is always uncertain; this operation does not start a build or job.

use crate::release_source::{ReleaseSourceError, TagLookupPlan};
use crate::source_archive::{verified_archive_bytes, SourceArchiveError};
use crate::source_archive_commit::SourceArchiveCommitProof;
use crate::stream_process::run_streamed;
use crate::vm_source_archive::{VmSourceArchiveError, VmSourceArchiveProbePlan};
use serde_json::{json, Value};
use std::fmt;
use std::path::Path;
use std::time::Duration;

const GUEST_UPLOAD: &str = r#"import hashlib,json,os,stat,sys
p=sys.argv[1]
expected=sys.argv[2]
parent,name=os.path.split(p)
d=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
 os.stat(name,dir_fd=d,follow_symlinks=False)
 raise ValueError('one-use source archive destination exists')
except FileNotFoundError:
 pass
partial='.'+name+'.rust-partial'
fd=os.open(partial,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=d)
h=hashlib.sha256()
n=0
with os.fdopen(fd,'wb',buffering=0) as f:
 for chunk in iter(lambda:sys.stdin.buffer.read(1048576),b''):
  n+=len(chunk)
  if n>268435456: raise ValueError('source archive too large')
  h.update(chunk)
  while chunk:
   written=f.write(chunk)
   if not written: raise OSError('source archive write incomplete')
   chunk=chunk[written:]
 f.flush()
 os.fsync(f.fileno())
 s=os.fstat(f.fileno())
 if not 0<n==s.st_size or h.hexdigest()!=expected or not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600: raise ValueError('source archive input differs')
os.link(partial,name,src_dir_fd=d,dst_dir_fd=d,follow_symlinks=False)
os.fsync(d)
os.unlink(partial,dir_fd=d)
os.fsync(d)
s=os.stat(name,dir_fd=d,follow_symlinks=False)
if s.st_nlink!=1 or s.st_size!=n or stat.S_IMODE(s.st_mode)!=0o600: raise ValueError('source archive publish uncertain')
print(json.dumps({'sha256':h.hexdigest(),'bytes':n,'uid':s.st_uid,'mode':stat.S_IMODE(s.st_mode)}))"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmSourceTransferError {
    InvalidBinding,
    HostArchive(SourceArchiveError),
    ReleaseTag(ReleaseSourceError),
    VmConfig(VmSourceArchiveError),
    GuestUncertain,
}

impl fmt::Display for VmSourceTransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBinding => f.write_str("archive proof has no fixed source binding"),
            Self::HostArchive(error) => write!(f, "host source archive: {error}"),
            Self::ReleaseTag(error) => write!(f, "release recheck: {error}"),
            Self::VmConfig(error) => write!(f, "VM source configuration: {error}"),
            Self::GuestUncertain => f.write_str(
                "guest source upload or readback is uncertain; inspect exact destination before retry",
            ),
        }
    }
}

impl std::error::Error for VmSourceTransferError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmSourceTransferProof {
    job_id: String,
    source_sha: String,
    archive_sha256: String,
    guest_path: String,
    bytes: u64,
    execution_eligible: bool,
}

impl VmSourceTransferProof {
    pub fn archive_sha256(&self) -> &str {
        &self.archive_sha256
    }

    pub fn guest_path(&self) -> &str {
        &self.guest_path
    }

    pub fn execution_eligible(&self) -> bool {
        self.execution_eligible
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-vm-source-transfer.v1",
            "job_id":self.job_id,
            "source_sha":self.source_sha,
            "source_archive_sha256":self.archive_sha256,
            "guest_path":self.guest_path,
            "bytes":self.bytes,
            "one_use_destination_verified":true,
            "execution_eligible":self.execution_eligible,
        })
    }
}

/// Recheck an already verified Git-object archive, stream its exact bytes to
/// an exclusive guest path, then independently reread the guest file. Any
/// post-spawn error is uncertain and never triggers an automatic retry.
pub fn transfer_source_archive_one_use(
    state: &Path,
    operations: &Value,
    proof: &SourceArchiveCommitProof,
) -> Result<VmSourceTransferProof, VmSourceTransferError> {
    if !proof.git_graph_verified() || proof.archive().execution_eligible {
        return Err(VmSourceTransferError::InvalidBinding);
    }
    let guest =
        VmSourceArchiveProbePlan::new(operations, proof.job_id(), &proof.archive().archive_sha256)
            .map_err(VmSourceTransferError::VmConfig)?;
    if let Some(tag) = proof.source_ref().strip_prefix("refs/tags/") {
        TagLookupPlan::new(operations, tag)
            .and_then(|plan| plan.recheck_archive_commit_read_only(proof))
            .map_err(VmSourceTransferError::ReleaseTag)?;
    } else if proof.source_ref() != format!("refs/heads/local-{}", proof.source_sha()) {
        return Err(VmSourceTransferError::InvalidBinding);
    }
    let (bytes, inventory) =
        verified_archive_bytes(state, proof.job_id(), &proof.archive().archive_sha256)
            .map_err(VmSourceTransferError::HostArchive)?;
    if inventory != *proof.archive() {
        return Err(VmSourceTransferError::InvalidBinding);
    }
    let argv = vec![
        guest.argv[0].clone(),
        "shell".to_owned(),
        guest.argv[2].clone(),
        "--".to_owned(),
        "/usr/bin/python3".to_owned(),
        "-I".to_owned(),
        "-B".to_owned(),
        "-c".to_owned(),
        GUEST_UPLOAD.to_owned(),
        guest.guest_path.clone(),
        inventory.archive_sha256.clone(),
    ];
    let response = run_streamed(&argv, &bytes, Duration::from_secs(180), 2048)
        .map_err(|_| VmSourceTransferError::GuestUncertain)?;
    let accepted = guest
        .parse_response(&response)
        .map_err(|_| VmSourceTransferError::GuestUncertain)?;
    let observed = guest
        .execute_read_only()
        .map_err(|_| VmSourceTransferError::GuestUncertain)?;
    if accepted != observed || accepted["bytes"].as_u64() != Some(bytes.len() as u64) {
        return Err(VmSourceTransferError::GuestUncertain);
    }
    Ok(VmSourceTransferProof {
        job_id: proof.job_id().to_owned(),
        source_sha: proof.source_sha().to_owned(),
        archive_sha256: inventory.archive_sha256,
        guest_path: guest.guest_path,
        bytes: bytes.len() as u64,
        execution_eligible: false,
    })
}
