//! Immutable interpreter identity. This metadata alone grants no authority.
use crate::{
    types::{hex, identifier, platform},
    InterpreterBuild, ReleaseError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterpreterBinding {
    pub build_id: String,
    pub python_version: [u16; 3],
    pub platform: String,
    pub source_revision: String,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    pub tree_sha256: String,
    pub files: u32,
    pub expanded_bytes: u64,
    pub executable_sha256: String,
}
impl InterpreterBuild {
    pub fn binding(&self) -> Result<InterpreterBinding, ReleaseError> {
        self.validate()?;
        Ok(InterpreterBinding {
            build_id: self.build_id.clone(),
            python_version: self.python_version,
            platform: self.platform.clone(),
            source_revision: self.source_revision.clone(),
            archive_sha256: self.archive_sha256.clone(),
            archive_bytes: self.archive_bytes,
            tree_sha256: self.tree_sha256.clone(),
            files: self.files,
            expanded_bytes: self.expanded_bytes,
            executable_sha256: self.executable_sha256.clone(),
        })
    }
}
impl InterpreterBinding {
    pub fn validate(&self) -> Result<(), ReleaseError> {
        if !identifier(&self.build_id)
            || self.python_version[..2] != [3, 14]
            || !platform(&self.platform)
            || !hex(&self.source_revision, 40)
            || !hex(&self.archive_sha256, 64)
            || !hex(&self.tree_sha256, 64)
            || !hex(&self.executable_sha256, 64)
            || self.archive_bytes == 0
            || self.archive_bytes > 128 * 1024 * 1024
            || self.files == 0
            || self.files > 8192
            || self.expanded_bytes == 0
            || self.expanded_bytes > 256 * 1024 * 1024
        {
            return Err(ReleaseError::InvalidIdentity);
        }
        Ok(())
    }
    pub fn executable(&self) -> &'static str {
        if self.platform == "win32-x64" {
            "python.exe"
        } else {
            "bin/python3.14"
        }
    }
    /// Origins, catalog checkpoints and qualification receipts may be refreshed
    /// without changing the installed bytes or their stable physical slot.
    pub fn slot_id(&self) -> Result<String, ReleaseError> {
        self.validate()?;
        let bytes = serde_json::to_vec(&("guard-cigar-python-slot.v2", self))
            .map_err(|_| ReleaseError::InvalidIdentity)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}
