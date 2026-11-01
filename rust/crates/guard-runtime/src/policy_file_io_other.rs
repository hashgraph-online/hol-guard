//! Policy files off Unix: there is no directory descriptor to walk the path
//! without following links, so Guard never trusts the folder.

use std::path::{Path, PathBuf};

use super::Failure;

/// Only Unix paths are raw bytes.
pub(super) fn path_from_bytes(_bytes: Vec<u8>) -> Option<PathBuf> {
    None
}

pub(super) fn read_trusted(_path: &Path, _limit: usize) -> Result<Vec<u8>, Failure> {
    Err("policy_parent_unavailable")
}

pub(super) fn write_private(_path: &Path, _payload: &[u8]) -> Result<(), Failure> {
    Err("policy_parent_unavailable")
}
