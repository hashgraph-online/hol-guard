//! Digest-bound private Python preparation. No installer scripts, subprocess,
//! network, symlinks, enrollment or system environment writes.
use crate::*;
use guard_cigar_release::ResolvedInterpreterBuild;
use std::io::Read;
#[path = "python_tar.rs"]
mod tar;

pub fn prepare_python(
    build: &ResolvedInterpreterBuild,
    archive: &Path,
    control: &PreparationControl,
) -> Result<BundlePlan, InstallError> {
    control.checkpoint()?;
    let expected = build.build();
    let input = guard_secure_fs::read_stable(archive, 128 * 1024 * 1024, false)
        .map_err(|_| InstallError::ArtifactUnreadable)?;
    control.checkpoint()?;
    if input.sha256 != expected.archive_sha256 || input.bytes.len() as u64 != expected.archive_bytes
    {
        return Err(InstallError::ArtifactMismatch);
    }
    let mut decoder = flate2::bufread::GzDecoder::new(std::io::Cursor::new(&input.bytes));
    let mut raw = Vec::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        control.checkpoint()?;
        let size = decoder
            .read(&mut buffer)
            .map_err(|_| InstallError::ArchiveInvalid)?;
        if size == 0 {
            break;
        }
        if raw.len().saturating_add(size) > 256 * 1024 * 1024 {
            return Err(InstallError::LimitExceeded);
        }
        raw.extend_from_slice(&buffer[..size]);
    }
    if decoder.get_ref().position() != input.bytes.len() as u64 {
        return Err(InstallError::ArchiveInvalid);
    }
    let files = tar::read(&raw, control)?;
    let mut bytes = 0u64;
    let mut digest = Sha256::new();
    digest.update(b"guard-cigar-python-tree.v1\0");
    for (name, content) in &files {
        control.checkpoint()?;
        bytes = bytes
            .checked_add(content.bytes.len() as u64)
            .ok_or(InstallError::LimitExceeded)?;
        if bytes > MAX_BYTES {
            return Err(InstallError::LimitExceeded);
        }
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update(format!("{:x}", Sha256::digest(&content.bytes)).as_bytes());
    }
    let tree_sha256 = format!("{:x}", digest.finalize());
    if tree_sha256 != expected.tree_sha256
        || files.len() != expected.files as usize
        || bytes != expected.expanded_bytes
    {
        return Err(InstallError::TreeMismatch);
    }
    let python = files
        .get(expected.executable())
        .ok_or(InstallError::InputsInvalid)?;
    if !python.executable
        || format!("{:x}", Sha256::digest(&python.bytes)) != expected.executable_sha256
    {
        return Err(InstallError::ArtifactMismatch);
    }
    Ok(BundlePlan {
        files,
        bytes,
        tree_sha256,
    })
}

#[cfg(test)]
#[path = "python_bundle_tests.rs"]
mod tests;
