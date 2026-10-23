//! Read-only custody of the pinned builder context and one job's AppArmor
//! policy. This does not build an image, load a policy or start a container.

use crate::hex;
use gauntlet_evidence::verify_controller_tree;
use rustix::fs::{fstat, open, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::Path;

const CONTROL_PLANE: [&str; 3] = ["ci", "gauntlet", "control_plane"];
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const PLACEHOLDER: &str = "HOL_GAUNTLET_BUILD_PROFILE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderContextError {
    RootRequired,
    InvalidPins,
    ControllerMismatch,
    UnsafeFiles,
    Changed,
    InvalidTemplate,
}

impl fmt::Display for BuilderContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux ARM Root required for builder context custody",
            Self::InvalidPins => "fixed builder job and controller tree pins required",
            Self::ControllerMismatch => "Root controller tree differs from outside digest",
            Self::UnsafeFiles => "fixed builder context files are unsafe or unavailable",
            Self::Changed => "builder context changed during inspection",
            Self::InvalidTemplate => "fixed AppArmor template is invalid",
        })
    }
}

impl std::error::Error for BuilderContextError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderContextProof {
    controller_tree_digest: String,
    context_sha256: String,
    image_tag: String,
    profile_name: String,
    policy_sha256: String,
    policy_bytes: Vec<u8>,
    dockerfile_bytes: Vec<u8>,
    entry_bytes: Vec<u8>,
    artifact_bytes: Vec<u8>,
}

impl BuilderContextProof {
    pub fn policy_bytes(&self) -> &[u8] {
        &self.policy_bytes
    }

    pub fn image_tag(&self) -> &str {
        &self.image_tag
    }

    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }

    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }

    pub(crate) fn context_sha256(&self) -> &str {
        &self.context_sha256
    }

    pub(crate) fn dockerfile_bytes(&self) -> &[u8] {
        &self.dockerfile_bytes
    }

    pub(crate) fn entry_bytes(&self) -> &[u8] {
        &self.entry_bytes
    }

    pub(crate) fn artifact_bytes(&self) -> &[u8] {
        &self.artifact_bytes
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-builder-context-shadow.v1",
            "controller_tree_digest":self.controller_tree_digest,
            "context_sha256":self.context_sha256,
            "image_tag":self.image_tag,
            "profile_name":self.profile_name,
            "rendered_policy_sha256":self.policy_sha256,
            "image_verified":false,
            "policy_loaded":false,
            "builder_executed":false,
            "execution_eligible":false,
        })
    }
}

fn same_inode(before: &Stat, after: &Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_nlink == after.st_nlink
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

fn root_directory(directory: &OwnedFd) -> Result<(), BuilderContextError> {
    let stat = fstat(directory).map_err(|_| BuilderContextError::UnsafeFiles)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_mode & 0o022 != 0
    {
        return Err(BuilderContextError::UnsafeFiles);
    }
    Ok(())
}

fn read_context_file(directory: &OwnedFd, name: &str) -> Result<Vec<u8>, BuilderContextError> {
    let descriptor = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BuilderContextError::UnsafeFiles)?;
    let before = fstat(&descriptor).map_err(|_| BuilderContextError::UnsafeFiles)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o022 != 0
        || before.st_size <= 0
        || before.st_size as u64 > MAX_FILE_BYTES
    {
        return Err(BuilderContextError::UnsafeFiles);
    }
    let mut file = File::from(descriptor);
    let mut bytes = Vec::with_capacity(before.st_size as usize);
    Read::by_ref(&mut file)
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BuilderContextError::Changed)?;
    let after = fstat(&file).map_err(|_| BuilderContextError::Changed)?;
    let visible = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| BuilderContextError::Changed)?;
    if bytes.len() as i64 != before.st_size
        || !same_inode(&before, &after)
        || !same_inode(&before, &visible)
    {
        return Err(BuilderContextError::Changed);
    }
    Ok(bytes)
}

pub(crate) fn derive_from_bytes(
    tree_digest: &str,
    job_id: &str,
    dockerfile: &[u8],
    entry: &[u8],
    artifact: &[u8],
    template: &[u8],
) -> Result<BuilderContextProof, BuilderContextError> {
    if !hex(job_id, 16) || !hex(tree_digest, 64) {
        return Err(BuilderContextError::InvalidPins);
    }
    let mut hash = Sha256::new();
    hash.update(dockerfile);
    hash.update(entry);
    hash.update(artifact);
    let context_sha256 = format!("{:x}", hash.finalize());
    let image_tag = format!("localhost/hol-gauntlet-builder:{}", &context_sha256[..20]);
    let template =
        std::str::from_utf8(template).map_err(|_| BuilderContextError::InvalidTemplate)?;
    if !template.contains(PLACEHOLDER) || template.as_bytes().contains(&0) {
        return Err(BuilderContextError::InvalidTemplate);
    }
    let profile_name = format!("hol-gauntlet-build-{job_id}");
    let policy_bytes = template.replace(PLACEHOLDER, &profile_name).into_bytes();
    let policy_sha256 = format!("{:x}", Sha256::digest(&policy_bytes));
    Ok(BuilderContextProof {
        controller_tree_digest: tree_digest.to_owned(),
        context_sha256,
        image_tag,
        profile_name,
        policy_sha256,
        policy_bytes,
        dockerfile_bytes: dockerfile.to_vec(),
        entry_bytes: entry.to_vec(),
        artifact_bytes: artifact.to_vec(),
    })
}

/// Derive the Python-compatible image tag and exact job policy from a full
/// outside-pinned Root controller tree. A future runner must separately pin
/// and inspect the image ID, load/remove the policy and own the build process.
pub fn inspect_fixed_builder_context(
    controller_root: &Path,
    expected_tree_digest: &str,
    job_id: &str,
) -> Result<BuilderContextProof, BuilderContextError> {
    if geteuid().as_raw() != 0 {
        return Err(BuilderContextError::RootRequired);
    }
    if !hex(expected_tree_digest, 64) || !hex(job_id, 16) {
        return Err(BuilderContextError::InvalidPins);
    }
    verify_controller_tree(controller_root, expected_tree_digest)
        .map_err(|_| BuilderContextError::ControllerMismatch)?;
    let mut directory = open(
        controller_root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BuilderContextError::UnsafeFiles)?;
    root_directory(&directory)?;
    for part in CONTROL_PLANE {
        directory = openat(
            &directory,
            part,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| BuilderContextError::UnsafeFiles)?;
        root_directory(&directory)?;
    }
    let dockerfile = read_context_file(&directory, "Builder.Dockerfile")?;
    let entry = read_context_file(&directory, "builder_entry.py")?;
    let artifact = read_context_file(&directory, "build_artifact.py")?;
    let template = read_context_file(&directory, "Builder.apparmor")?;
    let proof = derive_from_bytes(
        expected_tree_digest,
        job_id,
        &dockerfile,
        &entry,
        &artifact,
        &template,
    )?;
    verify_controller_tree(controller_root, expected_tree_digest)
        .map_err(|_| BuilderContextError::Changed)?;
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_context_identity_and_policy_bytes_match() {
        let proof = derive_from_bytes(
            &"a".repeat(64),
            "0123456789abcdef",
            include_bytes!("../../../../gauntlet/control_plane/Builder.Dockerfile"),
            include_bytes!("../../../../gauntlet/control_plane/builder_entry.py"),
            include_bytes!("../../../../gauntlet/control_plane/build_artifact.py"),
            include_bytes!("../../../../gauntlet/control_plane/Builder.apparmor"),
        )
        .unwrap();
        assert_eq!(
            proof.context_sha256,
            "efe7c9623195a139721e607bdd03359b9a2a295acae87d099adff87119727659"
        );
        assert_eq!(
            proof.image_tag(),
            "localhost/hol-gauntlet-builder:efe7c9623195a139721e"
        );
        assert_eq!(
            proof.policy_sha256,
            "17608141e218fdc371147199930ea01c6efc1cacdc72ff33252b126c6b0ec2ea"
        );
        assert!(!proof
            .policy_bytes()
            .windows(PLACEHOLDER.len())
            .any(|bytes| bytes == PLACEHOLDER.as_bytes()));
        assert_eq!(proof.to_json()["execution_eligible"], false);
    }

    #[test]
    fn invalid_pins_or_policy_placeholder_refuse() {
        assert_eq!(
            derive_from_bytes(
                "bad",
                "0123456789abcdef",
                b"x",
                b"y",
                b"z",
                b"profile HOL_GAUNTLET_BUILD_PROFILE"
            ),
            Err(BuilderContextError::InvalidPins)
        );
        assert_eq!(
            derive_from_bytes(
                &"a".repeat(64),
                "0123456789abcdef",
                b"x",
                b"y",
                b"z",
                b"profile x"
            ),
            Err(BuilderContextError::InvalidTemplate)
        );
    }
}
