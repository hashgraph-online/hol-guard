//! One private native esbuild image for a contained Vitest run's transforms.
//!
//! Vitest transforms TypeScript with the project's own esbuild binary. The
//! sandbox runs a private copy instead, read here once from the project's
//! `node_modules` into a directory of its own, so a child cannot replace
//! the image by renaming a writable scratch ancestor.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::OFlag;

use super::{Failure, Outcome};

/// The largest esbuild image copied.
const LIMIT: u64 = 64 * 1024 * 1024;
/// The largest esbuild manifest read.
const MANIFEST_LIMIT: u64 = 64 * 1024;
/// The first bytes of an ELF or Mach-O executable.
const MAGIC: [[u8; 4]; 5] = [
    *b"\x7fELF",
    *b"\xcf\xfa\xed\xfe",
    *b"\xce\xfa\xed\xfe",
    *b"\xfe\xed\xfa\xcf",
    *b"\xca\xfe\xba\xbe",
];
const UNAVAILABLE: &str = "vitest_restricted_esbuild_unavailable";

/// The image a run uses: the project's binary, the private copy, and the
/// version the project's manifest names.
pub(super) struct Image {
    pub(super) source: PathBuf,
    pub(super) image: PathBuf,
    pub(super) version: String,
}

/// The private copy of `project`'s esbuild in `images`, or `None` when the
/// project installs no esbuild.
pub(super) fn snapshot(project: &Path, images: &Path) -> Outcome<Option<Image>> {
    let manifest = project.join("node_modules/esbuild/package.json");
    if !manifest.exists() {
        return Ok(None);
    }
    copy(project, &manifest, images).map(Some).ok_or_else(|| {
        Failure::new(
            UNAVAILABLE,
            "The local transform image could not be safely prepared.",
        )
    })
}

fn copy(project: &Path, manifest: &Path, images: &Path) -> Option<Image> {
    let modules = project.join("node_modules");
    let root = modules.canonicalize().ok()?;
    let resolved = manifest.canonicalize().ok()?;
    if !resolved.starts_with(&root) {
        return None;
    }
    let raw = read_regular(&resolved, MANIFEST_LIMIT)?.1;
    let package: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let version = package.get("version")?.as_str()?;
    if package.get("name").and_then(serde_json::Value::as_str) != Some("esbuild")
        || !release_version(version)
    {
        return None;
    }
    let source = modules
        .join("@esbuild")
        .join(format!("{}-{}", system()?, cpu()?))
        .join("bin/esbuild")
        .canonicalize()
        .ok()?;
    if !source.starts_with(&root) {
        return None;
    }
    let (metadata, image) = read_regular(&source, LIMIT)?;
    let uid = nix::unistd::getuid().as_raw();
    // Another local account can replace a group- or world-writable image
    // before this copy. The private 0500 file is only as trustworthy as the
    // bytes read here, so those write bits stay a refusal unless a private
    // ancestor keeps every other account from reaching the file.
    if ![0, uid].contains(&metadata.uid())
        || (metadata.mode() & 0o022 != 0 && !private_ancestor(&source, uid))
        || metadata.mode() & 0o100 == 0
        || !(4..=LIMIT).contains(&metadata.size())
        || !MAGIC.iter().any(|magic| image.starts_with(magic))
    {
        return None;
    }
    let target = images.join("esbuild");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .custom_flags(OFlag::O_NOFOLLOW.bits())
        .open(&target)
        .ok()?;
    file.write_all(&image).ok()?;
    Some(Image {
        source,
        image: target,
        version: version.to_owned(),
    })
}

/// The bytes of the regular file at `path`, opened without following a
/// link or blocking on a pipe, and refused past `limit` bytes.
fn read_regular(path: &Path, limit: u64) -> Option<(std::fs::Metadata, Vec<u8>)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    let mut raw = Vec::new();
    (&file).take(limit + 1).read_to_end(&mut raw).ok()?;
    (u64::try_from(raw.len()).ok()? <= limit).then_some((metadata, raw))
}

/// Whether a directory above `path` denies search to every other account.
///
/// Package managers such as Bun can unpack images with mode 0777. Under a
/// 0700 home directory those bits grant nothing: no other account can
/// traverse to the file, so it cannot replace it.
fn private_ancestor(path: &Path, uid: u32) -> bool {
    for directory in path.ancestors().skip(1) {
        let Ok(metadata) = std::fs::symlink_metadata(directory) else {
            return false;
        };
        if metadata.file_type().is_symlink() {
            return false;
        }
        if metadata.uid() == uid && metadata.mode() & 0o011 == 0 {
            return true;
        }
    }
    false
}

/// A release version as esbuild publishes it: three numbers of at most
/// eight digits.
fn release_version(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| (1..=8).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit()))
}

fn system() -> Option<&'static str> {
    match std::env::consts::OS {
        "macos" => Some("darwin"),
        "linux" => Some("linux"),
        _ => None,
    }
}

fn cpu() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "aarch64" => Some("arm64"),
        "x86_64" => Some("x64"),
        _ => None,
    }
}

#[cfg(test)]
#[path = "contained_esbuild_image_tests.rs"]
mod tests;
