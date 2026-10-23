//! A source-bound, local-only builder image plan. The two `FROM` lines are
//! replaced by independently pinned local image IDs, so a registry tag cannot
//! move between preflight and the eventual Podman build. This module does not
//! build, tag, run or admit an image.

use crate::builder_context::BuilderContextProof;
use crate::hex;
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const UV_REF: &str = "ghcr.io/astral-sh/uv:0.9.26";
const RUST_REF: &str = "docker.io/library/rust:1.88.0-slim-bookworm";
const INSPECT_FORMAT: &str = "{{.Id}}|{{.Os}}|{{.Architecture}}";
const INSPECT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderImageError {
    RootRequired,
    InvalidPins,
    UnsupportedDockerfile,
    BaseUnavailable,
    BaseMismatch,
}

impl fmt::Display for BuilderImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux ARM Root required for builder base image custody",
            Self::InvalidPins => "fixed job and two outside base image IDs required",
            Self::UnsupportedDockerfile => "builder Dockerfile has unsupported FROM instructions",
            Self::BaseUnavailable => "fixed local Podman base image inspection failed",
            Self::BaseMismatch => "local Podman base image differs from outside ID or ARM platform",
        })
    }
}

impl std::error::Error for BuilderImageError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderImagePlan {
    pub image_tag: String,
    pub source_context_sha256: String,
    pub effective_dockerfile_sha256: String,
    pub uv_image_id: String,
    pub rust_image_id: String,
    pub job_id: String,
    dockerfile: Vec<u8>,
    entry: Vec<u8>,
    artifact: Vec<u8>,
}

impl BuilderImagePlan {
    pub fn dockerfile_bytes(&self) -> &[u8] {
        &self.dockerfile
    }

    pub fn entry_bytes(&self) -> &[u8] {
        &self.entry
    }

    pub fn artifact_bytes(&self) -> &[u8] {
        &self.artifact
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-builder-image-plan-shadow.v1",
            "job_id":self.job_id,
            "source_context_sha256":self.source_context_sha256,
            "effective_dockerfile_sha256":self.effective_dockerfile_sha256,
            "uv_image_id":self.uv_image_id,
            "rust_image_id":self.rust_image_id,
            "image_tag":self.image_tag,
            "base_images_verified":false,
            "image_built":false,
            "execution_eligible":false,
        })
    }
}

fn is_from(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("FROM"))
        && trimmed
            .as_bytes()
            .get(4)
            .is_some_and(u8::is_ascii_whitespace)
}

fn pinned_dockerfile(
    original: &[u8],
    uv_id: &str,
    rust_id: &str,
) -> Result<Vec<u8>, BuilderImageError> {
    let original =
        std::str::from_utf8(original).map_err(|_| BuilderImageError::UnsupportedDockerfile)?;
    if original.contains('\r') || original.contains('\0') {
        return Err(BuilderImageError::UnsupportedDockerfile);
    }
    let mut output = String::with_capacity(original.len() + 128);
    let mut from_count = 0;
    for line in original.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        if is_from(body) {
            let replacement = match (from_count, body) {
                (0, "FROM ghcr.io/astral-sh/uv:0.9.26 AS uv") => {
                    format!("FROM sha256:{uv_id} AS uv")
                }
                (1, "FROM docker.io/library/rust:1.88.0-slim-bookworm") => {
                    format!("FROM sha256:{rust_id}")
                }
                _ => return Err(BuilderImageError::UnsupportedDockerfile),
            };
            output.push_str(&replacement);
            from_count += 1;
        } else {
            output.push_str(body);
        }
        if line.ends_with('\n') {
            output.push('\n');
        }
    }
    if from_count != 2 || output.contains(UV_REF) || output.contains(RUST_REF) {
        return Err(BuilderImageError::UnsupportedDockerfile);
    }
    Ok(output.into_bytes())
}

/// Build a fixed local-only plan from the already outside-pinned controller
/// context. The image tag includes both base IDs, avoiding collisions with
/// the Python builder's tag when its mutable base tags resolve differently.
pub fn fixed_builder_image_plan(
    context: &BuilderContextProof,
    job_id: &str,
    uv_id: &str,
    rust_id: &str,
) -> Result<BuilderImagePlan, BuilderImageError> {
    if !hex(job_id, 16) || !hex(uv_id, 64) || !hex(rust_id, 64) {
        return Err(BuilderImageError::InvalidPins);
    }
    let dockerfile = pinned_dockerfile(context.dockerfile_bytes(), uv_id, rust_id)?;
    let mut hash = Sha256::new();
    hash.update(b"hol-gauntlet-rust-builder-image-plan.v1\0");
    hash.update(context.context_sha256().as_bytes());
    hash.update(b"\0");
    hash.update(uv_id.as_bytes());
    hash.update(b"\0");
    hash.update(rust_id.as_bytes());
    let identity = format!("{:x}", hash.finalize());
    Ok(BuilderImagePlan {
        image_tag: format!("localhost/hol-gauntlet-rust-builder:{}", &identity[..20]),
        source_context_sha256: context.context_sha256().to_owned(),
        effective_dockerfile_sha256: format!("{:x}", Sha256::digest(&dockerfile)),
        uv_image_id: format!("sha256:{uv_id}"),
        rust_image_id: format!("sha256:{rust_id}"),
        job_id: job_id.to_owned(),
        dockerfile,
        entry: context.entry_bytes().to_vec(),
        artifact: context.artifact_bytes().to_vec(),
    })
}

fn inspect_one(reference: &str, expected: &str) -> Result<(), BuilderImageError> {
    let mut child = Command::new("/usr/bin/podman")
        .args(["image", "inspect", "--format", INSPECT_FORMAT, reference])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| BuilderImageError::BaseUnavailable)?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < INSPECT_TIMEOUT => {
                thread::sleep(Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(BuilderImageError::BaseUnavailable);
            }
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|_| BuilderImageError::BaseUnavailable)?;
    if !output.status.success() || output.stdout.len() > 256 || output.stderr.len() > 4096 {
        return Err(BuilderImageError::BaseUnavailable);
    }
    let line = std::str::from_utf8(&output.stdout)
        .map_err(|_| BuilderImageError::BaseMismatch)?
        .trim_end_matches('\n');
    let expected_line = format!("{expected}|linux|arm64");
    if line != expected_line {
        return Err(BuilderImageError::BaseMismatch);
    }
    Ok(())
}

/// Read-only local Podman preflight. The eventual build must use the image IDs
/// from this plan with `--pull=never`, then reinspect its image and bases.
pub fn inspect_fixed_builder_base_images(plan: &BuilderImagePlan) -> Result<(), BuilderImageError> {
    if geteuid().as_raw() != 0 {
        return Err(BuilderImageError::RootRequired);
    }
    inspect_one(UV_REF, &plan.uv_image_id[7..])?;
    inspect_one(&plan.uv_image_id, &plan.uv_image_id[7..])?;
    inspect_one(RUST_REF, &plan.rust_image_id[7..])?;
    inspect_one(&plan.rust_image_id, &plan.rust_image_id[7..])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder_context::derive_from_bytes;

    fn context() -> BuilderContextProof {
        derive_from_bytes(
            &"a".repeat(64),
            "0123456789abcdef",
            include_bytes!("../../../../gauntlet/control_plane/Builder.Dockerfile"),
            include_bytes!("../../../../gauntlet/control_plane/builder_entry.py"),
            include_bytes!("../../../../gauntlet/control_plane/build_artifact.py"),
            include_bytes!("../../../../gauntlet/control_plane/Builder.apparmor"),
        )
        .unwrap()
    }

    #[test]
    fn exact_controller_context_uses_only_pinned_local_base_ids() {
        let plan = fixed_builder_image_plan(
            &context(),
            "0123456789abcdef",
            &"b".repeat(64),
            &"c".repeat(64),
        )
        .unwrap();
        let dockerfile = std::str::from_utf8(plan.dockerfile_bytes()).unwrap();
        assert!(dockerfile.contains(&format!("FROM sha256:{} AS uv", "b".repeat(64))));
        assert!(dockerfile.contains(&format!("FROM sha256:{}\n", "c".repeat(64))));
        assert!(!dockerfile.contains(UV_REF));
        assert!(!dockerfile.contains(RUST_REF));
        assert_eq!(plan.to_json()["execution_eligible"], false);
        let changed = fixed_builder_image_plan(
            &context(),
            "0123456789abcdef",
            &"d".repeat(64),
            &"c".repeat(64),
        )
        .unwrap();
        assert_ne!(plan.image_tag, changed.image_tag);
    }

    #[test]
    fn unsupported_from_or_unpinned_base_refuses() {
        assert_eq!(
            fixed_builder_image_plan(&context(), "0123456789abcdef", "bad", &"c".repeat(64))
                .unwrap_err(),
            BuilderImageError::InvalidPins
        );
        let changed = b"FROM ghcr.io/astral-sh/uv:0.9.26 AS uv\nFROM docker.io/library/rust:1.88.0-slim-bookworm\nFROM attacker.invalid/latest\n";
        assert_eq!(
            pinned_dockerfile(changed, &"b".repeat(64), &"c".repeat(64)).unwrap_err(),
            BuilderImageError::UnsupportedDockerfile
        );
        let moved = b"FROM ghcr.io/astral-sh/uv:0.9.27 AS uv\nFROM docker.io/library/rust:1.88.0-slim-bookworm\n";
        assert_eq!(
            pinned_dockerfile(moved, &"b".repeat(64), &"c".repeat(64)).unwrap_err(),
            BuilderImageError::UnsupportedDockerfile
        );
    }
}
