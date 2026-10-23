//! One-use inert revision of a shadow candidate's provisional config when its
//! previously pinned local executor image has disappeared from Podman. Only
//! the exact image ID changes; the old config and candidate assets remain.

use crate::builder_image_context::{python_worker_lock, verify_python_lock, RUST_STATE};
use crate::candidate_conformance_readiness::inspect_executor_image;
use crate::{open_root_owned_public_directory, RunReservationJournal};
use gauntlet_contracts::{canonicalize, is_git_sha, validate_runner_declaration};
use gauntlet_evidence::{
    load_runner_config_from_paths, valid_package_version, verify_runner_assets_inert,
};
use rustix::fs::{fchmod, fsync, openat, Mode, OFlags};
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Write;
use std::path::Path;

const SHADOW_ROOT: &str = "/opt/hol-gauntlet/rust-shadow-candidates";

#[derive(Debug, Clone, Copy)]
pub struct StagingConfigRevisionPins<'a> {
    pub build_job_id: &'a str,
    pub source_sha: &'a str,
    pub version: &'a str,
    pub old_config_digest: &'a str,
    pub private_manifest_sha256: &'a str,
    pub prefix_tree_sha256: &'a str,
    pub old_image_id: &'a str,
    pub new_image_id: &'a str,
}

fn lower_hex(raw: &str, len: usize) -> bool {
    raw.len() == len
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn image_id(raw: &str) -> bool {
    raw.strip_prefix("sha256:")
        .is_some_and(|digest| lower_hex(digest, 64))
}

fn revised_config(
    old: &Value,
    old_image: &str,
    new_image: &str,
) -> Result<(Vec<u8>, String), String> {
    if !image_id(old_image)
        || !image_id(new_image)
        || old_image == new_image
        || old["runtime"]["guard_executor_image_id"] != old_image
    {
        return Err("exact changed executor-image pins required".to_owned());
    }
    let mut next = old.clone();
    next["runtime"]["guard_executor_image_id"] = json!(new_image);
    let serialized = serde_json::to_vec(&next).map_err(|error| error.to_string())?;
    let canonical = canonicalize(&serialized).map_err(|error| error.to_string())?;
    let digest = format!("{:x}", Sha256::digest(&canonical));
    validate_runner_declaration(&canonical, &digest).map_err(|error| error.to_string())?;
    let mut file_bytes = canonical;
    file_bytes.push(b'\n');
    Ok((file_bytes, digest))
}

/// Write one distinct Root-owned config while both existing worker locks are
/// held. The output remains provisional and benchmark-ineligible.
pub fn revise_staging_config_ineligible(
    pins: &StagingConfigRevisionPins<'_>,
) -> Result<Value, String> {
    if geteuid().as_raw() != 0
        || !lower_hex(pins.build_job_id, 16)
        || !is_git_sha(pins.source_sha)
        || !valid_package_version(pins.version)
        || !lower_hex(pins.old_config_digest, 64)
        || !lower_hex(pins.private_manifest_sha256, 64)
        || !lower_hex(pins.prefix_tree_sha256, 64)
        || !image_id(pins.old_image_id)
        || !image_id(pins.new_image_id)
        || pins.old_image_id == pins.new_image_id
    {
        return Err("Linux ARM Root and exact staging revision pins required".to_owned());
    }
    let journal = RunReservationJournal::open_root_owned(Path::new(RUST_STATE))
        .map_err(|error| error.to_string())?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|error| error.to_string())?;
    let python_lock = python_worker_lock().map_err(|error| error.to_string())?;
    let shadow_path = Path::new(SHADOW_ROOT).join(pins.build_job_id);
    let shadow =
        open_root_owned_public_directory(&shadow_path).map_err(|error| error.to_string())?;
    let old_name = format!("provisional-{}.json", &pins.private_manifest_sha256[..16]);
    let old_path = shadow_path.join(&old_name);
    let loaded =
        load_runner_config_from_paths(&old_path, pins.old_config_digest, Path::new("/opt"))
            .map_err(|error| error.to_string())?;
    let old = loaded.verified.config.value();
    let base = format!("hol-gauntlet/rust-shadow-candidates/{}", pins.build_job_id);
    let expected_id = format!(
        "rust-shadow-{}-{}-{}",
        pins.source_sha,
        pins.build_job_id,
        &pins.private_manifest_sha256[..16]
    );
    if loaded.verified.version != 7
        || old["id"] != expected_id
        || old["runtime"]["guard_source_sha"] != pins.source_sha
        || old["runtime"]["guard_package_version"] != pins.version
        || old["assets"]["guard_prefix"]["path"] != format!("{base}/prefix")
        || old["assets"]["guard_prefix"]["sha256"] != pins.prefix_tree_sha256
        || old["assets"]["private_cell"]["path"] != format!("{base}/cell-artifacts")
        || old["assets"]["private_cell"]["sha256"] != pins.private_manifest_sha256
        || old["runtime"]["guard_executor_image_id"] != pins.old_image_id
    {
        return Err("source-matched old provisional config differs from outside pins".to_owned());
    }
    verify_runner_assets_inert(&loaded, Path::new("/opt")).map_err(|error| error.to_string())?;
    inspect_executor_image(pins.new_image_id).map_err(|error| error.to_string())?;
    let (bytes, digest) = revised_config(old, pins.old_image_id, pins.new_image_id)?;
    let name = format!(
        "provisional-{}-{}.json",
        &pins.private_manifest_sha256[..16],
        &digest[..16]
    );
    let descriptor = openat(
        &shadow,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|error| format!("one-use revised config unavailable: {error}"))?;
    let mut file = File::from(descriptor);
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    fchmod(&file, Mode::from_bits_truncate(0o444)).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    fsync(&shadow).map_err(|error| error.to_string())?;
    let new_path = shadow_path.join(name);
    let after = load_runner_config_from_paths(&new_path, &digest, Path::new("/opt"))
        .map_err(|error| error.to_string())?;
    let roles =
        verify_runner_assets_inert(&after, Path::new("/opt")).map_err(|error| error.to_string())?;
    if after.verified.config.value()["runtime"]["guard_executor_image_id"] != pins.new_image_id
        || load_runner_config_from_paths(&old_path, pins.old_config_digest, Path::new("/opt"))
            .is_err()
    {
        return Err("revised or original config changed during readback".to_owned());
    }
    inspect_executor_image(pins.new_image_id).map_err(|error| error.to_string())?;
    lease
        .verify(&journal.root)
        .map_err(|error| error.to_string())?;
    verify_python_lock(&python_lock).map_err(|error| error.to_string())?;
    Ok(json!({
        "schema":"hol-gauntlet-staging-config-revision.v1",
        "build_job_id":pins.build_job_id,
        "source_sha":pins.source_sha,
        "old_config_digest":pins.old_config_digest,
        "new_config_digest":digest,
        "new_config_file_sha256":format!("{:x}", Sha256::digest(&bytes)),
        "new_config_path":new_path,
        "new_executor_image_id":pins.new_image_id,
        "asset_roles":roles.observed.len(),
        "execution_eligible":false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v7_revision_preserves_every_other_runner_field() {
        let old: Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../gauntlet-contracts/tests/fixtures/runner_config_v7.json"
        )))
        .unwrap();
        let old_image = old["runtime"]["guard_executor_image_id"].as_str().unwrap();
        let new_image = format!("sha256:{}", "b".repeat(64));
        assert!(revised_config(&old, old_image, old_image).is_err());
        assert!(revised_config(&old, &format!("sha256:{}", "c".repeat(64)), &new_image).is_err());
        let (bytes, digest) = revised_config(&old, old_image, &new_image).unwrap();
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert_eq!(
            digest,
            format!("{:x}", Sha256::digest(&bytes[..bytes.len() - 1]))
        );
        let actual: Value = serde_json::from_slice(&bytes).unwrap();
        let mut next = old.clone();
        next["runtime"]["guard_executor_image_id"] = json!(new_image);
        assert_eq!(actual, next);
    }
}
