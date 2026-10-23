//! Pure projection of Python staging's provisional v7 candidate config.
//! No candidate files are read or installed by this module.

use gauntlet_contracts::{canonicalize, is_git_sha, validate_runner_declaration};
use gauntlet_evidence::valid_package_version;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateConfigProjectionError {
    InvalidPins,
    InvalidTemplate,
    UnsupportedTemplate,
    InvalidProjection,
}

impl fmt::Display for CandidateConfigProjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPins => "exact candidate config input pins required",
            Self::InvalidTemplate => "outside-pinned runner template required",
            Self::UnsupportedTemplate => "v7 candidate runner template required",
            Self::InvalidProjection => "candidate config projection is invalid",
        })
    }
}

impl std::error::Error for CandidateConfigProjectionError {}

#[derive(Debug, Clone, Copy)]
pub struct CandidateConfigProjectionPins<'a> {
    pub source_sha: &'a str,
    pub package_version: &'a str,
    pub native_sha256: &'a str,
    pub root_prefix_digest: &'a str,
    pub runtime_tree_digest: &'a str,
    pub wheel_sha256: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateConfigProjection {
    pub canonical_bytes: Vec<u8>,
    pub file_bytes: Vec<u8>,
    pub digest: String,
}

fn lower_hex(raw: &str, len: usize) -> bool {
    raw.len() == len
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Match the `stage_candidate.py` provisional edits for a normal PR candidate.
/// The output is data only; caller-owned asset verification and fresh signed
/// conformance must precede any deployment declaration.
pub fn project_candidate_config_ineligible(
    template_raw: &[u8],
    template_digest: &str,
    pins: &CandidateConfigProjectionPins<'_>,
) -> Result<CandidateConfigProjection, CandidateConfigProjectionError> {
    let base = format!("hol-gauntlet/candidates/{}", pins.source_sha);
    let id = format!("pr-{}", pins.source_sha);
    project_at_fixed_base(template_raw, template_digest, pins, &base, &id)
}

/// The same inert v7 transformation for an isolated, one-use Rust shadow
/// asset root. Its Root-only parent prevents this data from becoming a live
/// runner deployment; no config file is written here.
pub fn project_shadow_candidate_config_ineligible(
    template_raw: &[u8],
    template_digest: &str,
    pins: &CandidateConfigProjectionPins<'_>,
    job_id: &str,
) -> Result<CandidateConfigProjection, CandidateConfigProjectionError> {
    if !lower_hex(job_id, 16) {
        return Err(CandidateConfigProjectionError::InvalidPins);
    }
    let base = format!("hol-gauntlet/rust-shadow-candidates/{job_id}");
    let id = format!("rust-shadow-{}-{job_id}", pins.source_sha);
    project_at_fixed_base(template_raw, template_digest, pins, &base, &id)
}

/// A fresh source-matched private-cell generation inside the same inert shadow
/// root. The manifest digest selects a distinct one-use config filename and
/// candidate ID, so a prior failed provisional file remains untouched.
pub fn project_shadow_candidate_config_with_private_cell_ineligible(
    template_raw: &[u8],
    template_digest: &str,
    pins: &CandidateConfigProjectionPins<'_>,
    job_id: &str,
    manifest_sha256: &str,
) -> Result<CandidateConfigProjection, CandidateConfigProjectionError> {
    if !lower_hex(job_id, 16) || !lower_hex(manifest_sha256, 64) {
        return Err(CandidateConfigProjectionError::InvalidPins);
    }
    let base = format!("hol-gauntlet/rust-shadow-candidates/{job_id}");
    let id = format!(
        "rust-shadow-{}-{job_id}-{}",
        pins.source_sha,
        &manifest_sha256[..16]
    );
    let base_projection = project_at_fixed_base(template_raw, template_digest, pins, &base, &id)?;
    let mut config: serde_json::Value = serde_json::from_slice(&base_projection.canonical_bytes)
        .map_err(|_| CandidateConfigProjectionError::InvalidProjection)?;
    config["assets"]["private_cell"]["path"] = json!(format!("{base}/cell-artifacts"));
    config["assets"]["private_cell"]["sha256"] = json!(manifest_sha256);
    let serialized = serde_json::to_vec(&config)
        .map_err(|_| CandidateConfigProjectionError::InvalidProjection)?;
    let canonical_bytes =
        canonicalize(&serialized).map_err(|_| CandidateConfigProjectionError::InvalidProjection)?;
    let digest = format!("{:x}", Sha256::digest(&canonical_bytes));
    validate_runner_declaration(&canonical_bytes, &digest)
        .map_err(|_| CandidateConfigProjectionError::InvalidProjection)?;
    let mut file_bytes = canonical_bytes.clone();
    file_bytes.push(b'\n');
    Ok(CandidateConfigProjection {
        canonical_bytes,
        file_bytes,
        digest,
    })
}

fn project_at_fixed_base(
    template_raw: &[u8],
    template_digest: &str,
    pins: &CandidateConfigProjectionPins<'_>,
    base: &str,
    id: &str,
) -> Result<CandidateConfigProjection, CandidateConfigProjectionError> {
    if !is_git_sha(pins.source_sha)
        || !valid_package_version(pins.package_version)
        || !lower_hex(pins.native_sha256, 64)
        || !lower_hex(pins.root_prefix_digest, 64)
        || !lower_hex(pins.runtime_tree_digest, 64)
        || pins.root_prefix_digest != pins.runtime_tree_digest
        || !lower_hex(pins.wheel_sha256, 64)
    {
        return Err(CandidateConfigProjectionError::InvalidPins);
    }
    let template = validate_runner_declaration(template_raw, template_digest)
        .map_err(|_| CandidateConfigProjectionError::InvalidTemplate)?;
    if template.version != 7 {
        return Err(CandidateConfigProjectionError::UnsupportedTemplate);
    }
    let mut config = template.record.value().clone();
    let wheel = format!(
        "{base}/hol_guard-{}-py3-none-linux_aarch64.whl",
        pins.package_version
    );
    let native = format!("{base}/hol-guard-runtime");
    config["id"] = json!(id);
    config["runtime"]["guard_source_sha"] = json!(pins.source_sha);
    config["runtime"]["guard_package_version"] = json!(pins.package_version);
    config["runtime"]["private_cell"]["native_sha256"] = json!(pins.native_sha256);
    config["runtime"]["private_cell"]["runtime_tree_digest"] = json!(pins.runtime_tree_digest);
    config["assets"]["guard_prefix"]["path"] = json!(format!("{base}/prefix"));
    config["assets"]["guard_prefix"]["sha256"] = json!(pins.root_prefix_digest);
    config["assets"]["wheel"]["path"] = json!(wheel);
    config["assets"]["wheel"]["sha256"] = json!(pins.wheel_sha256);
    for role in ["native", "compiler"] {
        config["assets"][role]["path"] = json!(native);
        config["assets"][role]["sha256"] = json!(pins.native_sha256);
    }
    let serialized = serde_json::to_vec(&config)
        .map_err(|_| CandidateConfigProjectionError::InvalidProjection)?;
    let canonical_bytes =
        canonicalize(&serialized).map_err(|_| CandidateConfigProjectionError::InvalidProjection)?;
    let digest = format!("{:x}", Sha256::digest(&canonical_bytes));
    validate_runner_declaration(&canonical_bytes, &digest)
        .map_err(|_| CandidateConfigProjectionError::InvalidProjection)?;
    let mut file_bytes = canonical_bytes.clone();
    file_bytes.push(b'\n');
    Ok(CandidateConfigProjection {
        canonical_bytes,
        file_bytes,
        digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(version: u8) -> Vec<u8> {
        match version {
            6 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../gauntlet-contracts/tests/fixtures/runner_config_v6.json"
            ))
            .to_vec(),
            7 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../gauntlet-contracts/tests/fixtures/runner_config_v7.json"
            ))
            .to_vec(),
            _ => panic!("unsupported test fixture version"),
        }
    }

    fn pins() -> CandidateConfigProjectionPins<'static> {
        CandidateConfigProjectionPins {
            source_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            package_version: "3.48.0",
            native_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            root_prefix_digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            runtime_tree_digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            wheel_sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        }
    }

    #[test]
    fn python_frozen_v7_projection_matches_canonical_digest_and_file_bytes() {
        let projection = project_candidate_config_ineligible(
            &fixture(7),
            "580c94be23f58345bf7c59eb11239ae9bd21347b70fadb6c19f243b7f7a3f1e8",
            &pins(),
        )
        .unwrap();
        assert_eq!(
            projection.digest,
            "d2ada18656a9a8c51162d376ab24cd80e601b80240641495cfa3710f7a90ae31"
        );
        assert_eq!(projection.canonical_bytes.len(), 3673);
        let value: serde_json::Value = serde_json::from_slice(&projection.canonical_bytes).unwrap();
        assert_eq!(
            value["assets"]["guard_prefix"]["sha256"],
            pins().root_prefix_digest
        );
        assert_eq!(
            value["runtime"]["private_cell"]["runtime_tree_digest"],
            pins().runtime_tree_digest
        );
        assert_eq!(projection.file_bytes.last(), Some(&b'\n'));
        assert_eq!(
            projection.file_bytes.len(),
            projection.canonical_bytes.len() + 1
        );
    }

    #[test]
    fn wrong_template_or_candidate_identity_refuses() {
        let raw = fixture(7);
        assert_eq!(
            project_candidate_config_ineligible(&raw, &"0".repeat(64), &pins()),
            Err(CandidateConfigProjectionError::InvalidTemplate)
        );
        let mut wrong = pins();
        wrong.source_sha = "main";
        assert_eq!(
            project_candidate_config_ineligible(
                &raw,
                "580c94be23f58345bf7c59eb11239ae9bd21347b70fadb6c19f243b7f7a3f1e8",
                &wrong
            ),
            Err(CandidateConfigProjectionError::InvalidPins)
        );
        let mut wrong = pins();
        wrong.runtime_tree_digest = "missing";
        assert_eq!(
            project_candidate_config_ineligible(
                &raw,
                "580c94be23f58345bf7c59eb11239ae9bd21347b70fadb6c19f243b7f7a3f1e8",
                &wrong
            ),
            Err(CandidateConfigProjectionError::InvalidPins)
        );
        let mut wrong = pins();
        wrong.runtime_tree_digest =
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        assert_eq!(
            project_candidate_config_ineligible(
                &raw,
                "580c94be23f58345bf7c59eb11239ae9bd21347b70fadb6c19f243b7f7a3f1e8",
                &wrong
            ),
            Err(CandidateConfigProjectionError::InvalidPins)
        );
        assert_eq!(
            project_candidate_config_ineligible(
                &fixture(6),
                "066f727658e715027e21c2ec2459ab5bfb360b21d162f3bf87ba61a2f4ec43c4",
                &pins()
            ),
            Err(CandidateConfigProjectionError::UnsupportedTemplate)
        );
    }

    #[test]
    fn shadow_projection_uses_only_fixed_job_path_and_distinct_id() {
        let projection = project_shadow_candidate_config_ineligible(
            &fixture(7),
            "580c94be23f58345bf7c59eb11239ae9bd21347b70fadb6c19f243b7f7a3f1e8",
            &pins(),
            "1234567890abcdef",
        )
        .unwrap();
        assert_eq!(projection.canonical_bytes.len(), 3651);
        assert_eq!(
            projection.digest,
            "71e8bc8f042afc3970cee97eb1e57a1ea218dc43857dea4683708761d591ab95"
        );
        let config: serde_json::Value =
            serde_json::from_slice(&projection.canonical_bytes).unwrap();
        assert_eq!(
            config["id"],
            "rust-shadow-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-1234567890abcdef"
        );
        assert_eq!(
            config["assets"]["guard_prefix"]["path"],
            "hol-gauntlet/rust-shadow-candidates/1234567890abcdef/prefix"
        );
        assert_eq!(
            project_shadow_candidate_config_ineligible(
                &fixture(7),
                "580c94be23f58345bf7c59eb11239ae9bd21347b70fadb6c19f243b7f7a3f1e8",
                &pins(),
                "../escape"
            ),
            Err(CandidateConfigProjectionError::InvalidPins)
        );
    }

    #[test]
    fn source_matched_private_cell_projection_uses_distinct_fixed_id_and_path() {
        let digest = "e".repeat(64);
        let projection = project_shadow_candidate_config_with_private_cell_ineligible(
            &fixture(7),
            "580c94be23f58345bf7c59eb11239ae9bd21347b70fadb6c19f243b7f7a3f1e8",
            &pins(),
            "1234567890abcdef",
            &digest,
        )
        .unwrap();
        let config: serde_json::Value =
            serde_json::from_slice(&projection.canonical_bytes).unwrap();
        assert_eq!(
            config["id"],
            "rust-shadow-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-1234567890abcdef-eeeeeeeeeeeeeeee"
        );
        assert_eq!(
            config["assets"]["private_cell"]["path"],
            "hol-gauntlet/rust-shadow-candidates/1234567890abcdef/cell-artifacts"
        );
        assert_eq!(config["assets"]["private_cell"]["sha256"], digest);
        assert_eq!(projection.file_bytes.last(), Some(&b'\n'));
    }
}
