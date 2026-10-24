//! Read-only public bundle verifier. Candidate bytes never choose code or trust anchors.

mod bridge_frames;
mod campaign;
mod campaign_gate;
mod crypto;
mod episode_score;
mod io;
mod package_version;
mod payload;
mod public_files;
mod runner_inputs;
mod tree_inventory;
mod worker_receipt;

pub use bridge_frames::FrameCodec;
pub use campaign_gate::evaluate_audited_campaign;
pub use episode_score::evaluate_audited_episode;
pub use package_version::{valid_package_version, verify_installed_version_metadata};
pub use runner_inputs::{
    verify_runner_file_assets, verify_runner_inputs, verify_runner_inputs_from_paths,
    ReservationTotals, VerifiedRunnerInputs,
};
pub use tree_inventory::{inventory_tree, TreeInventory, TreeKind};
pub use worker_receipt::{verify_python_worker_terminal, PythonWorkerTerminal};

use crate::campaign::verify_campaign;
use crate::crypto::{decode_base64, decode_hex, is_sha256, sha256, verify_ed25519};
use crate::io::{valid_bundle_path, BundleReader};
use crate::payload::{
    exact_keys, public_safe, validate_anchors, validate_identities, validate_payload, KINDS,
};
use gauntlet_contracts::canonicalize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;
const MAX_FILES: usize = 2048;

#[derive(Debug)]
pub enum EvidenceError {
    Invalid(&'static str),
    Io(String),
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => f.write_str(message),
            Self::Io(message) => write!(f, "bundle I/O error: {message}"),
        }
    }
}

impl std::error::Error for EvidenceError {}

pub type Result<T> = std::result::Result<T, EvidenceError>;

pub(crate) fn canonical_value(value: &Value) -> Result<Vec<u8>> {
    canonicalize(value.to_string().as_bytes())
        .map_err(|_| EvidenceError::Invalid("invalid canonical evidence value"))
}

fn decode_json(raw: &[u8]) -> Result<Value> {
    let canonical =
        canonicalize(raw).map_err(|_| EvidenceError::Invalid("invalid bounded bundle JSON"))?;
    let value = serde_json::from_slice(&canonical)
        .map_err(|_| EvidenceError::Invalid("invalid bounded bundle JSON"))?;
    public_safe(&value)?;
    Ok(value)
}

/// Caller-owned pins. These must come from outside the candidate bundle.
#[derive(Debug, Clone)]
pub struct ExternalPins {
    pub controller_public_key: Vec<u8>,
    pub manifest_sha256: String,
    pub source_identities: Value,
    pub effect_anchors: Value,
}

impl ExternalPins {
    pub fn from_json(raw: &[u8]) -> Result<Self> {
        let value = decode_json(raw)?;
        if !exact_keys(
            &value,
            &[
                "controller_public_key",
                "manifest_sha256",
                "source_identities",
                "effect_anchors",
            ],
        ) {
            return Err(EvidenceError::Invalid("invalid independent pin fields"));
        }
        let key = value["controller_public_key"]
            .as_str()
            .ok_or(EvidenceError::Invalid("controller public key missing"))?;
        let digest = value["manifest_sha256"]
            .as_str()
            .filter(|value| is_sha256(value))
            .ok_or(EvidenceError::Invalid("manifest SHA-256 pin missing"))?;
        validate_identities(&value["source_identities"])?;
        validate_anchors(&value["effect_anchors"])?;
        Ok(Self {
            controller_public_key: decode_base64(key, 32)?,
            manifest_sha256: digest.to_owned(),
            source_identities: value["source_identities"].clone(),
            effect_anchors: value["effect_anchors"].clone(),
        })
    }
}

/// Open a public pin file through descriptor-relative no-symlink traversal.
pub fn read_external_pins(path: &Path) -> Result<ExternalPins> {
    let parent = path.parent().ok_or(EvidenceError::Invalid(
        "external pins need an absolute parent",
    ))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(EvidenceError::Invalid("external pin filename is invalid"))?;
    let reader = BundleReader::open(parent)?;
    let raw = reader.read_file(name)?;
    ExternalPins::from_json(&raw)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub files: usize,
    pub scheduled_episodes: usize,
    pub recorded_episodes: usize,
    pub missing_episodes: Vec<String>,
}

impl VerifyReport {
    pub fn to_json(&self) -> Value {
        json!({
            "integrity": "valid",
            "completeness": if self.missing_episodes.is_empty() { "complete" } else { "incomplete" },
            "profile": "gauntlet-workflow-public-bundle.v1",
            "files": self.files,
            "scheduled_episodes": self.scheduled_episodes,
            "recorded_episodes": self.recorded_episodes,
            "missing_episodes": self.missing_episodes,
            "qualification_eligible": false,
            "status": "exploratory",
            "reason": "requires an independently reviewed eligible trusted consumer"
        })
    }
}

fn manifest_files(record: &Value) -> Result<BTreeSet<String>> {
    if !exact_keys(
        record,
        &[
            "schema_version",
            "profile",
            "files",
            "campaign_digest",
            "inventory_digest",
            "scheduled_episodes",
            "source_identities",
            "effect_anchors",
        ],
    ) || record["schema_version"] != "1.0"
        || record["profile"] != "gauntlet-workflow-public-bundle.v1"
    {
        return Err(EvidenceError::Invalid("invalid signed bundle manifest"));
    }
    validate_identities(&record["source_identities"])?;
    validate_anchors(&record["effect_anchors"])?;
    for field in ["campaign_digest", "inventory_digest"] {
        if !record[field].as_str().is_some_and(is_sha256) {
            return Err(EvidenceError::Invalid("invalid campaign anchor digest"));
        }
    }
    if record["scheduled_episodes"]
        .as_u64()
        .filter(|count| *count <= 100_000)
        .is_none()
    {
        return Err(EvidenceError::Invalid("invalid scheduled inventory count"));
    }
    let files = record["files"]
        .as_array()
        .filter(|files| !files.is_empty() && files.len() < MAX_FILES)
        .ok_or(EvidenceError::Invalid("invalid file manifest inventory"))?;
    let mut names = BTreeSet::new();
    for item in files {
        if !exact_keys(
            item,
            &["path", "digest", "bytes", "records", "kind", "stream_id"],
        ) {
            return Err(EvidenceError::Invalid("invalid file manifest entry"));
        }
        let path = item["path"]
            .as_str()
            .filter(|value| valid_bundle_path(value) && *value != "manifest.json")
            .ok_or(EvidenceError::Invalid("unsafe or reserved manifest path"))?;
        if !names.insert(path.to_owned()) {
            return Err(EvidenceError::Invalid("duplicate manifest path"));
        }
        if !item["digest"].as_str().is_some_and(is_sha256)
            || !item["kind"]
                .as_str()
                .is_some_and(|kind| KINDS.contains(&kind))
            || (!item["stream_id"].is_null() && !item["stream_id"].is_string())
            || item["bytes"]
                .as_u64()
                .filter(|bytes| *bytes <= MAX_RECORD_BYTES as u64)
                .is_none()
            || item["records"]
                .as_u64()
                .filter(|records| *records <= 100_000)
                .is_none()
        {
            return Err(EvidenceError::Invalid("malformed file manifest metadata"));
        }
    }
    for name in &names {
        let mut prefix = String::new();
        for part in name.split('/').take(name.split('/').count() - 1) {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            if names.contains(&prefix) {
                return Err(EvidenceError::Invalid("file path conflicts with directory"));
            }
        }
    }
    Ok(names)
}

/// Verify one immutable public bundle against externally supplied custody pins.
/// Successful output is exploratory and never by itself makes a PR merge-eligible.
pub fn verify_bundle(directory: &Path, pins: &ExternalPins) -> Result<VerifyReport> {
    validate_identities(&pins.source_identities)?;
    let anchors = validate_anchors(&pins.effect_anchors)?;
    if pins.controller_public_key.len() != 32 || !is_sha256(&pins.manifest_sha256) {
        return Err(EvidenceError::Invalid("invalid external controller pin"));
    }
    let reader = BundleReader::open(directory)?;
    let actual_files = reader.list_files()?;
    let manifest_bytes = reader.read_file("manifest.json")?;
    if sha256(&manifest_bytes) != pins.manifest_sha256 {
        return Err(EvidenceError::Invalid(
            "independent manifest digest mismatch",
        ));
    }
    let envelope = decode_json(&manifest_bytes)?;
    if !exact_keys(&envelope, &["record", "signature"]) {
        return Err(EvidenceError::Invalid("invalid signed manifest envelope"));
    }
    let record = &envelope["record"];
    let listed = manifest_files(record)?;
    let signature = envelope["signature"]
        .as_str()
        .ok_or(EvidenceError::Invalid("manifest signature missing"))?;
    verify_ed25519(
        &pins.controller_public_key,
        &canonical_value(record)?,
        &decode_hex(signature, 64)?,
    )?;
    if record["source_identities"] != pins.source_identities
        || record["effect_anchors"] != pins.effect_anchors
    {
        return Err(EvidenceError::Invalid(
            "source or effect anchors differ from external pins",
        ));
    }
    let mut expected_files = listed.clone();
    expected_files.insert("manifest.json".to_owned());
    if actual_files != expected_files {
        return Err(EvidenceError::Invalid("missing or unlisted bundle files"));
    }
    let mut total = manifest_bytes.len();
    let mut streams = BTreeSet::new();
    let mut campaigns = Vec::new();
    let mut episodes = Vec::new();
    let mut episode_ids = BTreeSet::new();
    let entries = record["files"].as_array().expect("manifest validated");
    for item in entries {
        let path = item["path"].as_str().expect("manifest validated");
        let raw = reader.read_file(path)?;
        total += raw.len();
        if total > MAX_BUNDLE_BYTES
            || item["bytes"].as_u64() != Some(raw.len() as u64)
            || item["digest"] != sha256(&raw)
        {
            return Err(EvidenceError::Invalid(
                "bundle file hash, size or total budget mismatch",
            ));
        }
        let value = decode_json(&raw)?;
        let payload = validate_payload(&value, &anchors)?;
        if item["records"].as_u64() != Some(payload.records.len() as u64)
            || item["kind"] != payload.kind
            || item["stream_id"].as_str() != payload.stream_id
        {
            return Err(EvidenceError::Invalid(
                "file kind, stream or record count mismatch",
            ));
        }
        if payload.kind == "world-receipts" {
            let stream = payload.stream_id.expect("validated effect stream");
            if !streams.insert(stream.to_owned()) {
                return Err(EvidenceError::Invalid("duplicate effect stream"));
            }
        }
        if payload.kind == "campaign" {
            campaigns.extend(payload.records.iter().cloned());
        }
        if payload.kind == "episode" {
            for episode in payload.records {
                let id = episode["id"]
                    .as_str()
                    .ok_or(EvidenceError::Invalid("episode ID missing"))?;
                if !episode_ids.insert(id.to_owned()) {
                    return Err(EvidenceError::Invalid("duplicate episode evidence"));
                }
                episodes.push(episode.clone());
            }
        }
    }
    if streams != anchors.keys().cloned().collect() || campaigns.len() != 1 {
        return Err(EvidenceError::Invalid(
            "missing effect stream or frozen campaign",
        ));
    }
    let campaign = &campaigns[0];
    verify_campaign(campaign)?;
    let inventory = campaign["inventory"]
        .as_array()
        .expect("campaign validated");
    if record["campaign_digest"] != sha256(&canonical_value(campaign)?)
        || record["inventory_digest"] != campaign["inventory_digest"]
        || record["scheduled_episodes"].as_u64() != Some(inventory.len() as u64)
        || campaign["frozen_inputs"] != pins.source_identities
    {
        return Err(EvidenceError::Invalid(
            "campaign inventory or source anchor mismatch",
        ));
    }
    let assigned: BTreeMap<_, _> = inventory
        .iter()
        .filter_map(|row| row["id"].as_str().map(|id| (id, row)))
        .collect();
    for episode in &episodes {
        let id = episode["id"].as_str().unwrap_or("");
        let Some(row) = assigned.get(id) else {
            return Err(EvidenceError::Invalid("unscheduled episode evidence"));
        };
        if episode["campaign_id"] != campaign["id"]
            || [
                "workflow_id",
                "variant",
                "condition",
                "repetition",
                "snapshot_id",
            ]
            .iter()
            .any(|field| episode[*field] != row[*field])
        {
            return Err(EvidenceError::Invalid(
                "episode differs from frozen schedule",
            ));
        }
    }
    let missing_episodes = assigned
        .keys()
        .filter(|id| !episode_ids.contains(**id))
        .map(|id| (*id).to_owned())
        .collect();
    Ok(VerifyReport {
        files: actual_files.len(),
        scheduled_episodes: assigned.len(),
        recorded_episodes: episode_ids.len(),
        missing_episodes,
    })
}
