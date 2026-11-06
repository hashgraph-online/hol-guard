//! Rust port of `runtime/linux_artifact_supply_chain.py` (:287) — signed
//! supply-chain acceptance for privileged Linux Guard artifacts. Manifest
//! provenance is Ed25519-signed (`ring::signature::ED25519`); manifest and
//! receipt integrity use SHA-256 over canonical JSON.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fmt;
use std::sync::LazyLock;

use guard_contracts::write_canonical_json;
use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// `_SHA256_PATTERN` (:12) — `re.compile(r"[0-9a-f]{64}\Z")`.
static SHA256_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{64}$").expect("SHA256_PATTERN"));

/// `_SIGNATURE_PATTERN` (:13) — `re.compile(r"[0-9a-f]{128}\Z")`.
static SIGNATURE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{128}$").expect("SIGNATURE_PATTERN"));

/// `_IDENTIFIER_PATTERN` (:14).
static IDENTIFIER_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$").expect("IDENTIFIER_PATTERN")
});

/// `_SCHEMA_VERSION` (:15).
const SCHEMA_VERSION: i64 = 1;

/// `_SIGNATURE_DOMAIN` (:16).
const SIGNATURE_DOMAIN: &[u8] = b"hol-guard-linux-artifact-manifest-v1\0";

/// `LinuxArtifactSupplyChainError(ValueError)` (:19).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxArtifactSupplyChainError(pub String);

impl fmt::Display for LinuxArtifactSupplyChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LinuxArtifactSupplyChainError {}

pub type LinuxArtifactSupplyChainResult<T> = Result<T, LinuxArtifactSupplyChainError>;

/// `LinuxArtifactSupplyChainManifest` (:24) — frozen slots dataclass.
/// `try_new` enforces `__post_init__` (:31); fields are `pub` for the
/// frozen-value semantics, but construction goes through `try_new`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinuxArtifactSupplyChainManifest {
    pub schema_version: i64,
    pub component_id: String,
    pub version: String,
    pub release_sequence: i64,
    pub artifact_digest: String,
    pub sbom_digest: String,
    pub source_digest: String,
    pub builder_id: String,
    pub key_id: String,
    pub signature: String,
}

impl LinuxArtifactSupplyChainManifest {
    /// `__post_init__` (:31).
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        schema_version: i64,
        component_id: String,
        version: String,
        release_sequence: i64,
        artifact_digest: String,
        sbom_digest: String,
        source_digest: String,
        builder_id: String,
        key_id: String,
        signature: String,
    ) -> LinuxArtifactSupplyChainResult<Self> {
        if schema_version != SCHEMA_VERSION {
            return Err(LinuxArtifactSupplyChainError(
                "unsupported manifest schema".to_string(),
            ));
        }
        if release_sequence < 0 {
            return Err(LinuxArtifactSupplyChainError(
                "invalid release sequence".to_string(),
            ));
        }
        for (label, value) in [
            ("component_id", &component_id),
            ("builder_id", &builder_id),
            ("key_id", &key_id),
        ] {
            if !IDENTIFIER_PATTERN.is_match(value) {
                return Err(LinuxArtifactSupplyChainError(format!("invalid {label}")));
            }
        }
        if version.is_empty() || version != version.trim() || version.len() > 128 {
            return Err(LinuxArtifactSupplyChainError("invalid version".to_string()));
        }
        for (label, value) in [
            ("artifact_digest", &artifact_digest),
            ("sbom_digest", &sbom_digest),
            ("source_digest", &source_digest),
        ] {
            if !SHA256_PATTERN.is_match(value) {
                return Err(LinuxArtifactSupplyChainError(format!("invalid {label}")));
            }
        }
        if !SIGNATURE_PATTERN.is_match(&signature) {
            return Err(LinuxArtifactSupplyChainError(
                "invalid signature".to_string(),
            ));
        }
        Ok(Self {
            schema_version,
            component_id,
            version,
            release_sequence,
            artifact_digest,
            sbom_digest,
            source_digest,
            builder_id,
            key_id,
            signature,
        })
    }

    /// `digest` (:66) — SHA-256 of canonical `asdict(self)`.
    pub fn digest(&self) -> String {
        sha256(&canonical_json(&self.as_dict()))
    }

    /// `asdict(self)` — ordered field map for canonical JSON.
    pub fn as_dict(&self) -> Map<String, Value> {
        let mut out = Map::new();
        out.insert("artifact_digest".to_string(), json!(self.artifact_digest));
        out.insert("builder_id".to_string(), json!(self.builder_id));
        out.insert("component_id".to_string(), json!(self.component_id));
        out.insert("key_id".to_string(), json!(self.key_id));
        out.insert("release_sequence".to_string(), json!(self.release_sequence));
        out.insert("sbom_digest".to_string(), json!(self.sbom_digest));
        out.insert("schema_version".to_string(), json!(self.schema_version));
        out.insert("signature".to_string(), json!(self.signature));
        out.insert("source_digest".to_string(), json!(self.source_digest));
        out.insert("version".to_string(), json!(self.version));
        out
    }
}

/// `LinuxArtifactSupplyChainReceipt` (:73) — frozen slots dataclass; the
/// constructor `try_new` enforces `validate_provenance` (`__post_init__`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxArtifactSupplyChainReceipt {
    pub component_id: String,
    pub version: String,
    pub release_sequence: i64,
    pub artifact_digest: String,
    pub sbom_digest: String,
    pub source_digest: String,
    pub builder_id: String,
    pub key_id: String,
    pub manifest_digest: String,
    pub signer_public_key: String,
    pub manifest: LinuxArtifactSupplyChainManifest,
}

impl LinuxArtifactSupplyChainReceipt {
    /// `__post_init__` (:87) → `validate_provenance`.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        component_id: String,
        version: String,
        release_sequence: i64,
        artifact_digest: String,
        sbom_digest: String,
        source_digest: String,
        builder_id: String,
        key_id: String,
        manifest_digest: String,
        signer_public_key: String,
        manifest: LinuxArtifactSupplyChainManifest,
    ) -> LinuxArtifactSupplyChainResult<Self> {
        let receipt = Self {
            component_id,
            version,
            release_sequence,
            artifact_digest,
            sbom_digest,
            source_digest,
            builder_id,
            key_id,
            manifest_digest,
            signer_public_key,
            manifest,
        };
        receipt.validate_provenance()?;
        Ok(receipt)
    }

    /// `validate_provenance` (:90) — manifest binding + signature check.
    /// The Ed25519 verification seam is `verify_manifest_signature` so tests
    /// can substitute; the default path uses `ring::signature::ED25519`.
    pub fn validate_provenance(&self) -> LinuxArtifactSupplyChainResult<()> {
        self.validate_provenance_with(&RingEd25519)
    }

    pub fn validate_provenance_with(
        &self,
        verifier: &dyn Ed25519Verify,
    ) -> LinuxArtifactSupplyChainResult<()> {
        let manifest = &self.manifest;
        if self.component_id != manifest.component_id
            || self.version != manifest.version
            || self.release_sequence != manifest.release_sequence
            || self.artifact_digest != manifest.artifact_digest
            || self.sbom_digest != manifest.sbom_digest
            || self.source_digest != manifest.source_digest
            || self.builder_id != manifest.builder_id
            || self.key_id != manifest.key_id
            || self.manifest_digest != manifest.digest()
        {
            return Err(LinuxArtifactSupplyChainError(
                "receipt provenance is invalid".to_string(),
            ));
        }
        let public_key = hex::decode(&self.signer_public_key).map_err(|_| {
            LinuxArtifactSupplyChainError("receipt provenance is invalid".to_string())
        })?;
        let signature = hex::decode(&manifest.signature).map_err(|_| {
            LinuxArtifactSupplyChainError("receipt provenance is invalid".to_string())
        })?;
        verifier
            .verify(&public_key, &signature_payload(manifest), &signature)
            .map_err(|_| LinuxArtifactSupplyChainError("receipt provenance is invalid".to_string()))
    }
}

/// Ed25519 verify seam — `cryptography Ed25519PublicKey.verify`.
pub trait Ed25519Verify {
    fn verify(&self, public_key: &[u8], payload: &[u8], signature: &[u8]) -> Result<(), String>;
}

/// Default Ed25519 verifier via `ring::signature::ED25519`.
pub struct RingEd25519;

impl Ed25519Verify for RingEd25519 {
    fn verify(&self, public_key: &[u8], payload: &[u8], signature: &[u8]) -> Result<(), String> {
        let key = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key);
        key.verify(payload, signature)
            .map_err(|_| "invalid signature".to_string())
    }
}

/// Ed25519 sign seam — `cryptography Ed25519PrivateKey.sign`.
pub trait Ed25519Sign {
    fn sign(&self, payload: &[u8]) -> Vec<u8>;
}

/// `create_linux_artifact_supply_chain_manifest` (:137).
#[allow(clippy::too_many_arguments)]
pub fn create_linux_artifact_supply_chain_manifest(
    component_id: &str,
    version: &str,
    release_sequence: i64,
    artifact: &[u8],
    sbom: &[u8],
    source_digest: &str,
    builder_id: &str,
    key_id: &str,
    signing_key: &dyn Ed25519Sign,
) -> LinuxArtifactSupplyChainManifest {
    let unsigned = LinuxArtifactSupplyChainManifest::try_new(
        SCHEMA_VERSION,
        component_id.to_string(),
        version.to_string(),
        release_sequence,
        sha256(artifact),
        sha256(sbom),
        source_digest.to_string(),
        builder_id.to_string(),
        key_id.to_string(),
        "0".repeat(128),
    )
    .expect("create_linux_artifact_supply_chain_manifest inputs must validate");
    let signature = hex::encode(signing_key.sign(&signature_payload(&unsigned)));
    LinuxArtifactSupplyChainManifest {
        signature,
        ..unsigned
    }
}

/// `verify_linux_artifact_supply_chain` (:166). Returns a validated receipt.
#[allow(clippy::too_many_arguments)]
pub fn verify_linux_artifact_supply_chain(
    manifest: &LinuxArtifactSupplyChainManifest,
    artifact: &[u8],
    sbom: &[u8],
    expected_component_id: &str,
    expected_version: &str,
    expected_release_sequence: i64,
    expected_source_digest: &str,
    trusted_builder_ids: &BTreeSet<String>,
    trusted_public_keys: &HashMap<String, String>,
    revoked_key_ids: Option<&BTreeSet<String>>,
) -> LinuxArtifactSupplyChainResult<LinuxArtifactSupplyChainReceipt> {
    verify_linux_artifact_supply_chain_with(
        manifest,
        artifact,
        sbom,
        expected_component_id,
        expected_version,
        expected_release_sequence,
        expected_source_digest,
        trusted_builder_ids,
        trusted_public_keys,
        revoked_key_ids,
        &RingEd25519,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn verify_linux_artifact_supply_chain_with(
    manifest: &LinuxArtifactSupplyChainManifest,
    artifact: &[u8],
    sbom: &[u8],
    expected_component_id: &str,
    expected_version: &str,
    expected_release_sequence: i64,
    expected_source_digest: &str,
    trusted_builder_ids: &BTreeSet<String>,
    trusted_public_keys: &HashMap<String, String>,
    revoked_key_ids: Option<&BTreeSet<String>>,
    verifier: &dyn Ed25519Verify,
) -> LinuxArtifactSupplyChainResult<LinuxArtifactSupplyChainReceipt> {
    let revoked_keys: BTreeSet<&String> = revoked_key_ids
        .map(|s| s.iter().collect())
        .unwrap_or_default();
    if manifest.component_id != expected_component_id {
        return Err(LinuxArtifactSupplyChainError(
            "component identity mismatch".to_string(),
        ));
    }
    if manifest.version != expected_version {
        return Err(LinuxArtifactSupplyChainError(
            "artifact version mismatch".to_string(),
        ));
    }
    if manifest.release_sequence != expected_release_sequence {
        return Err(LinuxArtifactSupplyChainError(
            "artifact release sequence mismatch".to_string(),
        ));
    }
    if manifest.source_digest != expected_source_digest {
        return Err(LinuxArtifactSupplyChainError(
            "source digest mismatch".to_string(),
        ));
    }
    if !trusted_builder_ids.contains(&manifest.builder_id) {
        return Err(LinuxArtifactSupplyChainError(
            "artifact builder is not trusted".to_string(),
        ));
    }
    if revoked_keys.contains(&manifest.key_id) {
        return Err(LinuxArtifactSupplyChainError(
            "manifest signer is revoked".to_string(),
        ));
    }
    let Some(public_key_hex) = trusted_public_keys.get(&manifest.key_id) else {
        return Err(LinuxArtifactSupplyChainError(
            "manifest signer is not trusted".to_string(),
        ));
    };
    if manifest.artifact_digest != sha256(artifact) {
        return Err(LinuxArtifactSupplyChainError(
            "artifact digest mismatch".to_string(),
        ));
    }
    if manifest.sbom_digest != sha256(sbom) {
        return Err(LinuxArtifactSupplyChainError(
            "SBOM digest mismatch".to_string(),
        ));
    }
    let public_key = hex::decode(public_key_hex)
        .map_err(|_| LinuxArtifactSupplyChainError("manifest signature is invalid".to_string()))?;
    let signature = hex::decode(&manifest.signature)
        .map_err(|_| LinuxArtifactSupplyChainError("manifest signature is invalid".to_string()))?;
    verifier
        .verify(&public_key, &signature_payload(manifest), &signature)
        .map_err(|_| LinuxArtifactSupplyChainError("manifest signature is invalid".to_string()))?;
    LinuxArtifactSupplyChainReceipt::try_new(
        manifest.component_id.clone(),
        manifest.version.clone(),
        manifest.release_sequence,
        manifest.artifact_digest.clone(),
        manifest.sbom_digest.clone(),
        manifest.source_digest.clone(),
        manifest.builder_id.clone(),
        manifest.key_id.clone(),
        manifest.digest(),
        public_key_hex.clone(),
        manifest.clone(),
    )
}

/// `validate_linux_artifact_supply_chain_receipt` (:216) —
/// `receipt.validate_provenance()`.
pub fn validate_linux_artifact_supply_chain_receipt(
    receipt: &LinuxArtifactSupplyChainReceipt,
) -> LinuxArtifactSupplyChainResult<()> {
    receipt.validate_provenance()
}

/// `revalidate_linux_artifact_supply_chain_receipt` (:223) — verify
/// provenance plus current activation-time trust and revocation.
pub fn revalidate_linux_artifact_supply_chain_receipt(
    receipt: &LinuxArtifactSupplyChainReceipt,
    artifact_digest: &str,
    trusted_builder_ids: &BTreeSet<String>,
    trusted_public_keys: &HashMap<String, String>,
    revoked_key_ids: Option<&BTreeSet<String>>,
) -> LinuxArtifactSupplyChainResult<()> {
    revalidate_linux_artifact_supply_chain_receipt_with(
        receipt,
        artifact_digest,
        trusted_builder_ids,
        trusted_public_keys,
        revoked_key_ids,
        &RingEd25519,
    )
}

pub fn revalidate_linux_artifact_supply_chain_receipt_with(
    receipt: &LinuxArtifactSupplyChainReceipt,
    artifact_digest: &str,
    trusted_builder_ids: &BTreeSet<String>,
    trusted_public_keys: &HashMap<String, String>,
    revoked_key_ids: Option<&BTreeSet<String>>,
    verifier: &dyn Ed25519Verify,
) -> LinuxArtifactSupplyChainResult<()> {
    validate_linux_artifact_supply_chain_receipt(receipt)?;
    let manifest = &receipt.manifest;
    let revoked_keys: BTreeSet<&String> = revoked_key_ids
        .map(|s| s.iter().collect())
        .unwrap_or_default();
    if !trusted_builder_ids.contains(&manifest.builder_id) {
        return Err(LinuxArtifactSupplyChainError(
            "artifact builder is not trusted".to_string(),
        ));
    }
    if revoked_keys.contains(&manifest.key_id) {
        return Err(LinuxArtifactSupplyChainError(
            "manifest signer is revoked".to_string(),
        ));
    }
    let Some(public_key_hex) = trusted_public_keys.get(&manifest.key_id) else {
        return Err(LinuxArtifactSupplyChainError(
            "manifest signer is not trusted".to_string(),
        ));
    };
    if manifest.artifact_digest != artifact_digest {
        return Err(LinuxArtifactSupplyChainError(
            "artifact digest mismatch".to_string(),
        ));
    }
    if receipt.component_id != manifest.component_id
        || receipt.version != manifest.version
        || receipt.release_sequence != manifest.release_sequence
        || receipt.artifact_digest != manifest.artifact_digest
        || receipt.sbom_digest != manifest.sbom_digest
        || receipt.source_digest != manifest.source_digest
        || receipt.builder_id != manifest.builder_id
        || receipt.key_id != manifest.key_id
        || receipt.manifest_digest != manifest.digest()
    {
        return Err(LinuxArtifactSupplyChainError(
            "receipt manifest binding is invalid".to_string(),
        ));
    }
    let public_key = hex::decode(public_key_hex)
        .map_err(|_| LinuxArtifactSupplyChainError("manifest signature is invalid".to_string()))?;
    let signature = hex::decode(&manifest.signature)
        .map_err(|_| LinuxArtifactSupplyChainError("manifest signature is invalid".to_string()))?;
    verifier
        .verify(&public_key, &signature_payload(manifest), &signature)
        .map_err(|_| LinuxArtifactSupplyChainError("manifest signature is invalid".to_string()))
}

/// `_signature_payload` (:265) — `DOMAIN + canonical_json(asdict minus signature)`.
fn signature_payload(manifest: &LinuxArtifactSupplyChainManifest) -> Vec<u8> {
    let mut fields = manifest.as_dict();
    fields.remove("signature");
    let mut out = SIGNATURE_DOMAIN.to_vec();
    out.extend_from_slice(&canonical_json(&fields));
    out
}

/// `_canonical_json` (:271) — `json.dumps(sort_keys, separators, ensure_ascii)`.
fn canonical_json(value: &Map<String, Value>) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = write_canonical_json(&Value::Object(value.clone()), &mut out);
    out
}

/// `_sha256` (:275).
fn sha256(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}
