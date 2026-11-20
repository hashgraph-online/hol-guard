use crate::ReleaseError;
use serde::{Deserialize, Serialize};

pub const CATALOG_SCHEMA: &str = "guard-cigar-release-catalog.v1";
pub const ENVELOPE_SCHEMA: &str = "guard-cigar-signed-catalog.v1";
pub const GUARD_CONTRACT: u32 = 1;
pub const MAX_CATALOG_BYTES: usize = 512 * 1024;
pub const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;
pub const MAX_BUILDS: usize = 128;

/// Artifact identity is independent of SDK version. Same-version rebuilds must
/// have a new build ID and manifest binding; neither overwrites an installation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildIdentity {
    pub build_id: String,
    pub sdk_version: String,
    pub core_version: String,
    pub source_revision: String,
    pub manifest_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Stable,
    Preview,
    LocalCandidate,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Qualification {
    LocalCandidate,
    UpstreamOnly,
    GuardQualified,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    Graph,
    Sharing,
    Persistence,
    ExecutionContext,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterProfile {
    pub profile_id: String,
    pub adapter_id: String,
    pub adapter_revision: u32,
    pub guard_contract: u32,
    pub sdk_api_revision: u32,
    pub worker_protocol: String,
    pub broker_protocol: String,
    pub evidence_schema: u32,
    pub broker_storage: String,
    pub python_implementation: String,
    pub python_major: u16,
    pub python_minor: u16,
}

/// Only the named upstream repository or an authenticated offline bundle can
/// supply SDK wheels. A caller cannot inject an index URL or executable adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WheelSource {
    GithubCigarRelease {
        tag: String,
    },
    /// Exact content-addressed dependency file at files.pythonhosted.org.
    PypiFile {
        path: String,
    },
    OfflineBundle,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WheelLock {
    pub distribution: String,
    pub version: String,
    pub filename: String,
    pub sha256: String,
    pub bytes: u64,
    pub source: WheelSource,
    /// Optional only for old archived records or wheels without the header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_python: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformBuild {
    pub platform: String,
    pub worker_sha256: String,
    pub package_tree_sha256: Option<String>,
    pub wheel: Option<WheelLock>,
    pub dependencies: Vec<WheelLock>,
    pub qualification: Qualification,
    pub qualification_receipt_sha256: Option<String>,
    pub features: Vec<Feature>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBuild {
    pub identity: BuildIdentity,
    pub profile_id: String,
    pub channel: Channel,
    pub withdrawn: bool,
    pub platforms: Vec<PlatformBuild>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogDocument {
    pub schema: String,
    pub revision: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub legacy_candidate: Option<crate::LegacyCandidate>,
    pub profiles: Vec<AdapterProfile>,
    pub builds: Vec<ReleaseBuild>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interpreters: Vec<crate::InterpreterBuild>,
}

/// Installed adapters are code shipped with Guard. Catalog data can refer to
/// them but cannot add Python code or widen the interpreter/protocol boundary.
pub fn check_shipped_adapter(profile: &AdapterProfile) -> Result<(), ReleaseError> {
    if profile.guard_contract > GUARD_CONTRACT {
        return Err(ReleaseError::GuardUpdateRequired);
    }
    if profile.adapter_id != "guard-cigar-python-sdk-v1"
        || profile.adapter_revision != 1
        || profile.guard_contract != GUARD_CONTRACT
        || profile.sdk_api_revision != 1
        || profile.worker_protocol != "cigar.context-worker.v1"
        || profile.broker_protocol != "cigar.context-broker.v1"
        || profile.evidence_schema != 1
        || profile.broker_storage != "sqlite-checkpoint.v1"
        || profile.python_implementation != "cpython"
        || profile.python_major != 3
        || profile.python_minor != 14
    {
        return Err(ReleaseError::AdapterUpdateRequired);
    }
    Ok(())
}

pub(crate) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_:-".contains(&byte))
}
pub(crate) fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
pub(crate) fn platform(value: &str) -> bool {
    matches!(
        value,
        "darwin-arm64"
            | "darwin-x64"
            | "linux-x64-gnu"
            | "linux-arm64-gnu"
            | "linux-x64-musl"
            | "linux-arm64-musl"
            | "win32-x64"
    )
}
