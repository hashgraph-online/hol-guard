use super::*;

// ---------------------------------------------------------------------------
// Dependency mirrors — duck-typed `getattr` objects become `Map` payloads and
// typed dataclasses become structs, matching `local_supply_chain`'s seam
// convention.
// ---------------------------------------------------------------------------

/// `ScanOptions` mirror — only the fields consumed by the trust pipeline.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub cisco_skill_scan: String,
    pub cisco_mcp_scan: String,
    pub cisco_policy: String,
    pub ecosystem: String,
    pub extra: Map<String, Value>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            cisco_skill_scan: "auto".into(),
            cisco_mcp_scan: "auto".into(),
            cisco_policy: "balanced".into(),
            ecosystem: "auto".into(),
            extra: Map::new(),
        }
    }
}

impl ScanOptions {
    /// `_INVENTORY_TRUST_SCAN_OPTIONS` = `ScanOptions(cisco_skill_scan="off")`.
    pub fn inventory_trust_scan_options() -> Self {
        Self {
            cisco_skill_scan: "off".into(),
            ..ScanOptions::default()
        }
    }
}

/// `Severity` enum mirror — `isinstance(value, Severity)` / `value.value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// `Severity.value` — lowercase wire token.
    pub fn value(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

/// `trust_models.TrustComponentScore` mirror.
#[derive(Debug, Clone, Default)]
pub struct TrustComponentScore {
    pub key: String,
    pub score: f64,
    pub rationale: String,
    pub evidence: Vec<String>,
}

/// `trust_models.TrustAdapterScore` mirror.
#[derive(Debug, Clone, Default)]
pub struct TrustAdapterScore {
    pub adapter_id: String,
    pub label: String,
    pub weight: f64,
    pub contribution_mode: String,
    pub applicable: bool,
    pub emitted: bool,
    pub included_in_denominator: bool,
    pub score: f64,
    pub components: Vec<TrustComponentScore>,
}

/// `trust_models.TrustDomainScore` mirror.
#[derive(Debug, Clone, Default)]
pub struct TrustDomainScore {
    pub domain: String,
    pub label: String,
    pub spec_id: String,
    pub spec_version: String,
    pub spec_path: String,
    pub derived_from: Vec<String>,
    pub profile_id: String,
    pub profile_version: String,
    pub score: f64,
    pub adapters: Vec<TrustAdapterScore>,
}

/// `checks.skill_security.SkillSecurityContext` mirror — opaque payload until
/// the real port lands; the scoring seam produces/consumes it.
#[derive(Debug, Clone, Default)]
pub struct SkillSecurityContext {
    pub value: Value,
}

// ---------------------------------------------------------------------------
// Dependency seams.
// ---------------------------------------------------------------------------

/// `trust_*_scoring` + `checks.skill_security` seam.
pub trait TrustScoringApi {
    fn resolve_skill_security_context(
        &self,
        plugin_dir: &Path,
        options: &ScanOptions,
    ) -> SkillSecurityContext;
    fn build_plugin_domain(&self, plugin_dir: &Path) -> Option<TrustDomainScore>;
    fn build_skill_domain(
        &self,
        plugin_dir: &Path,
        context: &SkillSecurityContext,
    ) -> Option<TrustDomainScore>;
    fn build_mcp_domain(&self, plugin_dir: &Path) -> Option<TrustDomainScore>;
    fn build_mcp_surface_domain(
        &self,
        name: Option<&str>,
        command: Option<&str>,
        url: Option<&str>,
        transport: Option<&str>,
    ) -> Option<TrustDomainScore>;
    fn build_instruction_domain(
        &self,
        path: &Path,
        role: &str,
        item_kind: &str,
    ) -> Option<TrustDomainScore>;
}

/// `.runtime.evidence_hash` seam — `guard_evidence_hash(payload)`.
pub trait GuardEvidenceHashApi {
    fn guard_evidence_hash(&self, payload: &Map<String, Value>) -> String;
}

/// `.trust_metadata_boundary` seam.
pub trait TrustMetadataBoundaryApi {
    fn separate_untrusted_adapter_trust_metadata(
        &self,
        metadata: Map<String, Value>,
    ) -> Map<String, Value>;
}

/// Bundled seams so every public function takes a single `impl` reference.
pub struct TrustDeps<'a> {
    pub scoring: &'a dyn TrustScoringApi,
    pub evidence_hash: &'a dyn GuardEvidenceHashApi,
    pub boundary: &'a dyn TrustMetadataBoundaryApi,
}

// ---------------------------------------------------------------------------
// Constants.
// ---------------------------------------------------------------------------

/// `_LOCAL_BASELINE_ITEM_KINDS`
pub static LOCAL_BASELINE_ITEM_KINDS: &[&str] = &[
    "agent",
    "daemon_plugin",
    "hook",
    "mcp_server",
    "mcp_tool",
    "overlay",
    "plugin",
    "policy",
    "prompt_pack",
    "skill",
];

/// `_INSTRUCTION_BASELINE_ITEM_KINDS`
pub static INSTRUCTION_BASELINE_ITEM_KINDS: &[&str] = &[
    "agent",
    "daemon_plugin",
    "hook",
    "overlay",
    "policy",
    "prompt_pack",
];
