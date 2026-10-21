//! Port of `src/codex_plugin_scanner/guard/aibom_trust_metadata.py` (RTM-027).
//!
//! Attach local HCS trust domain evidence to AIBOM inventory metadata.
//!
//! TODO(deps): Python lazily resolves `.inventory_contract`
//! (`_normalize_inventory_datetime`), `..checks.skill_security`
//! (`resolve_skill_security_context`), `..trust_instruction_scoring`
//! (`build_instruction_domain`), `..trust_mcp_scoring`
//! (`build_mcp_domain`, `build_mcp_surface_domain`),
//! `..trust_plugin_scoring` (`build_plugin_domain`),
//! `..trust_skill_scoring` (`build_skill_domain`), `.runtime.evidence_hash`
//! (`guard_evidence_hash`), and `.trust_metadata_boundary`
//! (`separate_untrusted_adapter_trust_metadata`). Until those ports land, the
//! module keeps those surfaces behind the `TrustScoringApi`,
//! `GuardEvidenceHashApi`, and `TrustMetadataBoundaryApi` seams plus a local
//! mirror of the inventory-contract datetime normalizer.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

#[path = "aibom_trust_metadata/models.rs"]
mod models;
pub use models::{
    GuardEvidenceHashApi, ScanOptions, Severity, SkillSecurityContext, TrustAdapterScore,
    TrustComponentScore, TrustDeps, TrustDomainScore, TrustMetadataBoundaryApi, TrustScoringApi,
    INSTRUCTION_BASELINE_ITEM_KINDS, LOCAL_BASELINE_ITEM_KINDS,
};
#[path = "aibom_trust_metadata/values.rs"]
mod values;
pub use values::_metadata_string;
use values::{a_str, finding_str, meta_str, py_round, run_findings, run_meta};
#[path = "aibom_trust_metadata/datetime.rs"]
mod datetime;
pub use datetime::normalize_inventory_datetime;

#[path = "aibom_trust_metadata/enrichment.rs"]
mod enrichment;
pub use enrichment::{apply_local_trust_metadata, trust_resolution_from_domain};
#[path = "aibom_trust_metadata/security_payload.rs"]
mod security_payload;
use security_payload::{_cisco_local_security_payload, _local_security_for_artifact};
#[path = "aibom_trust_metadata/skill_security.rs"]
mod skill_security;
use skill_security::{
    _local_skill_security_for_artifact, _local_skill_security_label, _local_skill_security_severity,
};
#[path = "aibom_trust_metadata/mcp_security.rs"]
mod mcp_security;
use mcp_security::_local_mcp_security_for_artifact;
#[path = "aibom_trust_metadata/local_domain.rs"]
mod local_domain;
use local_domain::{
    _local_baseline_evidence_payload, _local_claim_provenance, _local_trust_domain_for_artifact,
    _merge_trust_layers, _trust_layer_from_domain, _trust_root_for_artifact,
};
#[path = "aibom_trust_metadata/cisco_matching.rs"]
mod cisco_matching;
use cisco_matching::{
    _cisco_run_target_path, _cisco_trust_layers_for_artifact, _matches_mcp_cisco_run,
    _matches_skill_cisco_run, _paths_related,
};
#[path = "aibom_trust_metadata/cisco_evidence.rs"]
mod cisco_evidence;
use cisco_evidence::{
    _cisco_analyzers_used, _cisco_layer_score, _cisco_severity_counts, _cisco_trust_layer,
};
#[path = "aibom_trust_metadata/components.rs"]
mod components;
use components::{_trust_components_from_domain, _trust_evidence_hash};

#[cfg(test)]
#[path = "aibom_trust_metadata/tests.rs"]
mod tests;

#[cfg(test)]
use cisco_matching::_cisco_run_config_path;
