//! Exact build-program wire records.

use super::*;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawVariant {
    pub(super) variant_id: String,
    pub(super) matcher: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawRule {
    pub(super) rule_id: String,
    pub(super) rule_version: String,
    pub(super) extension_id: String,
    pub(super) permission_id: String,
    pub(super) baseline_floor: String,
    pub(super) configurable: bool,
    pub(super) default_mode: String,
    pub(super) severity: String,
    pub(super) risk_classes: Vec<String>,
    pub(super) action_classes: Vec<String>,
    pub(super) matcher: Option<String>,
    pub(super) safe_variants: Vec<RawVariant>,
    pub(super) candidate_executables: Vec<String>,
    pub(super) candidate_keywords: Vec<String>,
    pub(super) candidate_unindexed: bool,
}

// The three serialized fields are in canonical lexical order. Nested children
// and JSON objects also retain sorted keys, so node hashes need no cloned JSON
// tree. Every packaged node hash is checked against the Python compiler output.
#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawNode {
    pub(super) children: BTreeMap<String, Value>,
    pub(super) config: Value,
    pub(super) op: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawCoverageVariant {
    pub(super) variant_id: String,
    pub(super) matcher_contract_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawCoverage {
    pub(super) rule_id: String,
    pub(super) matcher_contract_digest: String,
    pub(super) translation: String,
    pub(super) native_execution: String,
    pub(super) safe_variants: Vec<RawCoverageVariant>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawProgram {
    pub(super) schema: String,
    pub(super) compiler_version: u16,
    pub(super) semantic_profile: String,
    pub(super) authoring_semantics_digest: String,
    pub(super) catalog_digest: String,
    pub(super) trust_digest: String,
    pub(super) program_digest: String,
    pub(super) extensions: Vec<ProgramExtension>,
    pub(super) rules: Vec<RawRule>,
    pub(super) nodes: BTreeMap<String, RawNode>,
    pub(super) coverage: Vec<RawCoverage>,
    pub(super) matcher_families: BTreeMap<String, usize>,
}
