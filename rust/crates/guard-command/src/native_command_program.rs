//! Immutable, content-bound command extension program. No Python or IPC runs
//! here. The only production program input is packaged with the resident.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use guard_contracts::{
    NativeCommandObservationBatchV1, NativeCommandObservationV1,
    NativeCommandPermissionObservationV1, NativeMatcherEvidenceV1, NativeSafeVariantObservationV1,
    MAX_NATIVE_COMMAND_EVIDENCE_ITEMS, MAX_NATIVE_COMMAND_OBSERVATIONS,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::command_ascii_comparison::lowercase_for_ascii_comparison;
use crate::command_common_cli_matchers::CommonCliMatcher;
use crate::command_database_matchers::DatabaseMatcher;
use crate::command_operand_matchers::OperandMatcher;
use crate::command_option_parsing::{
    argument_semantics, flags_present_in_all_option_parses_with_deadline, known_option_advance,
    matches_subcommands_conservatively_with_deadline,
};
use crate::command_specialized_matchers::SpecializedMatcher;
use crate::command_structured_matchers::StructuredMatcher;
use crate::executable_flag_contract::ExecutableFlagContract;
use crate::{CanonicalCommandV1, CommandSegmentV1};

const PROGRAM_SCHEMA: &str = "guard.native-command-program.v1";
const PROGRAM_DOMAIN: &[u8] = b"hol-guard.native-command-program.v1\0";
const NODE_DOMAIN: &[u8] = b"hol-guard.native-command-matcher.v1\0";
const MAX_PROGRAM_BYTES: usize = 4 * 1024 * 1024;
const MAX_RULES: usize = 1_024;
const MAX_NODES: usize = 16_384;
const MAX_DEPTH: usize = 32;
const MATCH_DETAIL: &str = "Matched bounded structured command constraints.";
const EMBEDDED_PROGRAM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../contracts/extensions/native-command-program.v1.json"
));

#[path = "native_command_program_admission.rs"]
mod admission;
#[path = "native_command_program_compile.rs"]
mod compile;
#[path = "native_command_program_evaluation.rs"]
mod evaluation;
#[path = "native_command_program_observations.rs"]
mod observations;
#[path = "native_command_source.rs"]
pub mod source;
#[path = "native_command_program_wire.rs"]
mod wire;
use compile::{compile_node, validate_graph};
use evaluation::Evaluation;
use wire::*;

type MatchResult = Result<Arc<[usize]>, &'static str>;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramPermission {
    pub permission_id: String,
    pub baseline_floor: String,
    pub default_enabled: bool,
    pub configurable: bool,
    pub dependencies: Vec<String>,
    pub implied_permissions: Vec<String>,
    pub rule_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramExtension {
    pub extension_id: String,
    pub version: String,
    pub source: String,
    pub required: bool,
    pub dependencies: Vec<String>,
    pub executables: Vec<String>,
    pub trust_class: String,
    pub activation: String,
    pub publisher: Value,
    pub delegated_protection: Option<String>,
    pub mcp: Option<ProgramMcp>,
    pub permissions: Vec<ProgramPermission>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramMcp {
    pub surface: String,
    pub mcp_launch: ProgramMcpLaunch,
    pub mcp_tools: Vec<ProgramMcpTool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramMcpLaunch {
    pub kind: String,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub package: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(rename = "serverNames", default)]
    pub server_names: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramMcpTool {
    pub name: String,
    pub state: String,
}

#[derive(Debug)]
pub struct ProgramRule {
    pub rule_id: String,
    pub rule_version: String,
    pub extension_index: usize,
    pub permission_id: String,
    pub baseline_floor: String,
    pub configurable: bool,
    pub default_mode: String,
    pub severity: String,
    pub risk_classes: Vec<String>,
    pub action_classes: Vec<String>,
    matcher: Option<usize>,
    variants: Vec<(String, usize)>,
}

impl ProgramRule {
    pub(crate) fn is_compatibility_attribution_only(&self) -> bool {
        self.matcher.is_none() && self.default_mode == "disabled"
    }
}

#[derive(Debug)]
struct ExecutableNode {
    contract: ExecutableFlagContract,
    paths: Vec<Vec<String>>,
    all_value_options: BTreeSet<String>,
    proof_known_flags: BTreeSet<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArgumentsNode {
    executables: BTreeSet<String>,
    required_arguments: BTreeSet<String>,
}

#[derive(Debug)]
enum Matcher {
    Executable(ExecutableNode),
    Arguments(ArgumentsNode),
    Any(Vec<usize>),
    All(Vec<usize>),
    Pipeline(usize, usize),
    Operand(OperandMatcher),
    Structured(StructuredMatcher),
    CommonCli(CommonCliMatcher),
    Database(DatabaseMatcher),
    Specialized(SpecializedMatcher),
}

#[derive(Debug)]
struct Node {
    operation: String,
    matcher: Matcher,
}

#[derive(Debug)]
pub struct NativeCommandProgram {
    pub program_digest: String,
    pub catalog_digest: String,
    pub trust_digest: String,
    pub extensions: Vec<ProgramExtension>,
    pub rules: Vec<ProgramRule>,
    nodes: Vec<Node>,
    executable_index: BTreeMap<String, Vec<usize>>,
    keyword_index: BTreeMap<String, Vec<usize>>,
    unindexed: Vec<usize>,
    rule_indices: BTreeMap<String, usize>,
}

pub fn packaged_command_program() -> Result<Arc<NativeCommandProgram>, &'static str> {
    static PROGRAM: OnceLock<Result<Arc<NativeCommandProgram>, &'static str>> = OnceLock::new();
    PROGRAM
        .get_or_init(|| NativeCommandProgram::from_packaged_bytes(EMBEDDED_PROGRAM).map(Arc::new))
        .clone()
}

pub fn digest_value(domain: &[u8], value: &impl serde::Serialize) -> Result<String, &'static str> {
    let canonical = serde_json::to_value(value).map_err(|_| "native_command_encoding_failed")?;
    digest_json_value(domain, &canonical)
}

fn digest_json_value(domain: &[u8], value: &Value) -> Result<String, &'static str> {
    let encoded = serde_json::to_vec(value).map_err(|_| "native_command_encoding_failed")?;
    Ok(digest_canonical_bytes(domain, &encoded))
}

fn digest_canonical_bytes(domain: &[u8], encoded: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(encoded);
    hex::encode(digest.finalize())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bounded_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

impl NativeCommandProgram {
    pub fn candidate_rule_indices(&self, command: &CanonicalCommandV1) -> Vec<usize> {
        let mut candidates = vec![false; self.rules.len()];
        for index in &self.unindexed {
            candidates[*index] = true;
        }
        for segment in &command.segments {
            if let Some(executable) = segment.executable.as_deref() {
                if let Some(indices) = self
                    .executable_index
                    .get(&lowercase_for_ascii_comparison(basename(executable)))
                {
                    for index in indices {
                        candidates[*index] = true;
                    }
                }
            }
            for token in &segment.tokens {
                if let Some(indices) = self
                    .keyword_index
                    .get(&lowercase_for_ascii_comparison(token))
                {
                    for index in indices {
                        candidates[*index] = true;
                    }
                }
            }
        }
        candidates
            .into_iter()
            .enumerate()
            .filter_map(|(index, selected)| selected.then_some(index))
            .collect()
    }

    pub fn runtime_coverage(&self) -> Vec<(&str, bool)> {
        self.rules
            .iter()
            .map(|rule| {
                // Every admitted node has a known, typed native operation.
                // Compatibility-only rules are qualified separately.
                let supported = rule.matcher.is_some();
                (rule.rule_id.as_str(), supported)
            })
            .collect()
    }

    pub fn supported_operations(&self) -> BTreeSet<&str> {
        self.nodes
            .iter()
            .map(|node| node.operation.as_str())
            .collect()
    }
}

fn basename(value: &str) -> &str {
    value.rsplit(['/', '\\']).next().unwrap_or(value)
}

fn executable_matches(segment: &CommandSegmentV1, executables: &BTreeSet<String>) -> bool {
    segment
        .executable
        .as_deref()
        .is_some_and(|value| executables.contains(&lowercase_for_ascii_comparison(basename(value))))
}

#[cfg(test)]
#[path = "native_command_program_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "native_command_program_bench.rs"]
mod bench;

#[cfg(test)]
#[path = "native_command_program_matrix.rs"]
mod matrix;
