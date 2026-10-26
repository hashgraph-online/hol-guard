//! Immutable, content-bound command extension program. No Python or IPC runs
//! here. The only production program input is packaged with the resident.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use guard_contracts::{
    NativeCommandObservationBatchV1, NativeCommandObservationV1,
    NativeCommandPermissionObservationV1, NativeMatcherEvidenceV1, NativeSafeVariantObservationV1,
    MAX_NATIVE_COMMAND_EVIDENCE_ITEMS, MAX_NATIVE_COMMAND_OBSERVATIONS,
};
use serde::Deserialize;
use serde_json::Value;

#[cfg(test)]
#[path = "authored_test_support.rs"]
pub(crate) mod authored_test_support;

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
const MAX_PROGRAM_BYTES: usize = 6 * 1024 * 1024;
const MAX_RULES: usize = 1_024;
const MAX_NODES: usize = 16_384;
const MAX_DEPTH: usize = 32;
const MATCH_DETAIL: &str = "Matched bounded structured command constraints.";
#[cfg(not(guard_source_bootstrap))]
static EMBEDDED_PROGRAM: &[u8] = guard_command_catalog_data::PROGRAM_JSON_ZST;
/// SHA-256 hex of the exact packaged program bytes (with trailing newline).
#[cfg(not(guard_source_bootstrap))]
pub const PACKAGED_COMMAND_PROGRAM_SHA256: &str = guard_command_catalog_data::PROGRAM_JSON_SHA256;
#[cfg(guard_source_bootstrap)]
pub const PACKAGED_COMMAND_PROGRAM_SHA256: &str = "";

/// Program identity without decoding the legacy embedded artifact.
#[cfg(not(guard_source_bootstrap))]
pub const PACKAGED_COMMAND_PROGRAM_ID: &str = guard_command_catalog_data::PROGRAM_ID;
#[cfg(guard_source_bootstrap)]
pub const PACKAGED_COMMAND_PROGRAM_ID: &str = "";

#[cfg(not(guard_source_bootstrap))]
const DEFAULT_COMMAND_PACK_IDS: &str = guard_command_catalog_data::DEFAULT_COMMAND_PACK_IDS;
#[cfg(guard_source_bootstrap)]
const DEFAULT_COMMAND_PACK_IDS: &str = "";

/// The exact program admitted by the runtime, also used for rule attestation.
// One shared allocation and accessor keep multi-megabyte data out of caller
// codegen units. Constant propagation otherwise emits redundant binary copies.
// Only the host build dependency has no packaged default. It compiles supplied
// sources; attempts to evaluate a default fail closed through normal admission.
#[inline(never)]
pub fn packaged_command_program_bytes() -> &'static [u8] {
    #[cfg(not(guard_source_bootstrap))]
    {
        static DECODED: OnceLock<Box<[u8]>> = OnceLock::new();
        DECODED
            .get_or_init(|| {
                crate::packaged_blob::decode(
                    EMBEDDED_PROGRAM,
                    guard_command_catalog_data::PROGRAM_JSON_LEN,
                    guard_command_catalog_data::PROGRAM_JSON_SHA256,
                )
            })
            .as_ref()
    }
    #[cfg(guard_source_bootstrap)]
    {
        &[]
    }
}

#[path = "native_command_program_admission.rs"]
mod admission;
pub(crate) use admission::{public_ipv4, public_ipv6};
#[path = "native_command_program_collection.rs"]
mod collection;
#[path = "native_command_program_collection_reader.rs"]
mod collection_reader;
pub use collection_reader::PackAdmissionBudget;
#[path = "native_command_program_compile.rs"]
mod compile;
#[path = "native_command_program_dispatch.rs"]
mod dispatch;
#[path = "native_command_program_evaluation.rs"]
mod evaluation;
#[path = "native_command_program_pack_cache.rs"]
mod pack_cache;
pub(crate) use dispatch::CommandCandidateIndex;
#[path = "native_command_program_memo.rs"]
mod memo;
use memo::{MemoLayout, NodeMemo};
#[path = "native_command_program_observations.rs"]
mod observations;
#[path = "native_command_source.rs"]
pub mod source;
#[path = "native_command_program_wire.rs"]
mod wire;
#[path = "native_command_program_work_stats.rs"]
pub mod work_stats;
use compile::{compile_node, validate_graph};
use evaluation::Evaluation;
use wire::*;

type MatchResult = Result<Arc<[usize]>, &'static str>;

/// `ExecutableInvocationMatcher` - one executable matcher, built outside a
/// compiled program.
///
/// Extension review has to decide which discovered operation owns a reviewed
/// literal invocation. Python answered that with matchers of its own, so a
/// vector could be bound by one grammar at review time and enforced by
/// another at run time. This hands that caller the node a compiled program
/// would hold, matched by the same code.
#[derive(Debug)]
pub struct ExecutableInvocationMatcher {
    node: ExecutableNode,
}

impl ExecutableInvocationMatcher {
    /// Builds the matcher from the config an `executable.v1` or
    /// `executable-path-set.v1` node carries, with the same validation the
    /// program compiler applies.
    pub fn from_config(operation: &str, config: Value) -> Result<Self, &'static str> {
        Ok(Self {
            node: compile::compile_executable(operation, config)?,
        })
    }

    /// Whether any segment of the command matches.
    pub fn matches(
        &self,
        command: &CanonicalCommandV1,
        deadline: Option<Instant>,
    ) -> Result<bool, &'static str> {
        evaluation::executable_evidence(&self.node, command, deadline)
            .map(|evidence| !evidence.is_empty())
    }
}

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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionedPackageSubcommandNode {
    executables: BTreeSet<String>,
    package: String,
    #[serde(default)]
    leading_subcommands: Vec<String>,
    #[serde(default)]
    subcommands: Vec<String>,
    #[serde(default)]
    required_flags: BTreeSet<String>,
    #[serde(default)]
    interspersed_options_with_values: BTreeSet<String>,
    #[serde(default)]
    interspersed_flags: BTreeSet<String>,
}

#[derive(Debug)]
enum Matcher {
    Executable(ExecutableNode),
    Arguments(ArgumentsNode),
    VersionedPackageSubcommand(VersionedPackageSubcommandNode),
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
    node_ids: Vec<String>,
    executable_index: BTreeMap<String, Vec<usize>>,
    keyword_index: BTreeMap<String, Vec<usize>>,
    unindexed: Vec<usize>,
    rule_indices: BTreeMap<String, usize>,
    extension_rule_indices: Vec<Vec<usize>>,
    baseline_allow_permissions: BTreeSet<String>,
}

pub fn packaged_command_program() -> Result<Arc<NativeCommandProgram>, &'static str> {
    static PROGRAM: OnceLock<Result<Arc<NativeCommandProgram>, &'static str>> = OnceLock::new();
    PROGRAM
        .get_or_init(|| {
            NativeCommandProgram::from_embedded_artifact(packaged_command_program_bytes())
                .map(Arc::new)
        })
        .clone()
}

pub fn packaged_program_digests() -> (String, String, String) {
    packaged_command_program()
        .map(|program| {
            (
                program.program_digest.clone(),
                program.catalog_digest.clone(),
                program.trust_digest.clone(),
            )
        })
        .unwrap_or_default()
}

pub fn digest_value(domain: &[u8], value: &impl serde::Serialize) -> Result<String, &'static str> {
    let canonical = serde_json::to_value(value).map_err(|_| "native_command_encoding_failed")?;
    digest_json_value(domain, &canonical)
}

fn digest_json_value(domain: &[u8], value: &Value) -> Result<String, &'static str> {
    let encoded = canonical_json_bytes(value).map_err(|_| "native_command_encoding_failed")?;
    Ok(digest_canonical_bytes(domain, &encoded))
}

// Do not depend on serde_json's selected Map implementation. Build dependencies
// may enable preserve_order, while the packaged/runtime contract requires
// recursively sorted object keys and the usual UTF-8 JSON string encoding.
pub(crate) fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, serde_json::Error> {
    let mut canonical = value.clone();
    canonical.sort_all_objects();
    serde_json::to_vec(&canonical)
}

// ring uses the CPU's SHA instructions; the packaged program digest covers
// megabytes of canonical JSON on every resident start.
fn digest_canonical_bytes(domain: &[u8], encoded: &[u8]) -> String {
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    digest.update(domain);
    digest.update(encoded);
    hex::encode(digest.finish())
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
    pub(crate) fn permission_baseline_allows(&self, id: &str) -> bool {
        self.baseline_allow_permissions.contains(id)
    }

    pub(crate) fn extension_rules(&self, index: usize) -> impl Iterator<Item = &ProgramRule> {
        self.extension_rule_indices[index]
            .iter()
            .map(|index| &self.rules[*index])
    }

    pub fn candidate_rule_indices(&self, command: &CanonicalCommandV1) -> Vec<usize> {
        dispatch::candidates(
            command,
            &self.executable_index,
            &self.keyword_index,
            &self.unindexed,
        )
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

    /// Program names one of which every command matching this extension must
    /// run: declared executables and, per rule, the executables its matcher
    /// requires. Compatibility-only rules are attributed by `compatibility`.
    /// `None` means some rule can match without naming a known program.
    pub(crate) fn extension_names(
        &self,
        extension_index: usize,
        compatibility: Option<&[&str]>,
    ) -> Option<BTreeSet<String>> {
        let mut names: BTreeSet<String> = self.extensions[extension_index]
            .executables
            .iter()
            .map(|name| lowercase_for_ascii_comparison(basename(name)))
            .collect();
        for rule in self.extension_rules(extension_index) {
            match rule.matcher {
                Some(node) => names.extend(self.required_executables(node, 0)?),
                None => names.extend(compatibility?.iter().map(|name| (*name).to_owned())),
            }
        }
        Some(names)
    }

    /// The names `extension_names` lists, leaving out rules that can match
    /// without naming a known program instead of giving up on the set.
    pub(crate) fn extension_known_names(
        &self,
        extension_index: usize,
        compatibility: Option<&[&str]>,
    ) -> BTreeSet<String> {
        let mut names: BTreeSet<String> = self.extensions[extension_index]
            .executables
            .iter()
            .map(|name| lowercase_for_ascii_comparison(basename(name)))
            .collect();
        for rule in self.extension_rules(extension_index) {
            match rule.matcher {
                Some(node) => names.extend(self.required_executables(node, 0).unwrap_or_default()),
                None => names.extend(
                    compatibility
                        .unwrap_or_default()
                        .iter()
                        .map(|name| (*name).to_owned()),
                ),
            }
        }
        names
    }

    /// Executables one of which a match of `node` must run. Alternatives need
    /// all of theirs; a conjunction needs any one child's. Matchers without a
    /// declared executable gate have no such set.
    fn required_executables(&self, node: usize, depth: usize) -> Option<BTreeSet<String>> {
        let executables = match &self.nodes.get(node)?.matcher {
            Matcher::Executable(node) => node.contract.executables.clone(),
            Matcher::Arguments(node) => node.executables.clone(),
            Matcher::VersionedPackageSubcommand(node) => node.executables.clone(),
            Matcher::Any(children) if depth < MAX_DEPTH && !children.is_empty() => {
                let mut union = BTreeSet::new();
                for child in children {
                    union.extend(self.required_executables(*child, depth + 1)?);
                }
                union
            }
            Matcher::All(children) if depth < MAX_DEPTH => children
                .iter()
                .filter_map(|child| self.required_executables(*child, depth + 1))
                .min_by_key(BTreeSet::len)?,
            Matcher::Pipeline(producer, consumer) if depth < MAX_DEPTH => [producer, consumer]
                .into_iter()
                .filter_map(|child| self.required_executables(*child, depth + 1))
                .min_by_key(BTreeSet::len)?,
            _ => return None,
        };
        let executables: BTreeSet<String> = executables
            .iter()
            .map(|name| lowercase_for_ascii_comparison(basename(name)))
            .collect();
        (!executables.is_empty()).then_some(executables)
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
