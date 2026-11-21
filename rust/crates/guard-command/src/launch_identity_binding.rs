//! Rust port of `runtime/launch_identity_binding.py` — the launch-identity
//! drift evidence record.
//!
//! `observe_launch_identity_binding` (:209) pulls live environment/launch
//! material through `launch_identity_environment.py`, `approval_context.py`,
//! `command_tokens.shell_tokens`, `package_execution_context`, and
//! `command.redirects`/`embedded_commands` — a transitive env-model +
//! subprocess surface that has not been ported yet (RTM-016 dependency).
//! This module ports the observation half that is already pure:
//! `LaunchBindingDimension`, `RuleVersionBinding`, `LaunchBindingDimensionDigest`,
//! `LaunchIdentityBindingObservation` (`__post_init__`/`to_dict`/
//! `action_floor`/`can_issue_positive_proof`),
//! `changed_launch_binding_dimensions`, `_binding_digest`, `_dimension`,
//! `_framed_digest`, `_wrapper_identity_digest`.
//!
//! Error strings match Python `ValueError` messages verbatim.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::command_model::CanonicalCommand;
use crate::command_tokens::shell_tokens;
use crate::effect_decision::{
    maximum_action_floor, GuardAction, ProofRequirement, UncertaintyKind,
};
use crate::launch_identity::{
    build_runtime_executable_identity, build_runtime_launch_identity,
    runtime_launch_identity_is_reusable,
};
use crate::launch_identity_environment::{
    environment_observation_material, inherited_launch_environment,
    launch_environment_scope_is_ambiguous, launch_search_path, plan_command_segment_environment,
    plan_launch_environment, unresolved_launch_observation,
};
use crate::package_execution_context::{
    package_execution_context_from_evidence, PackageExecutionContext,
    NON_PORTABLE_PACKAGE_CONTEXT_COMPONENTS, PACKAGE_CONTEXT_COMPONENTS, PACKAGE_LAUNCHERS,
};

/// `LAUNCH_IDENTITY_BINDING_VERSION` (:34).
pub const LAUNCH_IDENTITY_BINDING_VERSION: &str = "1.0.0";

/// `LaunchBindingDimension` (:74).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LaunchBindingDimension {
    CommandStructure,
    ExecutableObservation,
    LaunchEnvironmentObservation,
    RedirectionTargetObservation,
    WorkspaceLocation,
    RepositoryLocation,
    WorkingDirectoryLocation,
    PolicyAndRuleVersions,
    PackageContextObservation,
}

impl LaunchBindingDimension {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommandStructure => "command-structure",
            Self::ExecutableObservation => "executable-observation",
            Self::LaunchEnvironmentObservation => "launch-environment-observation",
            Self::RedirectionTargetObservation => "redirection-target-observation",
            Self::WorkspaceLocation => "workspace-location",
            Self::RepositoryLocation => "repository-location",
            Self::WorkingDirectoryLocation => "working-directory-location",
            Self::PolicyAndRuleVersions => "policy-and-rule-versions",
            Self::PackageContextObservation => "package-context-observation",
        }
    }

    /// Every dimension, in `as_str` sort order. `_REQUIRED_DIMENSIONS` (:86).
    pub const ALL: [LaunchBindingDimension; 9] = [
        Self::CommandStructure,
        Self::ExecutableObservation,
        Self::LaunchEnvironmentObservation,
        Self::PackageContextObservation,
        Self::PolicyAndRuleVersions,
        Self::RedirectionTargetObservation,
        Self::RepositoryLocation,
        Self::WorkingDirectoryLocation,
        Self::WorkspaceLocation,
    ];
}

/// `_MANDATORY_UNCERTAINTIES` (:38) — `{unknown-effect, unresolved-launch-identity}`.
const MANDATORY_UNCERTAINTIES: [UncertaintyKind; 2] = [
    UncertaintyKind::UnresolvedLaunchIdentity,
    UncertaintyKind::UnknownEffect,
];

/// `_CORE_REQUIREMENTS` (:193).
const CORE_REQUIREMENTS: [ProofRequirement; 10] = [
    ProofRequirement::OperationAndTargets,
    ProofRequirement::WorkspaceIdentity,
    ProofRequirement::RepositoryIdentity,
    ProofRequirement::WorkingDirectoryIdentity,
    ProofRequirement::ExecutableIdentity,
    ProofRequirement::LaunchChain,
    ProofRequirement::ConfigurationIdentity,
    ProofRequirement::ShellDataFlow,
    ProofRequirement::ParserConfidence,
    ProofRequirement::ExpectedEffects,
];

type ObservationResult<T> = Result<T, String>;

/// `RuleVersionBinding` (:89) — `(rule_id, version)` with `_REFERENCE` /
/// `_VERSION` fullmatch gates from `__post_init__`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RuleVersionBinding {
    pub rule_id: String,
    pub version: String,
}

impl RuleVersionBinding {
    /// `__post_init__` (:94).
    pub fn validate(&self) -> ObservationResult<()> {
        // `_REFERENCE` (:36): `[a-z][a-z0-9_-]*(?:[.:/][a-z0-9][a-z0-9_-]*)+`
        let reference_ok = regex::Regex::new(r"^[a-z][a-z0-9_-]*(?:[.:/][a-z0-9][a-z0-9_-]*)+$")
            .unwrap()
            .is_match(&self.rule_id);
        // `_VERSION` (:37): `[A-Za-z0-9][A-Za-z0-9._+-]{0,127}`
        let version_ok = regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
            .unwrap()
            .is_match(&self.version);
        if !reference_ok || !version_ok {
            return Err("rule binding must use canonical identifiers".to_string());
        }
        Ok(())
    }
}

/// `LaunchBindingDimensionDigest` (:99).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LaunchBindingDimensionDigest {
    pub dimension: LaunchBindingDimension,
    pub digest: String,
}

impl LaunchBindingDimensionDigest {
    /// `__post_init__` (:104).
    pub fn validate(&self) -> ObservationResult<()> {
        if !is_sha256(&self.digest) {
            return Err("dimension digest must be a lowercase SHA-256 value".to_string());
        }
        Ok(())
    }
}

/// `LaunchIdentityBindingObservation` (:111). Construct via [`new`] so
/// `__post_init__` runs end-to-end.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LaunchIdentityBindingObservation {
    pub binding_digest: String,
    pub dimensions: Vec<LaunchBindingDimensionDigest>,
    pub required_requirements: Vec<ProofRequirement>,
    pub unresolved_requirements: Vec<ProofRequirement>,
    pub uncertainties: Vec<UncertaintyKind>,
    pub schema_version: String,
}

impl LaunchIdentityBindingObservation {
    /// `LaunchIdentityBindingObservation(...)` → `__post_init__` (:122).
    pub fn new(
        binding_digest: String,
        dimensions: Vec<LaunchBindingDimensionDigest>,
        required_requirements: Vec<ProofRequirement>,
        unresolved_requirements: Vec<ProofRequirement>,
        uncertainties: Vec<UncertaintyKind>,
    ) -> ObservationResult<Self> {
        let observation = Self {
            binding_digest,
            dimensions,
            required_requirements,
            unresolved_requirements,
            uncertainties,
            schema_version: LAUNCH_IDENTITY_BINDING_VERSION.to_string(),
        };
        observation.validate()?;
        Ok(observation)
    }

    /// `__post_init__` (:122-168), same check order, same messages.
    pub fn validate(&self) -> ObservationResult<()> {
        if self.schema_version != LAUNCH_IDENTITY_BINDING_VERSION {
            return Err("unsupported launch binding observation version".to_string());
        }
        if !is_sha256(&self.binding_digest) {
            return Err("binding digest must be a lowercase SHA-256 value".to_string());
        }
        for item in &self.dimensions {
            item.validate()
                .map_err(|_| "dimensions must contain exact dimension digests".to_string())?;
        }
        // `dimension_names == tuple(sorted(set(dimension_names), key=value))` —
        // unique AND ordered by dimension value.
        let mut sorted = self.dimensions.clone();
        sorted.sort_by_key(|d| d.dimension.as_str());
        sorted.dedup_by_key(|d| d.dimension.as_str());
        if sorted.len() != self.dimensions.len()
            || sorted
                .iter()
                .zip(self.dimensions.iter())
                .any(|(a, b)| a.dimension != b.dimension)
        {
            return Err("dimensions must be unique and ordered".to_string());
        }
        let names: BTreeSet<_> = self.dimensions.iter().map(|d| d.dimension).collect();
        if names.len() != LaunchBindingDimension::ALL.len()
            || !names
                .iter()
                .all(|d| LaunchBindingDimension::ALL.contains(d))
        {
            return Err("all launch binding dimensions are required".to_string());
        }
        // required/unresolved are frozensets in Python; the Vec here is the
        // member list — required ⊇ _CORE_REQUIREMENTS.
        let required: BTreeSet<_> = self.required_requirements.iter().copied().collect();
        if !CORE_REQUIREMENTS.iter().all(|r| required.contains(r)) {
            return Err("core launch proof requirements cannot be omitted".to_string());
        }
        // `required_requirements != unresolved_requirements` → frozenset eq.
        let unresolved: BTreeSet<_> = self.unresolved_requirements.iter().copied().collect();
        if required != unresolved {
            return Err("observation-only bindings cannot satisfy proof requirements".to_string());
        }
        // uncertainties unique + ordered by value, ⊇ _MANDATORY_UNCERTAINTIES.
        let mut sorted_u = self.uncertainties.clone();
        sorted_u.sort_by_key(|u: &UncertaintyKind| u.as_str());
        sorted_u.dedup_by_key(|u| *u);
        if sorted_u.len() != self.uncertainties.len()
            || sorted_u
                .iter()
                .zip(self.uncertainties.iter())
                .any(|(a, b)| a != b)
        {
            return Err("uncertainties must be unique and ordered".to_string());
        }
        let set_u: BTreeSet<_> = self.uncertainties.iter().copied().collect();
        if !MANDATORY_UNCERTAINTIES.iter().all(|u| set_u.contains(u)) {
            return Err(
                "observation-only bindings require launch and effect uncertainty".to_string(),
            );
        }
        let expected = binding_digest(&self.dimensions, &required, &self.uncertainties);
        if self.binding_digest != expected {
            return Err("binding digest does not match launch binding material".to_string());
        }
        Ok(())
    }

    /// `can_issue_positive_proof` (:170) — observation is never a proof.
    pub const fn can_issue_positive_proof(&self) -> bool {
        false
    }

    /// `action_floor` (:174) — `maximum_action_floor(UNCERTAINTY_FLOOR[u])`.
    pub fn action_floor(&self) -> GuardAction {
        let floors: Vec<GuardAction> = self.uncertainties.iter().map(|u| u.floor()).collect();
        maximum_action_floor(floors.iter())
    }

    /// `to_dict` (:180).
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert(
            "schema_version".into(),
            Value::String(self.schema_version.clone()),
        );
        m.insert(
            "binding_digest".into(),
            Value::String(self.binding_digest.clone()),
        );
        m.insert(
            "dimensions".into(),
            Value::Array(
                self.dimensions
                    .iter()
                    .map(|d| {
                        let mut dm = Map::new();
                        dm.insert(
                            "dimension".into(),
                            Value::String(d.dimension.as_str().to_string()),
                        );
                        dm.insert("digest".into(), Value::String(d.digest.clone()));
                        Value::Object(dm)
                    })
                    .collect(),
            ),
        );
        m.insert(
            "required_requirements".into(),
            sorted_str_array(self.required_requirements.iter().map(|r| r.as_str())),
        );
        m.insert(
            "unresolved_requirements".into(),
            sorted_str_array(self.unresolved_requirements.iter().map(|r| r.as_str())),
        );
        m.insert(
            "uncertainties".into(),
            Value::Array(
                self.uncertainties
                    .iter()
                    .map(|u| Value::String(u.as_str().to_string()))
                    .collect(),
            ),
        );
        m.insert("can_issue_positive_proof".into(), Value::Bool(false));
        m.insert(
            "action_floor".into(),
            Value::String(self.action_floor().as_str().to_string()),
        );
        Value::Object(m)
    }
}

/// `changed_launch_binding_dimensions` (:388) — dimensions whose digest
/// differs between two observations, ordered by dimension value.
pub fn changed_launch_binding_dimensions(
    previous: &LaunchIdentityBindingObservation,
    current: &LaunchIdentityBindingObservation,
) -> Vec<LaunchBindingDimension> {
    let previous_digests: BTreeMap<_, _> = previous
        .dimensions
        .iter()
        .map(|d| (d.dimension, &d.digest))
        .collect();
    let current_digests: BTreeMap<_, _> = current
        .dimensions
        .iter()
        .map(|d| (d.dimension, &d.digest))
        .collect();
    let mut changed: Vec<LaunchBindingDimension> = LaunchBindingDimension::ALL
        .iter()
        .copied()
        .filter(|d| previous_digests.get(d) != current_digests.get(d))
        .collect();
    changed.sort_by_key(|d| d.as_str());
    changed
}

/// `_binding_digest` (:472) — framed digest of the schema/dimensions/
/// requirements/uncertainties material.
pub fn binding_digest(
    dimensions: &[LaunchBindingDimensionDigest],
    required_requirements: &BTreeSet<ProofRequirement>,
    uncertainties: &[UncertaintyKind],
) -> String {
    let mut sorted_req: Vec<&str> = required_requirements.iter().map(|r| r.as_str()).collect();
    sorted_req.sort_unstable();
    let mut sorted_unc: Vec<&str> = uncertainties.iter().map(|u| u.as_str()).collect();
    sorted_unc.sort_unstable();
    let material = serde_json::json!({
        "schema_version": LAUNCH_IDENTITY_BINDING_VERSION,
        "dimensions": dimensions
            .iter()
            .map(|d| Value::Array(vec![
                Value::String(d.dimension.as_str().to_string()),
                Value::String(d.digest.clone()),
            ]))
            .collect::<Vec<_>>(),
        "required_requirements": sorted_req,
        "uncertainties": sorted_unc,
    });
    framed_digest("hol-guard.launch-binding-observation", &material)
}

/// `_dimension` (:487) — wrap a material value into a dimension digest.
pub fn dimension_digest(
    dimension: LaunchBindingDimension,
    material: &Value,
) -> LaunchBindingDimensionDigest {
    LaunchBindingDimensionDigest {
        dimension,
        digest: framed_digest(&format!("hol-guard.{}", dimension.as_str()), material),
    }
}

/// `_wrapper_identity_digest` (:431) — framed digest of the runtime-executable
/// identity minus `reuse_nonce`.
pub fn wrapper_identity_digest(identity: &Value) -> String {
    let mut stable = Map::new();
    if let Value::Object(m) = identity {
        for (k, v) in m {
            if k != "reuse_nonce" {
                stable.insert(k.clone(), v.clone());
            }
        }
    }
    framed_digest(
        "hol-guard.runtime-wrapper-executable",
        &Value::Object(stable),
    )
}

/// `_framed_digest` (:495) — `sha256(domain + NUL + u64be(len) + canonical)`.
pub fn framed_digest(domain: &str, value: &Value) -> String {
    let payload = guard_contracts::capability_canonical_json(value)
        .unwrap_or_default()
        .into_bytes();
    let mut frame = Vec::with_capacity(domain.len() + 1 + 8 + payload.len());
    frame.extend_from_slice(domain.as_bytes());
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    frame.extend_from_slice(&payload);
    let mut hasher = Sha256::new();
    hasher.update(&frame);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `_SHA256.fullmatch` (:35).
fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `sorted(item.value for item in …)` → JSON array.
fn sorted_str_array<'a>(items: impl Iterator<Item = &'a str>) -> Value {
    let mut values: Vec<String> = items.map(str::to_string).collect();
    values.sort_unstable();
    values.dedup();
    Value::Array(values.into_iter().map(Value::String).collect())
}

#[cfg(test)]
mod digest_parity {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn framed_digest_matches_python_oracle() {
        // python: framed('hol-guard.command-structure', {'segments':[['gh','issue','lock']],'unicode':'héllo'})
        //       = d10f8ee5…9429319
        let material = serde_json::json!({
            "segments": [["gh", "issue", "lock"]],
            "unicode": "héllo",
        });
        assert_eq!(
            framed_digest("hol-guard.command-structure", &material),
            "d10f8ee54304afc101086609aeeea553682e1ece071bc4165c703c6b58429319"
        );
    }

    #[test]
    fn binding_digest_matches_python_oracle() {
        // material with dims [[command-structure,a*64],[executable-observation,b*64]],
        // required [operation-and-targets, workspace-identity], uncertainties [unresolved-launch-identity, unknown-effect]
        let dims = vec![
            LaunchBindingDimensionDigest {
                dimension: LaunchBindingDimension::CommandStructure,
                digest: "a".repeat(64),
            },
            LaunchBindingDimensionDigest {
                dimension: LaunchBindingDimension::ExecutableObservation,
                digest: "b".repeat(64),
            },
        ];
        let required: BTreeSet<ProofRequirement> = [
            ProofRequirement::OperationAndTargets,
            ProofRequirement::WorkspaceIdentity,
        ]
        .into_iter()
        .collect();
        let uncertainties = vec![
            UncertaintyKind::UnresolvedLaunchIdentity,
            UncertaintyKind::UnknownEffect,
        ];
        assert_eq!(
            binding_digest(&dims, &required, &uncertainties),
            "a84eb5f03410da2511c17e85f2209a47241ca5adcf17e13e9f831c24b0fa3958"
        );
    }
}

// ---------------------------------------------------------------------------
// `observe_launch_identity_binding` (:209-385) + the remaining private
// helpers (`_validated_package_observation` :406,
// `_command_requires_package_context` :419, `_redirection_target_material`
// :436, `_resolved` :491).
// ---------------------------------------------------------------------------

/// `_VERSION.fullmatch` (:37) — `[A-Za-z0-9][A-Za-z0-9._+-]{0,127}`.
fn is_version(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    value.len() <= 128
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

/// `secrets.token_hex(16)` — RNG failure yields an all-zero marker so the
/// observation stays unresolved rather than fabricating a reusable nonce.
fn token_hex_16() -> String {
    let mut bytes = [0u8; 16];
    match getrandom::fill(&mut bytes) {
        Ok(()) => hex::encode(bytes),
        Err(_) => "0".repeat(32),
    }
}

/// `Path.expanduser` subset (`~`/`~/` → `$HOME`), mirroring
/// `launch_identity::expand_user`.
fn expand_user(path: &std::path::Path) -> PathBuf {
    let text = path.to_string_lossy();
    if text == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home);
        }
        return path.to_path_buf();
    }
    if let Some(rest) = text.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::Path::new(&home).join(rest);
        }
    }
    path.to_path_buf()
}

/// `os.path.abspath`/`normpath` — collapse `.`/`..` lexically without
/// touching the filesystem (mirrors `launch_identity::normalize_lexical`).
fn normalize_lexical(path: &std::path::Path) -> PathBuf {
    let mut out: Vec<std::ffi::OsString> = Vec::new();
    let absolute = path.is_absolute();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if matches!(out.last().map(|s| s.to_string_lossy()), Some(s) if s != "..") {
                    out.pop();
                } else if !absolute {
                    out.push(std::ffi::OsString::from(".."));
                }
            }
            std::path::Component::Normal(s) => out.push(s.to_os_string()),
            std::path::Component::Prefix(_) => {}
        }
    }
    let mut result = if absolute {
        PathBuf::from("/")
    } else {
        PathBuf::new()
    };
    for part in out {
        result.push(part);
    }
    result
}

/// `Path.resolve(strict=False)` — canonicalize the deepest existing prefix
/// and append the remainder lexically (mirrors
/// `runtime_read_paths::weak_canonicalize`, with the tail normalized the way
/// `os.path.realpath` collapses `..` against the canonical prefix).
fn weak_canonicalize(path: &std::path::Path) -> Option<PathBuf> {
    match path.canonicalize() {
        Ok(p) => Some(p),
        Err(_) => {
            let mut prefix = path.to_path_buf();
            let mut tail: Vec<std::ffi::OsString> = Vec::new();
            loop {
                match prefix.canonicalize() {
                    Ok(p) => {
                        let mut out = p;
                        for part in tail.iter().rev() {
                            out.push(part);
                        }
                        return Some(normalize_lexical(&out));
                    }
                    Err(_) => {
                        let name = prefix.file_name()?.to_os_string();
                        tail.push(name);
                        if !prefix.pop() {
                            return None;
                        }
                    }
                }
            }
        }
    }
}

/// `_resolved` (:491) — `path.expanduser().resolve(strict=False)`.
fn resolved(path: &std::path::Path) -> PathBuf {
    let expanded = expand_user(path);
    match weak_canonicalize(&expanded) {
        Some(p) => p,
        // `resolve(strict=False)` degrades to a lexical `abspath` join when
        // every ancestor is unresolvable.
        None => {
            let candidate = if expanded.is_absolute() {
                expanded.clone()
            } else {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join(&expanded)
            };
            normalize_lexical(&candidate)
        }
    }
}

/// `_validated_package_observation` (:406) — re-derive the context from its
/// own evidence; any mismatch or wrong component set is `{"status":"invalid"}`.
fn validated_package_observation(context: &PackageExecutionContext) -> Value {
    let validated = package_execution_context_from_evidence(&context.to_evidence());
    let component_names: BTreeSet<&str> = context
        .components
        .iter()
        .map(|item| item.name.as_str())
        .collect();
    let expected_names: BTreeSet<&str> = if context.portable {
        PACKAGE_CONTEXT_COMPONENTS.iter().copied().collect()
    } else {
        NON_PORTABLE_PACKAGE_CONTEXT_COMPONENTS
            .iter()
            .copied()
            .collect()
    };
    if validated.as_ref() != Some(context) || component_names != expected_names {
        return serde_json::json!({"status": "invalid"});
    }
    // `sorted((item.name, item.digest) for item in ...)` — tuple sort, then
    // JSON-encode as a list of pairs.
    let mut component_digests: Vec<(&str, &str)> = context
        .components
        .iter()
        .map(|item| (item.name.as_str(), item.digest.as_str()))
        .collect();
    component_digests.sort();
    serde_json::json!({
        "status": if context.portable { "portable-observation" } else { "non-portable-observation" },
        "context_digest": context.digest,
        "component_digests": component_digests
            .iter()
            .map(|(name, digest)| Value::Array(vec![
                Value::String(name.to_string()),
                Value::String(digest.to_string()),
            ]))
            .collect::<Vec<_>>(),
    })
}

/// `_command_requires_package_context` (:419) — any executable/argument
/// basename (`\\`→`/`, rsplit, lower) in `_PACKAGE_LAUNCHERS`.
fn command_requires_package_context(command: &CanonicalCommand) -> bool {
    for segment in &command.segments {
        // `launch_tokens = (segment.executable, *segment.arguments)` with the
        // `isinstance(token, str)` filter — `None` executable is skipped.
        let mut launch_tokens: Vec<&str> = Vec::with_capacity(segment.arguments.len() + 1);
        if let Some(executable) = &segment.executable {
            launch_tokens.push(executable.as_str());
        }
        launch_tokens.extend(segment.arguments.iter().map(|a| a.as_str()));
        for token in launch_tokens {
            let basename = token
                .replace('\\', "/")
                .rsplit('/')
                .next()
                .unwrap_or("")
                .to_lowercase();
            if PACKAGE_LAUNCHERS.contains(&basename.as_str()) {
                return true;
            }
        }
    }
    false
}

/// `_redirection_target_material` (:436) — inline-input / dynamic / observed /
/// unresolved per-redirect observations verbatim.
fn redirection_target_material(command: &CanonicalCommand, cwd: &std::path::Path) -> Vec<Value> {
    let mut material: Vec<Value> = Vec::new();
    for (index, redirect) in command.redirects.iter().enumerate() {
        let target = redirect.target.as_str();
        let mut base = Map::new();
        base.insert("index".to_string(), Value::Number(index.into()));
        base.insert(
            "operator".to_string(),
            Value::String(redirect.operator.clone()),
        );
        let operator: String = redirect
            .operator
            .trim_start_matches(|c: char| c.is_ascii_digit())
            .to_string();
        if operator == "<<" || operator == "<<-" || operator == "<<<" {
            base.insert(
                "status".to_string(),
                Value::String("inline-input-bound-by-command-structure".to_string()),
            );
            material.push(Value::Object(base));
            continue;
        }
        if target
            .chars()
            .any(|c| matches!(c, '$' | '`' | '*' | '?' | '[' | ']' | '{' | '}'))
        {
            base.insert("status".to_string(), Value::String("dynamic".to_string()));
            base.insert("reuse_nonce".to_string(), Value::String(token_hex_16()));
            material.push(Value::Object(base));
            continue;
        }
        // `Path(target).expanduser()`, cwd-joined when relative, then
        // `resolve(strict=False)` (:454-469). `weak_canonicalize` `None` is
        // the `OSError`/`RuntimeError`/`ValueError` leg → unresolved + nonce.
        let mut lexical = expand_user(std::path::Path::new(target));
        if !lexical.is_absolute() {
            lexical = cwd.join(&lexical);
        }
        let canonical = match weak_canonicalize(&lexical) {
            Some(p) => p,
            None => {
                base.insert(
                    "status".to_string(),
                    Value::String("unresolved".to_string()),
                );
                base.insert("reuse_nonce".to_string(), Value::String(token_hex_16()));
                material.push(Value::Object(base));
                continue;
            }
        };
        base.insert(
            "canonical_path".to_string(),
            Value::String(canonical.to_string_lossy().into_owned()),
        );
        base.insert(
            "exists".to_string(),
            Value::Bool(std::fs::metadata(&lexical).is_ok()),
        );
        base.insert(
            "is_symlink".to_string(),
            Value::Bool(
                std::fs::symlink_metadata(&lexical)
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false),
            ),
        );
        base.insert("status".to_string(), Value::String("observed".to_string()));
        if operator == "<" {
            let identity = build_runtime_launch_identity(
                &Value::String(lexical.to_string_lossy().into_owned()),
                &[],
                true,
                false,
                None,
                Some(cwd),
                None,
                None,
            );
            base.insert(
                "input_identity".to_string(),
                identity.get("executable").cloned().unwrap_or(Value::Null),
            );
        }
        material.push(Value::Object(base));
    }
    material
}

/// `observe_launch_identity_binding` (:209).
///
/// `launch_env` models the Python `Mapping[str, str] | None` argument —
/// `None` reads the live process environment inside
/// `inherited_launch_environment`, exactly like Python.
#[allow(clippy::too_many_arguments)]
pub fn observe_launch_identity_binding(
    command: &CanonicalCommand,
    workspace: &std::path::Path,
    repository: &std::path::Path,
    working_directory: &std::path::Path,
    policy_version: &str,
    rules: &[RuleVersionBinding],
    launch_env: Option<&BTreeMap<String, String>>,
    package_contexts: &[PackageExecutionContext],
) -> ObservationResult<LaunchIdentityBindingObservation> {
    if !is_version(policy_version) || rules.is_empty() {
        return Err("policy and rule versions are required".to_string());
    }
    let unique_rule_ids: BTreeSet<&str> = rules.iter().map(|item| item.rule_id.as_str()).collect();
    if unique_rule_ids.len() != rules.len() {
        return Err("rule bindings must be unique".to_string());
    }
    let cwd = resolved(working_directory);

    // `dict.fromkeys` over top-level segment wrapper chains (:227-232).
    let mut segment_wrapper_order: Vec<String> = Vec::new();
    let mut seen_wrappers: BTreeSet<String> = BTreeSet::new();
    for segment in &command.segments {
        if !segment.execution_context.starts_with("top:") {
            continue;
        }
        for wrapper in &segment.wrapper_chain {
            if seen_wrappers.insert(wrapper.clone()) {
                segment_wrapper_order.push(wrapper.clone());
            }
        }
    }

    // Signed difference, like `len(...) - len(...)` (:234).
    let normalization_wrapper_count =
        command.wrapper_chain.len() as isize - segment_wrapper_order.len() as isize;
    let mut normalization_wrappers: Vec<String> = if normalization_wrapper_count > 0 {
        command.wrapper_chain[..normalization_wrapper_count as usize].to_vec()
    } else {
        Vec::new()
    };
    let wrapper_chain_complete = normalization_wrapper_count >= 0
        && command.wrapper_chain[normalization_wrapper_count as usize..]
            == segment_wrapper_order[..];
    if !wrapper_chain_complete {
        normalization_wrappers = Vec::new();
    }

    let inherited_plan = inherited_launch_environment(launch_env);
    let inherited_environment = inherited_plan.executable_environment.clone();
    let (raw_tokens, _raw_tokens_exact) = shell_tokens(&command.raw_text);
    let raw_plan = if command.raw_text != command.normalized_text {
        plan_launch_environment(&raw_tokens, &inherited_environment, inherited_plan.complete)
    } else {
        inherited_plan.clone()
    };
    let first_top_level_index = command
        .segments
        .iter()
        .position(|segment| segment.execution_context.starts_with("top:"));
    let script_scope_ambiguous =
        launch_environment_scope_is_ambiguous(&normalization_wrappers, command.segments.len());
    let planned_segments: Vec<crate::launch_identity_environment::LaunchEnvironmentPlan> = command
        .segments
        .iter()
        .enumerate()
        .map(|(index, segment)| {
            let inherited = if command.raw_text != command.normalized_text
                && Some(index) == first_top_level_index
            {
                &raw_plan.executable_environment
            } else {
                &inherited_environment
            };
            plan_command_segment_environment(segment, &command.embedded_commands, inherited)
        })
        .collect();
    let segment_plans: Vec<crate::launch_identity_environment::LaunchEnvironmentPlan> =
        planned_segments
            .into_iter()
            .map(
                |plan| crate::launch_identity_environment::LaunchEnvironmentPlan {
                    executable_environment: plan.executable_environment,
                    wrapper_environments: plan.wrapper_environments,
                    complete: inherited_plan.complete && plan.complete && !script_scope_ambiguous,
                },
            )
            .collect();

    let runtime_identities: Vec<Value> = command
        .segments
        .iter()
        .zip(segment_plans.iter())
        .map(|(segment, plan)| {
            // Python `Mapping` → wire `Value::Object` for the `launch_env` arg.
            let environment = Value::Object(
                plan.executable_environment
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                    .collect::<Map<String, Value>>(),
            );
            let args: Vec<Value> = segment
                .arguments
                .iter()
                .map(|a| Value::String(a.clone()))
                .collect();
            build_runtime_launch_identity(
                &segment
                    .executable
                    .as_ref()
                    .map(|e| Value::String(e.clone()))
                    .unwrap_or(Value::Null),
                &args,
                true,
                false,
                None,
                Some(&cwd),
                None,
                Some(&environment),
            )
        })
        .collect();

    // `executable_material` (:284-291) — `segment_index` is an int.
    let mut executable_material: Vec<Value> = Vec::new();
    for (index, identity) in runtime_identities.iter().enumerate() {
        executable_material.push(serde_json::json!({
            "segment_index": index,
            "identity_digest": framed_digest("hol-guard.runtime-launch", identity),
            "reusable_observation": runtime_launch_identity_is_reusable(identity),
        }));
    }
    if !wrapper_chain_complete {
        executable_material.push(unresolved_launch_observation("unresolved-wrapper-chain"));
    }
    if script_scope_ambiguous {
        executable_material.push(unresolved_launch_observation(
            "unresolved-script-environment-scope",
        ));
    }

    // `raw_wrapper_environments` is consumed by `del` inside the match loop
    // (:298-313) — matched candidates are removed so duplicate names resolve
    // to later occurrences.
    let mut raw_wrapper_environments = raw_plan.wrapper_environments.clone();
    for (index, wrapper) in normalization_wrappers.iter().enumerate() {
        let mut wrapper_environment = raw_plan.executable_environment.clone();
        if let Some(position) = raw_wrapper_environments
            .iter()
            .position(|candidate| candidate.name == *wrapper)
        {
            wrapper_environment = raw_wrapper_environments[position].environment.clone();
            raw_wrapper_environments.remove(position);
        }
        let wrapper_identity = build_runtime_executable_identity(
            &Value::String(wrapper.clone()),
            Some(&launch_search_path(&wrapper_environment)),
            Some(&cwd),
            None,
            true,
        );
        executable_material.push(serde_json::json!({
            "segment_index": format!("wrapper:{index}"),
            "identity_digest": wrapper_identity_digest(&wrapper_identity),
            "reusable_observation": runtime_launch_identity_is_reusable(&wrapper_identity),
        }));
    }
    for (segment_index, (segment, plan)) in command
        .segments
        .iter()
        .zip(segment_plans.iter())
        .enumerate()
    {
        for (wrapper_index, wrapper) in segment.wrapper_chain.iter().enumerate() {
            if wrapper_index >= plan.wrapper_environments.len() {
                executable_material.push(unresolved_launch_observation(&format!(
                    "segment:{segment_index}:wrapper-unresolved"
                )));
                continue;
            }
            let wrapper_environment = &plan.wrapper_environments[wrapper_index].environment;
            let wrapper_identity = build_runtime_executable_identity(
                &Value::String(wrapper.clone()),
                Some(&launch_search_path(wrapper_environment)),
                Some(&cwd),
                None,
                true,
            );
            executable_material.push(serde_json::json!({
                "segment_index": format!("segment:{segment_index}:wrapper:{wrapper_index}"),
                "identity_digest": wrapper_identity_digest(&wrapper_identity),
                "reusable_observation": runtime_launch_identity_is_reusable(&wrapper_identity),
            }));
        }
    }

    let package_material: Vec<Value> = package_contexts
        .iter()
        .map(validated_package_observation)
        .collect();

    // `environment_plans` (:339-344) — segment plans, then each plan's
    // wrapper environments (raw_plan's wrappers first), empty fallback to
    // raw_plan.
    let mut environment_plans: Vec<crate::launch_identity_environment::LaunchEnvironmentPlan> =
        segment_plans.clone();
    for plan in std::iter::once(&raw_plan).chain(segment_plans.iter()) {
        for wrapper in &plan.wrapper_environments {
            environment_plans.push(crate::launch_identity_environment::LaunchEnvironmentPlan {
                executable_environment: wrapper.environment.clone(),
                wrapper_environments: Vec::new(),
                complete: plan.complete,
            });
        }
    }
    if environment_plans.is_empty() {
        environment_plans.push(raw_plan.clone());
    }

    // `rules` material (:359-362) — `[policy_version, sorted(rule pairs)]`.
    let mut sorted_rules: Vec<(&str, &str)> = rules
        .iter()
        .map(|item| (item.rule_id.as_str(), item.version.as_str()))
        .collect();
    sorted_rules.sort();
    let rules_material = serde_json::json!([
        policy_version,
        sorted_rules
            .iter()
            .map(|(rule_id, version)| Value::Array(vec![
                Value::String(rule_id.to_string()),
                Value::String(version.to_string()),
            ]))
            .collect::<Vec<_>>(),
    ]);

    let dimensions = {
        let mut items = vec![
            dimension_digest(
                LaunchBindingDimension::CommandStructure,
                &Value::String(command.security_identity()),
            ),
            dimension_digest(
                LaunchBindingDimension::ExecutableObservation,
                &Value::Array(executable_material),
            ),
            dimension_digest(
                LaunchBindingDimension::LaunchEnvironmentObservation,
                &Value::Array(environment_observation_material(&environment_plans)),
            ),
            dimension_digest(
                LaunchBindingDimension::RedirectionTargetObservation,
                &Value::Array(redirection_target_material(command, &cwd)),
            ),
            dimension_digest(
                LaunchBindingDimension::WorkspaceLocation,
                &Value::String(resolved(workspace).to_string_lossy().into_owned()),
            ),
            dimension_digest(
                LaunchBindingDimension::RepositoryLocation,
                &Value::String(resolved(repository).to_string_lossy().into_owned()),
            ),
            dimension_digest(
                LaunchBindingDimension::WorkingDirectoryLocation,
                &Value::String(cwd.to_string_lossy().into_owned()),
            ),
            dimension_digest(
                LaunchBindingDimension::PolicyAndRuleVersions,
                &rules_material,
            ),
            dimension_digest(
                LaunchBindingDimension::PackageContextObservation,
                &Value::Array(package_material),
            ),
        ];
        items.sort_by_key(|item| item.dimension.as_str());
        items
    };

    let mut required: BTreeSet<ProofRequirement> = CORE_REQUIREMENTS.iter().copied().collect();
    if !package_contexts.is_empty() || command_requires_package_context(command) {
        required.insert(ProofRequirement::DependencyProvenance);
        required.insert(ProofRequirement::ConfigurationIdentity);
    }
    let mut uncertainties: Vec<UncertaintyKind> = MANDATORY_UNCERTAINTIES.to_vec();
    if command.confidence != "exact" || command.uncertainty_reason.is_some() {
        uncertainties.push(UncertaintyKind::PartialParse);
    }
    uncertainties.sort_by_key(|item| item.as_str());
    let typed_uncertainties = uncertainties;

    let typed_required: Vec<ProofRequirement> = required.iter().copied().collect();
    LaunchIdentityBindingObservation::new(
        binding_digest(&dimensions, &required, &typed_uncertainties),
        dimensions,
        typed_required.clone(),
        typed_required,
        typed_uncertainties,
    )
}

#[cfg(test)]
mod observe_tests {
    use super::*;
    use crate::command_model::CommandSegment;
    use crate::command_structure::CommandRedirect;

    fn one_segment_command() -> CanonicalCommand {
        CanonicalCommand {
            raw_text: "echo hello".to_string(),
            normalized_text: "echo hello".to_string(),
            dialect: "posix".to_string(),
            transport: "shell_string".to_string(),
            extraction_provenance: "test".to_string(),
            wrapper_chain: Vec::new(),
            segments: vec![CommandSegment {
                text: "echo hello".to_string(),
                tokens: vec!["echo".to_string(), "hello".to_string()],
                executable: Some("echo".to_string()),
                arguments: vec!["hello".to_string()],
                environment_names: Vec::new(),
                wrapper_chain: Vec::new(),
                path_overridden: false,
                execution_context: "top:0".to_string(),
                pipeline_index: 0,
                start: 0,
                end: 10,
            }],
            redirects: Vec::new(),
            embedded_commands: Vec::new(),
            confidence: "exact".to_string(),
            uncertainty_reason: None,
        }
    }

    fn rules() -> Vec<RuleVersionBinding> {
        vec![RuleVersionBinding {
            rule_id: "guard.launch".to_string(),
            version: "1.0.0".to_string(),
        }]
    }

    #[test]
    fn observe_returns_validated_observation() {
        let dir = std::env::temp_dir();
        let env: BTreeMap<String, String> = [("PATH", "/usr/bin:/bin")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let observation = observe_launch_identity_binding(
            &one_segment_command(),
            &dir,
            &dir,
            &dir,
            "policy-1.0",
            &rules(),
            Some(&env),
            &[],
        )
        .expect("observation");
        assert_eq!(observation.dimensions.len(), 9);
        // mandatory {unresolved-launch-identity, unknown-effect} — positive
        // proof can never be issued from drift evidence.
        assert!(!observation.uncertainties.is_empty());
        assert!(!observation.can_issue_positive_proof());
    }

    #[test]
    fn non_exact_parse_adds_partial_parse_uncertainty() {
        let dir = std::env::temp_dir();
        let env: BTreeMap<String, String> = [("PATH", "/usr/bin:/bin")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let mut command = one_segment_command();
        command.confidence = "uncertain".to_string();
        let observation = observe_launch_identity_binding(
            &command,
            &dir,
            &dir,
            &dir,
            "policy-1.0",
            &rules(),
            Some(&env),
            &[],
        )
        .expect("observation");
        assert!(observation
            .uncertainties
            .contains(&UncertaintyKind::PartialParse));
    }

    #[test]
    fn bad_policy_version_is_rejected() {
        let dir = std::env::temp_dir();
        let err = observe_launch_identity_binding(
            &one_segment_command(),
            &dir,
            &dir,
            &dir,
            "not a version!",
            &rules(),
            None,
            &[],
        )
        .unwrap_err();
        assert_eq!(err, "policy and rule versions are required");
    }

    #[test]
    fn duplicate_rules_are_rejected() {
        let dir = std::env::temp_dir();
        let mut dup = rules();
        dup.push(RuleVersionBinding {
            rule_id: "guard.launch".to_string(),
            version: "2.0.0".to_string(),
        });
        let err = observe_launch_identity_binding(
            &one_segment_command(),
            &dir,
            &dir,
            &dir,
            "policy-1.0",
            &dup,
            None,
            &[],
        )
        .unwrap_err();
        assert_eq!(err, "rule bindings must be unique");
    }

    #[test]
    fn inline_redirect_is_bound_by_command_structure() {
        let mut command = one_segment_command();
        command.redirects.push(CommandRedirect {
            operator: "<<".to_string(),
            target: "EOF".to_string(),
            start: 0,
            end: 0,
        });
        let material = redirection_target_material(&command, std::path::Path::new("/tmp"));
        assert_eq!(
            material[0]["status"],
            Value::String("inline-input-bound-by-command-structure".to_string())
        );
    }
}
