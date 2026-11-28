//! Inert, caller-pinned runner documents and selected campaign reservations.

use crate::campaign::verify_campaign;
use crate::crypto::sha256;
use crate::package_version::valid_package_version;
use crate::public_files::PublicRootReader;
use crate::{EvidenceError, Result};
use gauntlet_contracts::{
    bind_gate_policy, canonicalize, validate_runner_declaration, Record, MAX_RECORD_BYTES,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservationTotals {
    pub model_tokens: u64,
    pub tool_operations: u64,
    pub controller_seconds: u64,
}

impl ReservationTotals {
    fn add(self, other: Self) -> Option<Self> {
        Some(Self {
            model_tokens: self.model_tokens.checked_add(other.model_tokens)?,
            tool_operations: self.tool_operations.checked_add(other.tool_operations)?,
            controller_seconds: self
                .controller_seconds
                .checked_add(other.controller_seconds)?,
        })
    }

    fn times(self, count: u64) -> Option<Self> {
        Some(Self {
            model_tokens: self.model_tokens.checked_mul(count)?,
            tool_operations: self.tool_operations.checked_mul(count)?,
            controller_seconds: self.controller_seconds.checked_mul(count)?,
        })
    }

    pub fn to_json(self) -> Value {
        json!({
            "model_token_reservation": self.model_tokens,
            "tool_operation_reservation": self.tool_operations,
            "controller_seconds_reservation": self.controller_seconds,
        })
    }
}

#[derive(Debug)]
pub struct VerifiedRunnerInputs {
    pub version: u8,
    pub config: Record,
    pub campaign: Value,
    pub policy: Record,
    pub selection_reservations: ReservationTotals,
    pub shards: Vec<Vec<String>>,
    pub attempt_layout: &'static str,
}

fn decode_document(raw: &[u8]) -> Result<Value> {
    let canonical =
        canonicalize(raw).map_err(|_| EvidenceError::Invalid("invalid bounded runner document"))?;
    serde_json::from_slice(&canonical)
        .map_err(|_| EvidenceError::Invalid("invalid bounded runner document"))
}

fn budget(value: &Value, name: &str) -> Result<u64> {
    value[name]
        .as_u64()
        .ok_or(EvidenceError::Invalid("invalid campaign budget"))
}

pub(crate) fn developer_cell(cell: &Value) -> bool {
    if cell["group"] == "approval" {
        return false;
    }
    let Some(name) = cell["workflow_id"].as_str() else {
        return false;
    };
    matches!(
        name,
        "todo-app-to-github"
            | "fix-failing-node-test"
            | "add-validation-dependency"
            | "contributing-pull-request"
            | "worktree-report-branch"
            | "python-cli-with-tests"
            | "authored-developer-python-temperature-boundaries"
    )
}

fn reservation(cell: &Value, budgets: &Value) -> Result<ReservationTotals> {
    let seconds = budget(budgets, "episode_seconds")?;
    let operations = budget(budgets, "tool_operations")?;
    let tokens = budget(budgets, "model_tokens")?;
    if cell["group"] == "approval" {
        if !(1..=1800).contains(&seconds)
            || !(1..=500).contains(&operations)
            || !(1..=1_000_000).contains(&tokens)
        {
            return Err(EvidenceError::Invalid(
                "approval reservation exceeds executor bounds",
            ));
        }
        return Ok(ReservationTotals {
            model_tokens: tokens * 2,
            tool_operations: operations * 2,
            controller_seconds: 2 * (seconds + 90) + 60,
        });
    }
    if developer_cell(cell) {
        if !(1..=900).contains(&seconds)
            || !(1..=200).contains(&operations)
            || !(1..=100_000).contains(&tokens)
        {
            return Err(EvidenceError::Invalid(
                "developer reservation exceeds executor bounds",
            ));
        }
        return Ok(ReservationTotals {
            model_tokens: tokens,
            tool_operations: operations,
            controller_seconds: seconds + 300,
        });
    }
    Ok(ReservationTotals {
        model_tokens: tokens,
        tool_operations: operations,
        controller_seconds: seconds + 60,
    })
}

fn validate_protocol_mapping(config: &Value, selected: &[&Value]) -> Result<()> {
    let Some(mapping) = config["runtime"].get("mcp_protocol_profiles") else {
        return Ok(());
    };
    let profiles = mapping
        .as_object()
        .ok_or(EvidenceError::Invalid("invalid protocol mapping"))?;
    let cells: BTreeMap<_, _> = selected
        .iter()
        .filter_map(|cell| cell["id"].as_str().map(|id| (id, *cell)))
        .collect();
    for (id, profile) in profiles {
        let cell = cells.get(id.as_str()).ok_or(EvidenceError::Invalid(
            "protocol profile names an unselected cell",
        ))?;
        if cell["group"] == "approval" || (cell["variant"] == "clean" && profile["id"] != "clean") {
            return Err(EvidenceError::Invalid("unsafe protocol profile assignment"));
        }
    }
    Ok(())
}

/// Validate the frozen config, campaign and policy bytes without opening assets.
/// The caller must supply the config digest independently and later verify
/// the actual SDK/product/provider assets before admitting execution.
pub fn verify_runner_inputs(
    config_raw: &[u8],
    expected_config_digest: &str,
    campaign_raw: &[u8],
    policy_raw: &[u8],
) -> Result<VerifiedRunnerInputs> {
    if campaign_raw.len() > MAX_RECORD_BYTES || policy_raw.len() > MAX_RECORD_BYTES {
        return Err(EvidenceError::Invalid("runner document exceeds byte bound"));
    }
    let declared = validate_runner_declaration(config_raw, expected_config_digest)
        .map_err(|_| EvidenceError::Invalid("invalid caller-pinned runner declaration"))?;
    let config = declared.record.value();
    if declared.version >= 5
        && !config["runtime"]["guard_package_version"]
            .as_str()
            .is_some_and(valid_package_version)
    {
        return Err(EvidenceError::Invalid(
            "invalid frozen Guard package version",
        ));
    }
    if sha256(campaign_raw) != config["campaign"]["sha256"]
        || sha256(policy_raw) != config["policy"]["sha256"]
    {
        return Err(EvidenceError::Invalid(
            "campaign or policy bytes differ from caller pins",
        ));
    }
    let campaign = decode_document(campaign_raw)?;
    verify_campaign(&campaign)?;
    let inventory = campaign["inventory"]
        .as_array()
        .ok_or(EvidenceError::Invalid("campaign inventory missing"))?;
    let by_id: BTreeMap<&str, &Value> = inventory
        .iter()
        .filter_map(|cell| cell["id"].as_str().map(|id| (id, cell)))
        .collect();
    let selection = config["selection"]
        .as_array()
        .ok_or(EvidenceError::Invalid("runner selection missing"))?;
    let ids: Vec<&str> = selection
        .iter()
        .map(|id| {
            id.as_str()
                .ok_or(EvidenceError::Invalid("invalid selected episode ID"))
        })
        .collect::<Result<_>>()?;
    if ids.len() != ids.iter().copied().collect::<BTreeSet<_>>().len()
        || ids.iter().any(|id| !by_id.contains_key(id))
    {
        return Err(EvidenceError::Invalid(
            "selected episodes differ from campaign",
        ));
    }
    let selected: Vec<&Value> = ids.iter().map(|id| by_id[id]).collect();
    let policy = bind_gate_policy(
        policy_raw,
        &selected
            .iter()
            .map(|cell| (*cell).clone())
            .collect::<Vec<_>>(),
    )
    .map_err(|_| EvidenceError::Invalid("policy differs from selected campaign"))?;
    validate_protocol_mapping(config, &selected)?;
    let budgets = &campaign["budgets"];
    let campaign_tokens = budget(budgets, "campaign_tokens")?;
    let campaign_seconds = budget(budgets, "campaign_seconds")?;
    let retries = budget(budgets, "max_retries")?;
    if budget(budgets, "concurrency")? != 1
        || retries > 1
        || campaign_tokens > config["provider"]["token_cap"].as_u64().unwrap_or(0)
        || budget(budgets, "tool_timeout_seconds")? != 30
    {
        return Err(EvidenceError::Invalid(
            "unbounded or nonserial campaign budget",
        ));
    }
    let mut planned = ReservationTotals {
        model_tokens: 0,
        tool_operations: 0,
        controller_seconds: 0,
    };
    for cell in &selected {
        planned = planned
            .add(reservation(cell, budgets)?)
            .ok_or(EvidenceError::Invalid("campaign reservations overflow"))?;
    }
    planned = planned
        .times(retries + 1)
        .ok_or(EvidenceError::Invalid("campaign reservations overflow"))?;
    if planned.model_tokens > campaign_tokens || planned.controller_seconds > campaign_seconds {
        return Err(EvidenceError::Invalid(
            "selected campaign exceeds reservations",
        ));
    }
    let shard_count = config["shards"]
        .as_u64()
        .ok_or(EvidenceError::Invalid("invalid shard count"))? as usize;
    let mut shards = vec![Vec::new(); shard_count];
    for (index, id) in ids.iter().enumerate() {
        shards[index % shard_count].push((*id).to_owned());
    }
    Ok(VerifiedRunnerInputs {
        version: declared.version,
        config: declared.record,
        campaign,
        policy,
        selection_reservations: planned,
        shards,
        attempt_layout: if declared.version >= 4 {
            "compact-v1"
        } else {
            "legacy-v1"
        },
    })
}

/// Read a literal config and its pinned campaign/policy below distinct roots.
/// No candidate executable, SDK, model or product file is opened here.
pub fn verify_runner_inputs_from_paths(
    config_path: &Path,
    expected_config_digest: &str,
    asset_root: &Path,
) -> Result<VerifiedRunnerInputs> {
    let parent = config_path.parent().ok_or(EvidenceError::Invalid(
        "runner config needs an absolute parent",
    ))?;
    let name = config_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(EvidenceError::Invalid("runner config filename is invalid"))?;
    let config_raw = PublicRootReader::open(parent)?.read_file(name, MAX_RECORD_BYTES)?;
    let declared = validate_runner_declaration(&config_raw, expected_config_digest)
        .map_err(|_| EvidenceError::Invalid("invalid caller-pinned runner declaration"))?;
    let assets = PublicRootReader::open(asset_root)?;
    let campaign_path = declared.record.value()["campaign"]["path"]
        .as_str()
        .ok_or(EvidenceError::Invalid("campaign path missing"))?;
    let policy_path = declared.record.value()["policy"]["path"]
        .as_str()
        .ok_or(EvidenceError::Invalid("policy path missing"))?;
    let campaign_raw = assets.read_file(campaign_path, MAX_RECORD_BYTES)?;
    let policy_raw = assets.read_file(policy_path, MAX_RECORD_BYTES)?;
    verify_runner_inputs(
        &config_raw,
        expected_config_digest,
        &campaign_raw,
        &policy_raw,
    )
}

/// Hash only declared ordinary file assets as inert bytes. Tree, installed
/// prefix and private-cell inventories remain separate required checks.
pub fn verify_runner_file_assets(
    inputs: &VerifiedRunnerInputs,
    asset_root: &Path,
) -> Result<BTreeMap<String, String>> {
    let reader = PublicRootReader::open(asset_root)?;
    let mut observed = BTreeMap::new();
    for (role, row) in inputs.config.value()["assets"]
        .as_object()
        .ok_or(EvidenceError::Invalid("asset declarations missing"))?
    {
        if row["kind"] != "file" {
            continue;
        }
        let path = row["path"]
            .as_str()
            .ok_or(EvidenceError::Invalid("asset path missing"))?;
        let digest = reader.file_digest(
            path,
            matches!(role.as_str(), "bun" | "node" | "native" | "compiler"),
        )?;
        if row["sha256"] != digest {
            return Err(EvidenceError::Invalid("file asset differs from its pin"));
        }
        observed.insert(role.clone(), digest);
    }
    Ok(observed)
}
