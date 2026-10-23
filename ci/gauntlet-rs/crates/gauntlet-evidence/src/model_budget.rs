//! Signed provider relay accounting for the fixed Python v1 record.
//! The public key and source hashes must come from outside the candidate.

use crate::crypto::{is_sha256, sha256};
use crate::io::open_absolute_directory;
use crate::model_endpoint::verify_model_endpoint;
use crate::{verify_controller_envelope, EvidenceError, Result};
use rustix::fs::{fstat, openat, FileType, Mode, OFlags};
use serde_json::{json, Map, Value};
use std::fs::File;
use std::io::Read;
use std::path::Path;

const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_ROWS: usize = 3_000;
const SOURCE_NAMES: [&str; 4] = [
    "developer_budget.py",
    "developer_model_relay.py",
    "business_model_budget.py",
    "model_endpoint.py",
];

fn invalid() -> EvidenceError {
    EvidenceError::Invalid("invalid signed model budget")
}

fn object(value: &Value) -> Result<&Map<String, Value>> {
    value.as_object().ok_or_else(invalid)
}

fn field<'a>(value: &'a Map<String, Value>, name: &str) -> Result<&'a Value> {
    value.get(name).ok_or_else(invalid)
}

fn text<'a>(value: &'a Map<String, Value>, name: &str) -> Result<&'a str> {
    field(value, name)?.as_str().ok_or_else(invalid)
}

fn natural(value: &Map<String, Value>, name: &str) -> Result<u64> {
    field(value, name)?.as_u64().ok_or_else(invalid)
}

fn flag(value: &Map<String, Value>, name: &str) -> Result<bool> {
    field(value, name)?.as_bool().ok_or_else(invalid)
}

fn sources_valid(value: &Value, legacy: bool, protocol: bool, agent: bool) -> Result<()> {
    let sources = object(value)?;
    let mut names = SOURCE_NAMES[..if legacy { 3 } else { 4 }].to_vec();
    if protocol {
        names.extend(["mcp_protocol_campaign.py", "mcp_protocol_profiles.py"]);
    }
    if agent {
        names.push("mcp_agent_profile.py");
    }
    if sources.len() != names.len()
        || names.iter().any(|name| {
            !sources
                .get(*name)
                .and_then(Value::as_str)
                .is_some_and(is_sha256)
        })
    {
        return Err(invalid());
    }
    Ok(())
}

fn protocol_profile_valid(value: &Value) -> Result<()> {
    let profile = object(value)?;
    if profile.len() != 2
        || text(profile, "schema")? != "gauntlet-mcp-protocol-profile.v1"
        || !matches!(
            text(profile, "id")?,
            "clean"
                | "tool-description"
                | "misleading-annotations"
                | "schema-change"
                | "tool-list-change"
                | "resource-link"
                | "structured-content"
                | "resource-read"
                | "prompt-get"
                | "reconnect-schema"
                | "server-identity-collision"
                | "error-content"
        )
    {
        return Err(invalid());
    }
    Ok(())
}

fn sampling_valid(row: &Map<String, Value>) -> Result<()> {
    let Some(sample) = row.get("generation_parameters") else {
        return Ok(());
    };
    for (name, value) in object(sample)? {
        if !matches!(
            name.as_str(),
            "temperature"
                | "top_p"
                | "top_k"
                | "min_p"
                | "seed"
                | "max_tokens"
                | "max_completion_tokens"
                | "repetition_penalty"
                | "presence_penalty"
                | "frequency_penalty"
        ) || !(value.is_null() || value.is_number())
        {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Verify an 8-MiB-bounded signed controller record and recompute provider
/// cost from ordered request/response rows. Optional MCP profile declarations
/// are validated here; effect and exposure scoring remain separate.
#[allow(clippy::too_many_arguments)]
pub fn verify_signed_model_budget(
    envelope_bytes: &[u8],
    external_public_key: &[u8],
    model_id: &str,
    max_tokens: u64,
    config_digest: Option<&str>,
    maximum_requests: Option<u64>,
    expected_sources: &Value,
    base_url: &str,
) -> Result<Value> {
    if envelope_bytes.len() > MAX_BYTES || model_id.is_empty() || max_tokens == 0 {
        return Err(invalid());
    }
    let record = verify_controller_envelope(envelope_bytes, external_public_key)?;
    let record = object(&record)?;
    if text(record, "schema")? != "gauntlet-business-model-budget.v1"
        || !matches!(
            text(record, "mode")?,
            "provider-relay" | "not-launched" | "relay-startup-incomplete"
        )
        || flag(record, "sdk_stdout_authoritative")?
        || flag(record, "qualification")?
        || config_digest
            .is_some_and(|digest| record.get("public_config_digest") != Some(&json!(digest)))
    {
        return Err(invalid());
    }
    let provider = field(record, "provider")?;
    let legacy = provider == &json!({"host":"192.168.5.2","port":8001});
    verify_model_endpoint(if legacy { None } else { Some(provider) }, base_url)?;
    let protocol = record.get("mcp_protocol_profile");
    if let Some(profile) = protocol {
        protocol_profile_valid(profile)?;
    }
    let agent = record.get("mcp_agent_surfaces");
    if agent.is_some_and(|value| value.as_str() != Some("mcp-agent-surfaces.v1")) {
        return Err(invalid());
    }
    let sources = field(record, "sources")?;
    sources_valid(sources, legacy, protocol.is_some(), agent.is_some())?;
    if sources != expected_sources {
        return Err(invalid());
    }
    let budget = object(field(record, "budget")?)?;
    if text(record, "mode")? == "provider-relay"
        && agent.is_some_and(|profile| budget.get("mcp_agent_surfaces") != Some(profile))
    {
        return Err(invalid());
    }
    if !legacy {
        verify_model_endpoint(budget.get("provider").or(Some(provider)), base_url)?;
    }
    let declared_limit = natural(budget, "maximum_requests")?;
    let usage_known = flag(budget, "usage_known")?;
    let budget_cleanup = flag(budget, "cleanup_complete")?;
    if text(budget, "model_id")? != model_id
        || natural(budget, "max_tokens")? != max_tokens
        || !(1..=1_000).contains(&declared_limit)
        || maximum_requests.is_some_and(|limit| declared_limit != limit)
    {
        return Err(invalid());
    }
    let cleanup_fields = object(field(record, "cleanup")?)?;
    const CLEANUP: [&str; 3] = [
        "server_thread_stopped",
        "socket_removed",
        "connections_drained",
    ];
    if cleanup_fields.len() != CLEANUP.len() {
        return Err(invalid());
    }
    let cleanup_observed = CLEANUP.iter().try_fold(true, |all, name| {
        let observed = flag(cleanup_fields, name)?;
        Ok::<bool, EvidenceError>(all && observed)
    })?;
    let cleanup = budget_cleanup && cleanup_observed;
    let rows = field(budget, "records")?.as_array().ok_or_else(invalid)?;
    if rows.len() > MAX_ROWS {
        return Err(invalid());
    }
    let mut requests = 0_u64;
    let mut responses = 0_u64;
    let mut total = 0_u64;
    let mut pending = None;
    let mut all_complete = true;
    for (index, row) in rows.iter().enumerate() {
        let row = object(row)?;
        if natural(row, "sequence")? != (index + 1) as u64 || text(row, "model_id")? != model_id {
            return Err(invalid());
        }
        match text(row, "kind")? {
            "model-request" => {
                sampling_valid(row)?;
                let id = natural(row, "model_request_id")?;
                if pending.is_some()
                    || id != requests + 1
                    || total >= max_tokens
                    || !all_complete
                    || requests >= declared_limit
                {
                    return Err(invalid());
                }
                requests += 1;
                pending = Some(id);
            }
            "model-response" => {
                let method = text(row, "method")?;
                let tokens = match field(row, "provider_tokens")? {
                    Value::Null => None,
                    value => Some(
                        value
                            .as_u64()
                            .filter(|tokens| *tokens > 0)
                            .ok_or_else(invalid)?,
                    ),
                };
                let status = match field(row, "status")? {
                    Value::Null => None,
                    value => Some(
                        value
                            .as_u64()
                            .filter(|status| (100..=599).contains(status))
                            .ok_or_else(invalid)?,
                    ),
                };
                let error = field(row, "error")?;
                if !error.is_null() && !error.is_string() {
                    return Err(invalid());
                }
                let complete = flag(row, "complete")?;
                if method == "GET" {
                    if tokens.is_some() || !field(row, "model_request_id")?.is_null() {
                        return Err(invalid());
                    }
                } else if method == "POST" {
                    let id = natural(row, "model_request_id")?;
                    if pending != Some(id) {
                        return Err(invalid());
                    }
                    responses += 1;
                    pending = None;
                    total = total.checked_add(tokens.unwrap_or(0)).ok_or_else(invalid)?;
                } else {
                    return Err(invalid());
                }
                if natural(row, "cumulative_tokens")? != total {
                    return Err(invalid());
                }
                all_complete &= complete
                    && status == Some(200)
                    && error.is_null()
                    && (method == "GET" || tokens.is_some());
            }
            _ => return Err(invalid()),
        }
    }
    if natural(budget, "model_requests")? != requests
        || natural(budget, "observed_tokens")? != total
    {
        return Err(invalid());
    }
    if text(record, "mode")? == "not-launched" && (!rows.is_empty() || total != 0 || !cleanup) {
        return Err(invalid());
    }
    let complete = pending.is_none() && requests == responses && all_complete && cleanup;
    if usage_known && !complete && cleanup {
        return Err(invalid());
    }
    let overrun = total.saturating_sub(max_tokens);
    if natural(budget, "threshold_overrun")? != overrun {
        return Err(invalid());
    }
    Ok(json!({
        "observed_model_tokens": total,
        "model_usage_known": complete && usage_known,
        "model_requests": requests,
        "inference_started": requests > 0,
        "token_threshold_overrun": overrun,
        "budget_exhausted": total >= max_tokens,
        "cleanup_complete": cleanup,
        "model_budget_authority": "controller-provider-relay",
        "zero_model_requests_proven": requests == 0 && complete && usage_known,
    }))
}

/// Read one immutable-looking retained budget through no-symlink ancestry and
/// verify an outside byte digest before signature/accounting checks. File owner
/// and the origin of the digest/key remain separate caller obligations.
#[allow(clippy::too_many_arguments)]
pub fn read_signed_model_budget(
    path: &Path,
    expected_sha256: &str,
    external_public_key: &[u8],
    model_id: &str,
    max_tokens: u64,
    config_digest: Option<&str>,
    maximum_requests: Option<u64>,
    expected_sources: &Value,
    base_url: &str,
) -> Result<Value> {
    if !is_sha256(expected_sha256)
        || path.file_name().and_then(|name| name.to_str()) != Some("model-budget.json")
    {
        return Err(EvidenceError::Invalid(
            "outside model-budget digest or fixed filename missing",
        ));
    }
    let parent = path.parent().ok_or(EvidenceError::Invalid(
        "absolute model-budget path required",
    ))?;
    let directory = open_absolute_directory(parent)?;
    let fd = openat(
        &directory,
        "model-budget.json",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| EvidenceError::Io(error.to_string()))?;
    let before = fstat(&fd).map_err(|error| EvidenceError::Io(error.to_string()))?;
    if !FileType::from_raw_mode(before.st_mode).is_file()
        || before.st_size < 0
        || before.st_size as usize > MAX_BYTES
        || before.st_nlink != 1
    {
        return Err(EvidenceError::Invalid(
            "nonregular or oversized model-budget file",
        ));
    }
    let mut file = File::from(fd);
    let mut raw = Vec::with_capacity(before.st_size as usize);
    file.by_ref()
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|error| EvidenceError::Io(error.to_string()))?;
    let after = fstat(&file).map_err(|error| EvidenceError::Io(error.to_string()))?;
    if raw.len() != before.st_size as usize
        || raw.len() > MAX_BYTES
        || after.st_size != before.st_size
        || after.st_ino != before.st_ino
        || after.st_dev != before.st_dev
        || after.st_nlink != 1
    {
        return Err(EvidenceError::Invalid(
            "model-budget file changed while read",
        ));
    }
    if sha256(&raw) != expected_sha256 {
        return Err(EvidenceError::Invalid("model-budget SHA-256 differs"));
    }
    verify_signed_model_budget(
        &raw,
        external_public_key,
        model_id,
        max_tokens,
        config_digest,
        maximum_requests,
        expected_sources,
        base_url,
    )
}
