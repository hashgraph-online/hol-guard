//! Match a signed staging control's declared agent container PID/start tick
//! with a bounded kernel sample retained by the Rust owner. This establishes
//! one live container-process identity, not SDK, Native or Guard causality.

use crate::crypto::{decode_hex, is_sha256, sha256};
use crate::io::open_absolute_directory;
use crate::python_worker_files::{private_directory, read_private_file};
use crate::staging_control_record::read_one;
use crate::staging_suite::{cgroup_targets, require_absent_cgroup};
use crate::{
    observe_staging_physical_files_root_owned_ineligible, EvidenceError, Result,
    StagingEvidencePins,
};
use crate::{verify_controller_envelope, verify_product_kernel_identity};
use gauntlet_contracts::canonicalize;
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const STAGING: &str = "/var/lib/hol-gauntlet-rust/staging-state";
const INVALID: EvidenceError = EvidenceError::Invalid("invalid live staging agent process");
const SDK_ARGV: &[u8] =
    b"/runtime/bun\0/runtime/public/private_cell_sdk_conformance.ts\0/runtime/public/episode.json";

#[derive(Debug, Clone, Copy)]
pub struct StagingAgentProcessPins<'a> {
    pub evidence: StagingEvidencePins<'a>,
    pub worker_generation_sha256: &'a str,
    pub started_marker_sha256: &'a str,
    pub controller_key_pin_sha256: &'a str,
    pub report_sha256: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingAgentProcessShadow {
    pub run_id: String,
    pub record_sha256: String,
    pub report_sha256: String,
    pub container_id: String,
    pub agent_pid: u32,
    pub agent_start_ticks: u64,
    pub sampled_container_processes: usize,
}

impl StagingAgentProcessShadow {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-staging-agent-process-shadow.v1",
            "run_id":self.run_id,
            "record_sha256":self.record_sha256,
            "report_sha256":self.report_sha256,
            "container_id":self.container_id,
            "agent_pid":self.agent_pid,
            "agent_start_ticks":self.agent_start_ticks,
            "sampled_container_processes":self.sampled_container_processes,
            "caller_host_prelaunch_fields_matched":true,
            "agent_kernel_identity_matched":true,
            "independent_sdk_native_guard_causality_verified":false,
            "execution_eligible":false,
        })
    }
}

fn exact_keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
    })
}

fn positive_decimal(raw: &str) -> Option<u64> {
    if raw.is_empty() || raw.len() > 20 || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    raw.parse::<u64>().ok().filter(|value| *value > 0)
}

fn private_mcp_mounts(value: &Value) -> bool {
    let Some(mounts) = value.as_array() else {
        return false;
    };
    if mounts.len() != 5 {
        return false;
    }
    let mut destinations = BTreeMap::new();
    for mount in mounts {
        if !exact_keys(mount, &["source", "destination", "mode"]) {
            return false;
        }
        for field in ["source", "destination"] {
            let Some(path) = mount[field].as_str() else {
                return false;
            };
            if !path.starts_with('/')
                || path.split('/').any(|part| part == "..")
                || path.chars().any(|ch| matches!(ch, '\0' | '\n' | ':'))
            {
                return false;
            }
        }
        let Some(destination) = mount["destination"].as_str() else {
            return false;
        };
        if destinations.insert(destination, mount).is_some() {
            return false;
        }
    }
    for (destination, mode) in [
        ("/product/public", "ro"),
        ("/product/home", "rw"),
        ("/product/guard", "rw"),
        ("/upstream", "ro"),
    ] {
        if destinations
            .get(destination)
            .is_none_or(|mount| mount["mode"] != mode)
        {
            return false;
        }
    }
    let remaining: Vec<_> = destinations
        .iter()
        .filter(|(destination, _)| {
            !matches!(
                **destination,
                "/product/public" | "/product/home" | "/product/guard" | "/upstream"
            )
        })
        .collect();
    remaining.len() == 1
        && remaining[0].1["source"] == *remaining[0].0
        && remaining[0].1["mode"] == "ro"
}

pub(crate) fn matching_agent_process(
    record: &Value,
    activity: &Value,
) -> Result<(String, u32, u64, usize)> {
    let container_id = record["agent_container_inspection"]["Id"]
        .as_str()
        .filter(|value| is_sha256(value))
        .ok_or(INVALID)?;
    let pid = record["agent_container_inspection"]["State"]["Pid"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or(INVALID)?;
    let start_ticks = record["agent_identity"]["start_time"]
        .as_str()
        .and_then(positive_decimal)
        .ok_or(INVALID)?;
    let sdk_executable_samples = activity["schema"] == "hol-gauntlet-staging-kernel-samples.v3";
    let mut fields = vec![
        "schema",
        "sample_count",
        "max_controller_tasks",
        "product_slice_observed",
        "product_slice_populated",
        "max_product_tasks",
        "container_processes",
        "container_processes_exhaustively_observed",
        "control_processes_exhaustively_observed",
        "guard_causality_verified",
        "execution_eligible",
    ];
    if sdk_executable_samples {
        fields.push("sdk_executables");
    }
    if !exact_keys(activity, &fields)
        || (!sdk_executable_samples
            && activity["schema"] != "hol-gauntlet-staging-kernel-samples.v2")
        || activity["sample_count"]
            .as_u64()
            .is_none_or(|count| !(1..=10_000).contains(&count))
        || activity["max_controller_tasks"]
            .as_u64()
            .is_none_or(|count| !(1..=256).contains(&count))
        || activity["product_slice_observed"] != true
        || activity["product_slice_populated"] != true
        || activity["max_product_tasks"]
            .as_u64()
            .is_none_or(|count| !(1..=1_000_000).contains(&count))
        || activity["container_processes_exhaustively_observed"] != false
        || activity["control_processes_exhaustively_observed"] != false
        || activity["guard_causality_verified"] != false
        || activity["execution_eligible"] != false
    {
        return Err(INVALID);
    }
    let rows = activity["container_processes"].as_array().ok_or(INVALID)?;
    if rows.is_empty() || rows.len() > 64 {
        return Err(INVALID);
    }
    let mut seen = BTreeSet::new();
    let mut matched = 0;
    for row in rows {
        if !exact_keys(row, &["container_id", "pid", "start_ticks", "cgroup"]) {
            return Err(INVALID);
        }
        let id = row["container_id"]
            .as_str()
            .filter(|value| is_sha256(value))
            .ok_or(INVALID)?;
        let observed_pid = row["pid"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or(INVALID)?;
        let observed_start = row["start_ticks"]
            .as_u64()
            .filter(|value| *value > 0)
            .ok_or(INVALID)?;
        let expected_cgroup = format!("/machine.slice/libpod-{id}.scope/container");
        if row["cgroup"] != expected_cgroup || !seen.insert((id, observed_pid, observed_start)) {
            return Err(INVALID);
        }
        if id == container_id && observed_pid == pid && observed_start == start_ticks {
            matched += 1;
        }
    }
    if matched != 1 {
        return Err(INVALID);
    }
    if sdk_executable_samples {
        let sdk_rows = activity["sdk_executables"].as_array().ok_or(INVALID)?;
        if sdk_rows.len() > 16 {
            return Err(INVALID);
        }
        let mut sdk_seen = BTreeSet::new();
        for row in sdk_rows {
            if !exact_keys(
                row,
                &[
                    "container_id",
                    "pid",
                    "start_ticks",
                    "cgroup",
                    "argv_sha256",
                    "executable_sha256",
                ],
            ) {
                return Err(INVALID);
            }
            let id = row["container_id"]
                .as_str()
                .filter(|id| is_sha256(id))
                .ok_or(INVALID)?;
            let pid = row["pid"]
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok())
                .filter(|pid| *pid > 0)
                .ok_or(INVALID)?;
            let start = row["start_ticks"]
                .as_u64()
                .filter(|start| *start > 0)
                .ok_or(INVALID)?;
            if row["cgroup"] != format!("/machine.slice/libpod-{id}.scope/container")
                || !seen.contains(&(id, pid, start))
                || !sdk_seen.insert((id, pid, start))
                || row["argv_sha256"]
                    .as_str()
                    .is_none_or(|hash| !is_sha256(hash))
                || row["executable_sha256"]
                    .as_str()
                    .is_none_or(|hash| !is_sha256(hash))
            {
                return Err(INVALID);
            }
        }
    }
    Ok((container_id.to_owned(), pid, start_ticks, rows.len()))
}

/// The SDK gate's producer-declared process must be a second, distinct live
/// process in the same sampled Podman scope. The sample does not authenticate
/// its executable or establish that an SDK tool call occurred.
pub(crate) fn matching_sdk_gate_process(record: &Value, activity: &Value) -> Result<(u32, u64)> {
    let (container_id, agent_pid, _, _) = matching_agent_process(record, activity)?;
    let pid = record["sdk_gate"]["observation"]["pid"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0 && *value != agent_pid)
        .ok_or(INVALID)?;
    let start_ticks = record["sdk_gate"]["observation"]["identity"]["start_time"]
        .as_str()
        .and_then(positive_decimal)
        .ok_or(INVALID)?;
    let cgroup = format!("/machine.slice/libpod-{container_id}.scope/container");
    let matches = activity["container_processes"]
        .as_array()
        .ok_or(INVALID)?
        .iter()
        .filter(|row| {
            row["container_id"] == container_id
                && row["pid"] == pid
                && row["start_ticks"] == start_ticks
                && row["cgroup"] == cgroup
        })
        .count();
    if matches != 1 {
        return Err(INVALID);
    }
    Ok((pid, start_ticks))
}

/// Require the Rust owner's live kernel executable bytes and complete Bun
/// command to match an outside-pinned asset hash for the signed gate process.
/// This is process identity, not proof of an SDK tool call or Guard decision.
pub(crate) fn matching_sdk_executable(
    record: &Value,
    activity: &Value,
    expected_bun_sha256: &str,
) -> Result<()> {
    if activity["schema"] != "hol-gauntlet-staging-kernel-samples.v3"
        || !is_sha256(expected_bun_sha256)
    {
        return Err(INVALID);
    }
    let (pid, start_ticks) = matching_sdk_gate_process(record, activity)?;
    let container_id = record["agent_container_inspection"]["Id"]
        .as_str()
        .ok_or(INVALID)?;
    let cgroup = format!("/machine.slice/libpod-{container_id}.scope/container");
    let count = activity["sdk_executables"]
        .as_array()
        .ok_or(INVALID)?
        .iter()
        .filter(|row| {
            row["container_id"] == container_id
                && row["pid"] == pid
                && row["start_ticks"] == start_ticks
                && row["cgroup"] == cgroup
                && row["argv_sha256"] == sha256(SDK_ARGV)
                && row["executable_sha256"] == expected_bun_sha256
        })
        .count();
    if count != 1 {
        return Err(INVALID);
    }
    Ok(())
}

fn matching_verified_native_mcp_processes(
    audit: &Value,
    activity: &Value,
    agent_container_id: &str,
    agent_identity: &Value,
) -> Result<(String, usize)> {
    if !exact_keys(
        audit,
        &[
            "schema_version",
            "kind",
            "collected_at",
            "product_plane",
            "product_events_self_reported",
            "product_claims_authenticated",
            "transport_observations",
            "active_children",
            "active_sessions",
            "qualification_eligible",
        ],
    ) || audit["kind"] != "isolated-native-mcp-observation"
        || audit["schema_version"] != "1.0"
        || audit["collected_at"]
            .as_u64()
            .is_none_or(|value| value == 0)
        || audit["active_children"] != 0
        || audit["active_sessions"] != 0
        || audit["qualification_eligible"] != false
        || audit["product_claims_authenticated"] != false
        || audit["product_events_self_reported"]
            .as_array()
            .is_none_or(|events| events.len() > 1_000)
    {
        return Err(INVALID);
    }
    let plane = &audit["product_plane"];
    if !exact_keys(
        plane,
        &[
            "schema_version",
            "kind",
            "container",
            "image_id",
            "source_sha_expected",
            "uid",
            "prefix_digest",
            "prefix_unchanged",
            "controller_identity",
            "observations",
            "product_identity_claim",
            "product_claims_authenticated",
            "cleanup_complete",
            "cleanup_errors",
            "audit_error",
            "qualification_eligible",
        ],
    ) || plane["kind"] != "isolated-product-plane.v2"
        || plane["schema_version"] != "2.0"
        || plane["uid"] != 10005
        || plane["prefix_unchanged"] != true
        || plane["controller_identity"]["effective_uid"] != 0
        || plane["cleanup_complete"] != true
        || plane["cleanup_errors"] != json!([])
        || !plane["audit_error"].is_null()
        || plane["qualification_eligible"] != false
        || plane["product_claims_authenticated"] != false
        || plane["container"]
            .as_str()
            .is_none_or(|name| !name.starts_with("native-product-"))
    {
        return Err(INVALID);
    }
    let observations = plane["observations"].as_array().ok_or(INVALID)?;
    if observations.len() != 3 || observations[0]["kind"] != "container-boundary" {
        return Err(INVALID);
    }
    if !exact_keys(&observations[0], &["kind", "identity", "mounts"]) {
        return Err(INVALID);
    }
    let boundary_identity = &observations[0]["identity"];
    if verify_product_kernel_identity(
        boundary_identity,
        &plane["controller_identity"],
        Some(agent_identity),
        10005,
    )
    .is_err()
        || !private_mcp_mounts(&observations[0]["mounts"])
    {
        return Err(INVALID);
    }
    let boundary_start = boundary_identity["start_time"]
        .as_str()
        .and_then(positive_decimal)
        .ok_or(INVALID)?;
    let rows = activity["container_processes"].as_array().ok_or(INVALID)?;
    let boundary_rows: Vec<_> = rows
        .iter()
        .filter(|row| {
            row["container_id"] != agent_container_id && row["start_ticks"] == boundary_start
        })
        .collect();
    if boundary_rows.len() != 1 {
        return Err(INVALID);
    }
    let product_container_id = boundary_rows[0]["container_id"]
        .as_str()
        .filter(|id| is_sha256(id))
        .ok_or(INVALID)?;
    let expected_cgroup = format!("/machine.slice/libpod-{product_container_id}.scope/container");
    if boundary_rows[0]["cgroup"] != expected_cgroup {
        return Err(INVALID);
    }
    let mut proxy_pids = BTreeSet::new();
    let mut proxies = BTreeMap::new();
    for observation in &observations[1..] {
        if !exact_keys(
            observation,
            &[
                "kind",
                "session_id",
                "family",
                "host_exec_pid",
                "product_pid",
                "identity",
            ],
        ) || observation["kind"] != "proxy-process"
        {
            return Err(INVALID);
        }
        let session = observation["session_id"].as_str().ok_or(INVALID)?;
        let host_exec_pid = observation["host_exec_pid"]
            .as_u64()
            .filter(|value| *value > 0)
            .ok_or(INVALID)?;
        let pid = observation["product_pid"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or(INVALID)?;
        let start = observation["identity"]["start_time"]
            .as_str()
            .and_then(positive_decimal)
            .ok_or(INVALID)?;
        if !proxy_pids.insert(pid)
            || proxies
                .insert(session, (host_exec_pid, observation))
                .is_some()
            || verify_product_kernel_identity(
                &observation["identity"],
                &plane["controller_identity"],
                Some(agent_identity),
                10005,
            )
            .is_err()
            || [
                "boot_id",
                "effective_uid",
                "effective_gid",
                "mount_namespace",
                "network_namespace",
                "pid_namespace",
                "no_new_privileges",
            ]
            .iter()
            .any(|field| {
                observation["identity"][field].is_null()
                    || observation["identity"][field] != boundary_identity[field]
            })
            || rows
                .iter()
                .filter(|row| {
                    row["container_id"] == product_container_id
                        && row["pid"] == pid
                        && row["start_ticks"] == start
                        && row["cgroup"] == expected_cgroup
                })
                .count()
                != 1
        {
            return Err(INVALID);
        }
    }
    let events = audit["transport_observations"].as_array().ok_or(INVALID)?;
    if events.is_empty() || events.len() > 100_000 {
        return Err(INVALID);
    }
    let mut run_ids = BTreeSet::new();
    let mut children = BTreeSet::new();
    let mut authenticated_peers = 0_usize;
    let mut forwarded_tool_calls = 0_usize;
    let mut completed_tool_calls = 0_usize;
    let mut pending = BTreeMap::new();
    // Native sessions and both directions of one session are concurrent.
    // Keep at most one unmatched frame per session and delivery direction;
    // the matching forwarding event must carry the exact same message.
    let mut pending_frames = BTreeMap::new();
    for (index, event) in events.iter().enumerate() {
        if event["sequence"].as_u64() != Some((index + 1) as u64) {
            return Err(INVALID);
        }
        run_ids.insert(event["run_id"].as_str().ok_or(INVALID)?);
        if let Some(session) = event["session_id"].as_str() {
            if pending_frames.keys().any(|(held, _)| held == session)
                && !matches!(
                    event["kind"].as_str(),
                    Some("frame" | "forwarded" | "delivered")
                )
            {
                return Err(INVALID);
            }
        }
        if event["kind"] == "peer-authenticated" {
            if event["peer_uid"] != 10001 || event["allowed_uid"] != 10001 {
                return Err(INVALID);
            }
            authenticated_peers += 1;
        } else if event["kind"] == "child-started" {
            let session = event["session_id"].as_str().ok_or(INVALID)?;
            let (host_exec_pid, proxy) = proxies.get(session).ok_or(INVALID)?;
            if !children.insert(session)
                || event["backend"] != "isolated-product-uid10005"
                || event["pid"] != *host_exec_pid
                || event["product_pid"] != proxy["product_pid"]
                || event["product_identity"] != proxy["identity"]
                || event["family"] != proxy["family"]
            {
                return Err(INVALID);
            }
        } else if matches!(
            event["kind"].as_str(),
            Some("frame" | "forwarded" | "delivered")
        ) {
            let session = event["session_id"].as_str().ok_or(INVALID)?;
            let (_, proxy) = proxies.get(session).ok_or(INVALID)?;
            let message = &event["message"];
            if event["family"] != proxy["family"]
                || message["jsonrpc"] != "2.0"
                || !message.is_object()
            {
                return Err(INVALID);
            }
            if event["kind"] == "frame" {
                let expected = match event["direction"].as_str() {
                    Some("client-to-service") => "forwarded",
                    Some("service-to-client") => "delivered",
                    _ => return Err(INVALID),
                };
                if event["stage"] != "received" {
                    return Err(INVALID);
                }
                let key = (session.to_owned(), expected);
                if pending_frames
                    .insert(key, (event["family"].clone(), message.clone()))
                    .is_some()
                {
                    return Err(INVALID);
                }
                continue;
            }
            let key = (session.to_owned(), event["kind"].as_str().ok_or(INVALID)?);
            let (frame_family, frame_message) = pending_frames.remove(&key).ok_or(INVALID)?;
            if frame_family != event["family"] || frame_message != *message {
                return Err(INVALID);
            }
            let id = message["id"].as_str();
            if event["kind"] == "forwarded" {
                let method = message["method"]
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .ok_or(INVALID)?;
                if let Some(id) = id {
                    if id.is_empty()
                        || id.len() > 128
                        || pending
                            .insert(
                                (session.to_owned(), id.to_owned()),
                                (
                                    proxy["family"].as_str().ok_or(INVALID)?.to_owned(),
                                    method.to_owned(),
                                ),
                            )
                            .is_some()
                    {
                        return Err(INVALID);
                    }
                } else if !message["id"].is_null() {
                    return Err(INVALID);
                }
                if method == "tools/call" {
                    if id.is_none()
                        || event["family"] != "docs"
                        || message["params"]["name"] != "docs.read"
                        || message["params"]["arguments"]["record_id"] != "developer-spec"
                    {
                        return Err(INVALID);
                    }
                    forwarded_tool_calls += 1;
                }
            } else if let Some(id) = id {
                let (family, method) = pending
                    .remove(&(session.to_owned(), id.to_owned()))
                    .ok_or(INVALID)?;
                if event["family"] != family
                    || message["result"].is_object() == message["error"].is_object()
                {
                    return Err(INVALID);
                }
                if method == "tools/call" {
                    if !message["result"]["isError"].is_boolean() {
                        return Err(INVALID);
                    }
                    completed_tool_calls += 1;
                }
            } else if !message["id"].is_null() || message["method"].as_str().is_none() {
                return Err(INVALID);
            }
        }
    }
    if run_ids.len() != 1
        || children.len() != proxies.len()
        || authenticated_peers < children.len()
        || forwarded_tool_calls != 1
        || completed_tool_calls != 1
        || !pending.is_empty()
        || !pending_frames.is_empty()
    {
        return Err(INVALID);
    }
    Ok((product_container_id.to_owned(), proxy_pids.len()))
}

/// Independently sampled Podman tuples must contain the signed Native MCP
/// boundary and both proxy children in one container distinct from the SDK
/// agent. This binds process identity only, not MCP frames or Guard decisions.
pub(crate) fn matching_native_mcp_processes(
    record: &Value,
    activity: &Value,
    outside_public_key_hex: &str,
    outside_source_sha: &str,
    outside_prefix_digest: &str,
    outside_version: &str,
) -> Result<(String, usize)> {
    let (agent_container_id, _, _, _) = matching_agent_process(record, activity)?;
    if record["controller_public_key_hex"] != outside_public_key_hex {
        return Err(INVALID);
    }
    let key = decode_hex(outside_public_key_hex, 32).map_err(|_| INVALID)?;
    let runtime_envelope = serde_json::to_vec(&record["developer_runtime"]).map_err(|_| INVALID)?;
    let runtime = verify_controller_envelope(&runtime_envelope, &key)?;
    let audit_envelope = serde_json::to_vec(&runtime["native_mcp_audit"]).map_err(|_| INVALID)?;
    let audit = verify_controller_envelope(&audit_envelope, &key)?;
    if runtime["settings"]["source_sha"] != outside_source_sha
        || runtime["settings"]["prefix_digest"] != outside_prefix_digest
        || runtime["settings"]["package_version"] != outside_version
        || runtime["settings"]["mcp_identity_profile"] != "private-cell-mcp-v2"
        || audit["product_plane"]["source_sha_expected"] != outside_source_sha
        || audit["product_plane"]["prefix_digest"] != outside_prefix_digest
        || audit["product_plane"]["image_id"] != runtime["settings"]["mcp_image_id"]
        || audit["product_plane"]["product_identity_claim"]["package_version"] != outside_version
        || audit["product_plane"]["product_identity_claim"]["manifest"]["package_version"]
            != outside_version
        || audit["product_plane"]["product_identity_claim"]["capabilities"]["runtime_version"]
            != outside_version
    {
        return Err(INVALID);
    }
    matching_verified_native_mcp_processes(
        &audit,
        activity,
        &agent_container_id,
        &record["agent_identity"],
    )
}

/// The caller supplies the independently retained host prelaunch fields and
/// raw report hash. The signed control is reopened before comparing the
/// producer's agent claim to the Rust owner's live pidfd/cgroup samples.
pub fn observe_staging_agent_process_root_owned_ineligible(
    pins: &StagingAgentProcessPins<'_>,
) -> Result<StagingAgentProcessShadow> {
    if geteuid().as_raw() != 0
        || ![
            pins.worker_generation_sha256,
            pins.started_marker_sha256,
            pins.controller_key_pin_sha256,
            pins.report_sha256,
        ]
        .iter()
        .all(|value| is_sha256(value))
    {
        return Err(INVALID);
    }
    observe_staging_physical_files_root_owned_ineligible(&pins.evidence)?;
    let record_raw = read_one(pins.evidence.run_id, pins.evidence.role)?;
    if sha256(&record_raw) != pins.evidence.record_sha256 {
        return Err(INVALID);
    }
    let record: Value = serde_json::from_slice(&record_raw).map_err(|_| INVALID)?;
    let journal = open_absolute_directory(Path::new(STAGING))?;
    private_directory(&journal, 0)?;
    let report_name = format!("{}.report.json", pins.evidence.run_id);
    let terminal_name = format!("{}.terminal.json", pins.evidence.run_id);
    let report_raw = read_private_file(&journal, &report_name, 0, 16 * 1024)?.ok_or(INVALID)?;
    let terminal_raw = read_private_file(&journal, &terminal_name, 0, 16 * 1024)?.ok_or(INVALID)?;
    if sha256(&report_raw) != pins.report_sha256 {
        return Err(INVALID);
    }
    let report: Value = serde_json::from_slice(&canonicalize(&report_raw).map_err(|_| INVALID)?)
        .map_err(|_| INVALID)?;
    let terminal: Value =
        serde_json::from_slice(&canonicalize(&terminal_raw).map_err(|_| INVALID)?)
            .map_err(|_| INVALID)?;
    if report["schema"] != "hol-gauntlet-staging-control-run-report.v1"
        || report["source_sha"] != pins.evidence.source_sha
        || report["build_job_id"] != pins.evidence.build_job_id
        || report["run_id"] != pins.evidence.run_id
        || report["role"] != pins.evidence.role
        || report["provisional_config_digest"] != pins.evidence.config_digest
        || report["controller_public_key_hex"] != pins.evidence.controller_public_key_hex
        || report["exit_code"] != 0
        || report["timed_out"] != false
        || report["controller_and_product_slice_cleanup_verified"] != true
        || report["post_run_controller_custody"] != true
        || report["record_scored"] != false
        || report["execution_eligible"] != false
        || terminal["schema"] != "hol-gauntlet-worker-terminal.v2"
        || terminal["status"] != "invalid-evidence"
        || terminal["source_sha"] != pins.evidence.source_sha
        || terminal["job_id"] != pins.evidence.run_id
        || terminal["deployment_digest"] != pins.evidence.config_digest
        || terminal["worker_generation"] != pins.worker_generation_sha256
        || terminal["controller_public_key_hex"] != pins.evidence.controller_public_key_hex
        || terminal["controller_key_pin_sha256"] != pins.controller_key_pin_sha256
        || terminal["started_marker_sha256"] != pins.started_marker_sha256
        || terminal["report_sha256"] != pins.report_sha256
        || terminal["exit_code"] != 0
    {
        return Err(INVALID);
    }
    let (container_id, agent_pid, agent_start_ticks, sampled_container_processes) =
        matching_agent_process(&record, &report["live_kernel_activity"])?;
    for (parent, name) in cgroup_targets(pins.evidence.run_id) {
        require_absent_cgroup(Path::new(parent), &name, 0)?;
    }
    if record_raw != read_one(pins.evidence.run_id, pins.evidence.role)?
        || report_raw != read_private_file(&journal, &report_name, 0, 16 * 1024)?.ok_or(INVALID)?
        || terminal_raw
            != read_private_file(&journal, &terminal_name, 0, 16 * 1024)?.ok_or(INVALID)?
    {
        return Err(INVALID);
    }
    Ok(StagingAgentProcessShadow {
        run_id: pins.evidence.run_id.to_owned(),
        record_sha256: pins.evidence.record_sha256.to_owned(),
        report_sha256: pins.report_sha256.to_owned(),
        container_id,
        agent_pid,
        agent_start_ticks,
        sampled_container_processes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_agent_claim_must_match_one_live_kernel_tuple() {
        let id = "a".repeat(64);
        let record = json!({
            "agent_container_inspection":{"Id":id,"State":{"Pid":123}},
            "agent_identity":{"start_time":"456"},
        });
        let mut activity = json!({
            "schema":"hol-gauntlet-staging-kernel-samples.v2",
            "sample_count":5,
            "max_controller_tasks":2,
            "product_slice_observed":true,
            "product_slice_populated":true,
            "max_product_tasks":3,
            "container_processes_exhaustively_observed":false,
            "control_processes_exhaustively_observed":false,
            "guard_causality_verified":false,
            "execution_eligible":false,
            "container_processes":[{
                "container_id":id,
                "pid":123,
                "start_ticks":456,
                "cgroup":format!("/machine.slice/libpod-{}.scope/container", "a".repeat(64)),
            }],
        });
        assert!(matching_agent_process(&record, &activity).is_ok());
        activity["container_processes"][0]["start_ticks"] = json!(457);
        assert!(matching_agent_process(&record, &activity).is_err());
        activity["container_processes"][0]["start_ticks"] = json!(456);
        activity["container_processes"][0]["cgroup"] = json!("/system.slice/other");
        assert!(matching_agent_process(&record, &activity).is_err());
    }

    #[test]
    fn sdk_gate_requires_a_second_exact_live_process_in_the_agent_scope() {
        let id = "a".repeat(64);
        let record = json!({
            "agent_container_inspection":{"Id":id,"State":{"Pid":123}},
            "agent_identity":{"start_time":"456"},
            "sdk_gate":{"observation":{"pid":124,"identity":{"start_time":"457"}}},
        });
        let cgroup = format!("/machine.slice/libpod-{}.scope/container", "a".repeat(64));
        let mut activity = json!({
            "schema":"hol-gauntlet-staging-kernel-samples.v2",
            "sample_count":5,
            "max_controller_tasks":2,
            "product_slice_observed":true,
            "product_slice_populated":true,
            "max_product_tasks":3,
            "container_processes_exhaustively_observed":false,
            "control_processes_exhaustively_observed":false,
            "guard_causality_verified":false,
            "execution_eligible":false,
            "container_processes":[
                {"container_id":id,"pid":123,"start_ticks":456,"cgroup":cgroup},
                {"container_id":id,"pid":124,"start_ticks":457,"cgroup":cgroup},
            ],
        });
        assert_eq!(
            matching_sdk_gate_process(&record, &activity).unwrap(),
            (124, 457)
        );
        activity["container_processes"][1]["start_ticks"] = json!(458);
        assert!(matching_sdk_gate_process(&record, &activity).is_err());
        activity["container_processes"][1]["start_ticks"] = json!(457);
        activity["container_processes"][1]["cgroup"] = json!("/system.slice/other");
        assert!(matching_sdk_gate_process(&record, &activity).is_err());
    }

    #[test]
    fn sdk_executable_requires_outside_bun_bytes_and_exact_argv() {
        let id = "a".repeat(64);
        let bun = "b".repeat(64);
        let cgroup = format!("/machine.slice/libpod-{id}.scope/container");
        let record = json!({
            "agent_container_inspection":{"Id":id,"State":{"Pid":123}},
            "agent_identity":{"start_time":"456"},
            "sdk_gate":{"observation":{"pid":124,"identity":{"start_time":"457"}}},
        });
        let mut activity = json!({
            "schema":"hol-gauntlet-staging-kernel-samples.v3",
            "sample_count":5,
            "max_controller_tasks":2,
            "product_slice_observed":true,
            "product_slice_populated":true,
            "max_product_tasks":3,
            "container_processes_exhaustively_observed":false,
            "control_processes_exhaustively_observed":false,
            "guard_causality_verified":false,
            "execution_eligible":false,
            "container_processes":[
                {"container_id":id,"pid":123,"start_ticks":456,"cgroup":cgroup},
                {"container_id":id,"pid":124,"start_ticks":457,"cgroup":cgroup},
            ],
            "sdk_executables":[{
                "container_id":id,
                "pid":124,
                "start_ticks":457,
                "cgroup":cgroup,
                "argv_sha256":sha256(SDK_ARGV),
                "executable_sha256":bun,
            }],
        });
        assert!(matching_sdk_executable(&record, &activity, &bun).is_ok());
        assert!(matching_sdk_executable(&record, &activity, &"c".repeat(64)).is_err());
        activity["sdk_executables"][0]["argv_sha256"] = json!("d".repeat(64));
        assert!(matching_sdk_executable(&record, &activity, &bun).is_err());
        activity["sdk_executables"][0]["argv_sha256"] = json!(sha256(SDK_ARGV));
        activity["sdk_executables"][0]["start_ticks"] = json!(458);
        assert!(matching_sdk_executable(&record, &activity, &bun).is_err());
        activity["sdk_executables"][0]["start_ticks"] = json!(457);
        let duplicate = activity["sdk_executables"][0].clone();
        activity["sdk_executables"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert!(matching_sdk_executable(&record, &activity, &bun).is_err());
    }

    #[test]
    fn native_mcp_children_require_one_distinct_sampled_product_scope() {
        let agent_id = "a".repeat(64);
        let product_id = "b".repeat(64);
        let controller = json!({
            "effective_uid":0,
            "boot_id":"test-boot",
            "mount_namespace":"mnt:[1]",
            "network_namespace":"net:[1]",
            "pid_namespace":"pid:[1]",
        });
        let agent = json!({
            "boot_id":"test-boot",
            "mount_namespace":"mnt:[2]",
            "network_namespace":"net:[2]",
            "pid_namespace":"pid:[2]",
        });
        let identity = json!({
            "boot_id":"test-boot",
            "effective_uid":10005,
            "effective_gid":10005,
            "effective_capabilities":"0000000000000000",
            "capability_sets":{
                "CapEff":"0000000000000000","CapPrm":"0000000000000000",
                "CapInh":"0000000000000000","CapBnd":"0000000000000000",
                "CapAmb":"0000000000000000",
            },
            "uid_slots":[10005,10005,10005,10005],
            "gid_slots":[10005,10005,10005,10005],
            "supplementary_groups":[10005],
            "mount_namespace":"mnt:[100]",
            "network_namespace":"net:[101]",
            "pid_namespace":"pid:[102]",
            "no_new_privileges":1,
            "start_time":"100",
        });
        let mut first = identity.clone();
        first["start_time"] = json!("102");
        let mut second = identity.clone();
        second["start_time"] = json!("103");
        let call = json!({
            "jsonrpc":"2.0","id":"call-1","method":"tools/call",
            "params":{"name":"docs.read","arguments":{"record_id":"developer-spec"}},
        });
        let answer = json!({"jsonrpc":"2.0","id":"call-1","result":{"isError":false}});
        let audit = json!({
            "kind":"isolated-native-mcp-observation",
            "schema_version":"1.0",
            "collected_at":1,
            "active_children":0,
            "active_sessions":0,
            "qualification_eligible":false,
            "product_claims_authenticated":false,
            "product_events_self_reported":[],
            "transport_observations":[
                {"kind":"ready","sequence":1,"run_id":"test-run"},
                {"kind":"peer-authenticated","sequence":2,"run_id":"test-run","peer_uid":10001,"allowed_uid":10001},
                {"kind":"peer-authenticated","sequence":3,"run_id":"test-run","peer_uid":10001,"allowed_uid":10001},
                {"kind":"child-started","sequence":4,"run_id":"test-run","session_id":"first","backend":"isolated-product-uid10005","pid":21,"product_pid":12,"product_identity":first,"family":"docs"},
                {"kind":"child-started","sequence":5,"run_id":"test-run","session_id":"second","backend":"isolated-product-uid10005","pid":22,"product_pid":13,"product_identity":second,"family":"mail"},
                {"kind":"frame","sequence":6,"run_id":"test-run","session_id":"first","family":"docs","direction":"client-to-service","stage":"received","message":call},
                {"kind":"forwarded","sequence":7,"run_id":"test-run","session_id":"first","family":"docs","message":call},
                {"kind":"frame","sequence":8,"run_id":"test-run","session_id":"first","family":"docs","direction":"service-to-client","stage":"received","message":answer},
                {"kind":"delivered","sequence":9,"run_id":"test-run","session_id":"first","family":"docs","message":answer},
            ],
            "product_plane":{
                "kind":"isolated-product-plane.v2",
                "schema_version":"2.0",
                "container":"native-product-test",
                "image_id":format!("sha256:{}", "c".repeat(64)),
                "source_sha_expected":"a".repeat(40),
                "uid":10005,
                "prefix_digest":"b".repeat(64),
                "prefix_unchanged":true,
                "controller_identity":controller,
                "cleanup_complete":true,
                "cleanup_errors":[],
                "audit_error":null,
                "qualification_eligible":false,
                "product_claims_authenticated":false,
                "product_identity_claim":{},
                "observations":[
                    {"kind":"container-boundary","identity":identity,"mounts":[
                        {"source":"/prefix","destination":"/prefix","mode":"ro"},
                        {"source":"/source/public","destination":"/product/public","mode":"ro"},
                        {"source":"/source/home","destination":"/product/home","mode":"rw"},
                        {"source":"/source/guard","destination":"/product/guard","mode":"rw"},
                        {"source":"/source/upstream","destination":"/upstream","mode":"ro"},
                    ]},
                    {"kind":"proxy-process","session_id":"first","family":"docs","host_exec_pid":21,"product_pid":12,"identity":first},
                    {"kind":"proxy-process","session_id":"second","family":"mail","host_exec_pid":22,"product_pid":13,"identity":second},
                ],
            },
        });
        let cgroup = format!("/machine.slice/libpod-{product_id}.scope/container");
        let activity = json!({
            "container_processes":[
                {"container_id":product_id,"pid":10,"start_ticks":100,"cgroup":cgroup},
                {"container_id":product_id,"pid":12,"start_ticks":102,"cgroup":cgroup},
                {"container_id":product_id,"pid":13,"start_ticks":103,"cgroup":cgroup},
            ],
        });
        assert_eq!(
            matching_verified_native_mcp_processes(&audit, &activity, &agent_id, &agent).unwrap(),
            (product_id.clone(), 2)
        );
        let mut interleaved = audit.clone();
        let events = interleaved["transport_observations"]
            .as_array_mut()
            .unwrap();
        let notification = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        events.insert(
            8,
            json!({
                "kind":"frame","run_id":"test-run","session_id":"second",
                "family":"mail","direction":"client-to-service","stage":"received",
                "message":notification,
            }),
        );
        events.insert(
            9,
            json!({
                "kind":"forwarded","run_id":"test-run","session_id":"second",
                "family":"mail","message":notification,
            }),
        );
        for (index, event) in events.iter_mut().enumerate() {
            event["sequence"] = json!(index + 1);
        }
        assert!(
            matching_verified_native_mcp_processes(&interleaved, &activity, &agent_id, &agent)
                .is_ok()
        );
        let mut same_session = interleaved.clone();
        for event in &mut same_session["transport_observations"]
            .as_array_mut()
            .unwrap()[8..10]
        {
            event["session_id"] = json!("first");
            event["family"] = json!("docs");
        }
        assert!(matching_verified_native_mcp_processes(
            &same_session,
            &activity,
            &agent_id,
            &agent
        )
        .is_ok());
        let mut reaped_before_delivery = audit.clone();
        let events = reaped_before_delivery["transport_observations"]
            .as_array_mut()
            .unwrap();
        events.insert(
            8,
            json!({"kind":"child-reaped","run_id":"test-run","session_id":"first"}),
        );
        for (index, event) in events.iter_mut().enumerate() {
            event["sequence"] = json!(index + 1);
        }
        assert!(matching_verified_native_mcp_processes(
            &reaped_before_delivery,
            &activity,
            &agent_id,
            &agent
        )
        .is_err());
        interleaved["transport_observations"][9]["message"]["method"] =
            json!("notifications/changed");
        assert!(
            matching_verified_native_mcp_processes(&interleaved, &activity, &agent_id, &agent)
                .is_err()
        );
        let mut wrong = audit.clone();
        wrong["product_plane"]["observations"][1]["identity"]["start_time"] = json!("104");
        assert!(
            matching_verified_native_mcp_processes(&wrong, &activity, &agent_id, &agent).is_err()
        );
        wrong = audit.clone();
        wrong["product_plane"]["observations"][2]["product_pid"] = json!(12);
        assert!(
            matching_verified_native_mcp_processes(&wrong, &activity, &agent_id, &agent).is_err()
        );
        wrong = audit.clone();
        wrong["product_plane"]["observations"][2]["identity"]["pid_namespace"] = json!("pid:[999]");
        assert!(
            matching_verified_native_mcp_processes(&wrong, &activity, &agent_id, &agent).is_err()
        );
        wrong = audit.clone();
        wrong["product_plane"]["observations"][0]["mounts"][0]["mode"] = json!("rw");
        assert!(
            matching_verified_native_mcp_processes(&wrong, &activity, &agent_id, &agent).is_err()
        );
        wrong = audit.clone();
        wrong["product_plane"]["observations"][1]["identity"]["capability_sets"]["CapBnd"] =
            json!("0000000000000001");
        assert!(
            matching_verified_native_mcp_processes(&wrong, &activity, &agent_id, &agent).is_err()
        );
        wrong = audit.clone();
        wrong["transport_observations"][4]["sequence"] = json!(6);
        assert!(
            matching_verified_native_mcp_processes(&wrong, &activity, &agent_id, &agent).is_err()
        );
        wrong = audit.clone();
        wrong["transport_observations"][4]["run_id"] = json!("other-run");
        assert!(
            matching_verified_native_mcp_processes(&wrong, &activity, &agent_id, &agent).is_err()
        );
        wrong = audit.clone();
        wrong["transport_observations"][1]["peer_uid"] = json!(10005);
        assert!(
            matching_verified_native_mcp_processes(&wrong, &activity, &agent_id, &agent).is_err()
        );
        wrong = audit.clone();
        wrong["transport_observations"][3]["product_identity"]["start_time"] = json!("999");
        assert!(
            matching_verified_native_mcp_processes(&wrong, &activity, &agent_id, &agent).is_err()
        );
        wrong = audit.clone();
        wrong["transport_observations"][6]["message"]["params"]["name"] = json!("docs.create");
        assert!(
            matching_verified_native_mcp_processes(&wrong, &activity, &agent_id, &agent).is_err()
        );
        wrong = audit.clone();
        wrong["transport_observations"][8]["message"]["id"] = json!("other-call");
        assert!(
            matching_verified_native_mcp_processes(&wrong, &activity, &agent_id, &agent).is_err()
        );
        wrong = audit.clone();
        wrong["transport_observations"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(
            matching_verified_native_mcp_processes(&wrong, &activity, &agent_id, &agent).is_err()
        );
        let mut wrong_activity = activity.clone();
        wrong_activity["container_processes"][2]["container_id"] = json!(agent_id);
        assert!(
            matching_verified_native_mcp_processes(&audit, &wrong_activity, &agent_id, &agent)
                .is_err()
        );
    }
}
