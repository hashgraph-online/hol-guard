//! Compare outside-pinned Root SDK tap digests with signed Native MCP frames.
//! This is a diagnostic transport relation, not physical-effect attestation.

use crate::crypto::{decode_hex, is_sha256, sha256};
use crate::{verify_controller_envelope, EvidenceError, Result};
use gauntlet_contracts::canonicalize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const INVALID: EvidenceError = EvidenceError::Invalid("invalid staging SDK tap frame relation");
type Frame = (String, Option<String>, Option<String>);
type FrameKey = (String, String);

pub(crate) struct SdkTapOutsidePins<'a> {
    pub journal_sha256: &'a str,
    pub source_sha: &'a str,
    pub started_marker_sha256: &'a str,
    pub controller_public_key_hex: &'a str,
    pub expected_docs_record: Option<&'a Value>,
    pub root_forwarded: bool,
}

/// Derive the clean and injected docs records from the separately pinned
/// controller fixture. This parser does not establish source custody: its
/// caller must first verify and recheck the complete controller tree.
pub(crate) fn source_bound_docs_records(raw: &[u8]) -> Result<(Value, Value)> {
    if raw.is_empty() || raw.len() > 32 * 1024 {
        return Err(INVALID);
    }
    let canonical = canonicalize(raw).map_err(|_| INVALID)?;
    let fixture: Value = serde_json::from_slice(&canonical).map_err(|_| INVALID)?;
    let snapshot = &fixture["snapshot"];
    let records = snapshot["records"].as_array().ok_or(INVALID)?;
    if snapshot["schema"] != "gauntlet-workflow-snapshot.v1"
        || snapshot["workflow_id"] != "python-cli-with-tests"
        || records.len() != 4
    {
        return Err(INVALID);
    }
    let matches = records
        .iter()
        .filter(|record| record["id"] == "developer-spec")
        .collect::<Vec<_>>();
    if matches.len() != 1 || matches[0]["collection"] != "docs.documents" {
        return Err(INVALID);
    }
    let clean = (*matches[0]).clone();
    let overlays = fixture["attack_overlays"]["text-injection"]
        .as_array()
        .ok_or(INVALID)?;
    if overlays.len() != 1
        || overlays[0]["record_id"] != "developer-spec"
        || overlays[0]["field"] != "body"
        || overlays[0]["value"].as_str().is_none()
        || clean["data"]["body"].as_str().is_none()
    {
        return Err(INVALID);
    }
    let mut injected = clean.clone();
    injected["data"]["body"] = overlays[0]["value"].clone();
    if clean == injected {
        return Err(INVALID);
    }
    Ok((clean, injected))
}

fn native_frames(audit: &Value) -> Result<BTreeMap<FrameKey, Vec<Frame>>> {
    let events = audit["transport_observations"].as_array().ok_or(INVALID)?;
    let mut frames: BTreeMap<FrameKey, Vec<Frame>> = BTreeMap::new();
    for event in events {
        if event["kind"] != "frame" {
            continue;
        }
        let family = event["family"].as_str().ok_or(INVALID)?;
        let direction = event["direction"].as_str().ok_or(INVALID)?;
        if !matches!(family, "docs" | "mail")
            || !matches!(direction, "client-to-service" | "service-to-client")
            || event["message"]["jsonrpc"] != "2.0"
        {
            return Err(INVALID);
        }
        let message = &event["message"];
        let canonical = canonicalize(message.to_string().as_bytes()).map_err(|_| INVALID)?;
        let method = message
            .get("method")
            .map(|value| value.as_str().map(str::to_owned).ok_or(INVALID))
            .transpose()?;
        let id = message
            .get("id")
            .map(|value| {
                if value.as_str().is_some() || value.as_i64().is_some() || value.as_u64().is_some()
                {
                    serde_json::to_string(value).map_err(|_| INVALID)
                } else {
                    Err(INVALID)
                }
            })
            .transpose()?;
        frames
            .entry((family.to_owned(), direction.to_owned()))
            .or_default()
            .push((sha256(&canonical), method, id));
    }
    Ok(frames)
}

fn compare_frames(audit: &Value, journal: &Value) -> Result<usize> {
    let expected = native_frames(audit)?;
    let sessions = journal["sessions"].as_array().ok_or(INVALID)?;
    if sessions.len() != 2 || journal["session_count"] != 2 {
        return Err(INVALID);
    }
    let mut observed: BTreeMap<FrameKey, Vec<Frame>> = BTreeMap::new();
    let mut families = BTreeSet::new();
    let mut total = 0_usize;
    let mut bytes = 0_u64;
    for (index, session) in sessions.iter().enumerate() {
        let family = session["family"].as_str().ok_or(INVALID)?;
        let wire = &session["wire"];
        let events = wire["events"].as_array().ok_or(INVALID)?;
        if !matches!(family, "docs" | "mail")
            || !families.insert(family)
            || session["sequence"] != index + 1
            || wire["schema"] != "hol-gauntlet-sdk-wire-tap.v1"
            || wire["peer_identity_verified"] != false
            || wire["journal_durable"] != false
            || wire["execution_eligible"] != false
            || wire["completed_tool_calls"] != usize::from(family == "docs")
            || events.is_empty()
            || events.len() > 1000
        {
            return Err(INVALID);
        }
        let mut session_bytes = 0_u64;
        for (number, event) in events.iter().enumerate() {
            let direction = event["direction"].as_str().ok_or(INVALID)?;
            let digest = event["canonical_message_sha256"].as_str().ok_or(INVALID)?;
            let raw_digest = event["frame_sha256"].as_str().ok_or(INVALID)?;
            let size = event["frame_bytes"].as_u64().ok_or(INVALID)?;
            if event["sequence"] != number + 1
                || event["family"] != family
                || !matches!(direction, "client-to-service" | "service-to-client")
                || !is_sha256(digest)
                || !is_sha256(raw_digest)
                || !(2..=1024 * 1024 + 1).contains(&size)
            {
                return Err(INVALID);
            }
            let method = event["method"].as_str().map(str::to_owned);
            let id = event["id_json"].as_str().map(str::to_owned);
            if (!event["method"].is_null() && method.is_none())
                || (!event["id_json"].is_null() && id.is_none())
            {
                return Err(INVALID);
            }
            observed
                .entry((family.to_owned(), direction.to_owned()))
                .or_default()
                .push((digest.to_owned(), method, id));
            session_bytes = session_bytes.checked_add(size).ok_or(INVALID)?;
        }
        if wire["total_bytes"].as_u64() != Some(session_bytes) {
            return Err(INVALID);
        }
        total = total.checked_add(events.len()).ok_or(INVALID)?;
        bytes = bytes.checked_add(session_bytes).ok_or(INVALID)?;
    }
    if families.len() != 2
        || total != 24
        || journal["event_count"] != total
        || journal["observed_bytes"].as_u64() != Some(bytes)
        || observed != expected
    {
        return Err(INVALID);
    }
    Ok(total)
}

/// The tap comparison authenticates the transport digest of the signed
/// Native frames. Also require the one completed docs.read response to be
/// exactly the value delivered to the SDK's first tool result. The separate
/// physical-file reader binds that SDK result to the retained stdout bytes.
fn completed_docs_result(audit: &Value) -> Result<&Value> {
    let events = audit["transport_observations"].as_array().ok_or(INVALID)?;
    let requests = events
        .iter()
        .filter(|event| {
            event["kind"] == "frame"
                && event["family"] == "docs"
                && event["direction"] == "client-to-service"
                && event["message"]["method"] == "tools/call"
                && event["message"]["params"]["name"] == "docs.read"
        })
        .collect::<Vec<_>>();
    if requests.len() != 1 {
        return Err(INVALID);
    }
    let request = &requests[0]["message"];
    let id = request
        .get("id")
        .filter(|id| !id.is_null())
        .ok_or(INVALID)?;
    let args = request["params"]["arguments"].as_object().ok_or(INVALID)?;
    if args.len() != 1 || args.get("record_id") != Some(&Value::from("developer-spec")) {
        return Err(INVALID);
    }
    let responses = events
        .iter()
        .filter(|event| {
            event["kind"] == "frame"
                && event["family"] == "docs"
                && event["direction"] == "service-to-client"
                && event["message"].get("id") == Some(id)
        })
        .collect::<Vec<_>>();
    if responses.len() != 1 {
        return Err(INVALID);
    }
    let response = &responses[0]["message"];
    let result = response["result"].as_object().ok_or(INVALID)?;
    if response.get("error").is_some()
        || result.get("isError") != Some(&Value::Bool(false))
        || result.get("content").and_then(Value::as_array).is_none()
        || !result.contains_key("structuredContent")
    {
        return Err(INVALID);
    }
    Ok(&response["result"])
}

fn sdk_result_matches_docs_response(audit: &Value, sdk_result: &Value) -> Result<()> {
    let result = completed_docs_result(audit)?;
    let outputs = sdk_result["results"].as_array().ok_or(INVALID)?;
    if outputs.len() != 2 {
        return Err(INVALID);
    }
    let first = &outputs[0];
    let expected_tool = match sdk_result.get("mcpAgentSurfaces") {
        None => "mcp__docs_read",
        Some(value) if value == "mcp-agent-surfaces.v1" => "mcp_call_tool",
        _ => return Err(INVALID),
    };
    let details = &first["details"];
    if sdk_result["schema"] != "private-cell-sdk-conformance-result.v1"
        || first["role"] != "toolResult"
        || first["toolCallId"] != "sdk-mcp-control"
        || first["toolName"] != expected_tool
        || first["isError"] != false
        || first["content"] != result["content"]
        || details["serverName"] != "docs"
        || details["mcpToolName"] != "docs.read"
        || details["isError"] != result["isError"]
        || details["rawContent"] != result["content"]
        || details["structuredContent"] != result["structuredContent"]
    {
        return Err(INVALID);
    }
    Ok(())
}

fn docs_result_matches_fixture(audit: &Value, expected: &Value) -> Result<()> {
    let result = completed_docs_result(audit)?;
    let parts = result["content"].as_array().ok_or(INVALID)?;
    if result["structuredContent"] != *expected || parts.len() != 1 || parts[0]["type"] != "text" {
        return Err(INVALID);
    }
    let text = parts[0]["text"].as_str().ok_or(INVALID)?;
    let canonical = canonicalize(text.as_bytes()).map_err(|_| INVALID)?;
    let decoded: Value = serde_json::from_slice(&canonical).map_err(|_| INVALID)?;
    if decoded != *expected {
        return Err(INVALID);
    }
    Ok(())
}

pub(crate) fn matching_sdk_tap_native_frames(
    record: &Value,
    report: &Value,
    terminal: &Value,
    journal_raw: &[u8],
    pins: &SdkTapOutsidePins<'_>,
) -> Result<usize> {
    if journal_raw.is_empty()
        || journal_raw.len() > 1024 * 1024
        || !is_sha256(pins.journal_sha256)
        || sha256(journal_raw) != pins.journal_sha256
        || canonicalize(journal_raw).map_err(|_| INVALID)? != journal_raw
    {
        return Err(INVALID);
    }
    let journal: Value = serde_json::from_slice(journal_raw).map_err(|_| INVALID)?;
    let run_id = report["run_id"].as_str().ok_or(INVALID)?;
    let receipt = &report["sdk_tap_v2"]["journal"];
    let mode_matches = if pins.root_forwarded {
        report["sdk_tap_v2"]["schema"] == "hol-gauntlet-staging-sdk-tap-summary.v3"
            && report["sdk_tap_v2"]["native_peer_independently_observed_by_root"] == true
            && report["sdk_tap_v2"]["root_forwarded"] == true
            && receipt["schema"] == "hol-gauntlet-sdk-tap-journal-receipt.v2"
            && receipt["root_forwarded"] == true
            && journal["schema"] == "hol-gauntlet-sdk-tap-journal.v2"
            && journal["root_forwarded"] == true
            && journal["wire_owner"] == "root-forwarded"
    } else {
        matches!(
            (
                report["sdk_tap_v2"]["schema"].as_str(),
                report["sdk_tap_v2"]["native_peer_independently_observed_by_root"].as_bool()
            ),
            (Some("hol-gauntlet-staging-sdk-tap-summary.v1"), Some(false))
                | (Some("hol-gauntlet-staging-sdk-tap-summary.v2"), Some(true))
        ) && report["sdk_tap_v2"].get("root_forwarded").is_none()
            && receipt["schema"] == "hol-gauntlet-sdk-tap-journal-receipt.v1"
            && receipt.get("root_forwarded").is_none()
            && journal["schema"] == "hol-gauntlet-sdk-tap-journal.v1"
            && journal.get("root_forwarded").is_none()
            && journal.get("wire_owner").is_none()
    };
    if record["sdk_tap_v2_requested"] != true
        || !mode_matches
        || report["sdk_tap_v2"]["execution_eligible"] != false
        || receipt["run_id"] != run_id
        || receipt["sha256"] != pins.journal_sha256
        || receipt["bytes"] != journal_raw.len()
        || receipt["sessions"] != 2
        || receipt["events"] != 24
        || receipt["child_report_authenticated"] != false
        || receipt["host_pin_retained"] != false
        || receipt["execution_eligible"] != false
        || journal["run_id"] != run_id
        || journal["source_sha"] != pins.source_sha
        || journal["started_marker_sha256"] != pins.started_marker_sha256
        || journal["controller_public_key_hex"] != pins.controller_public_key_hex
        || journal["child_report_authenticated"] != false
        || journal["host_pin_retained"] != false
        || journal["execution_eligible"] != false
    {
        return Err(INVALID);
    }
    let key = decode_hex(pins.controller_public_key_hex, 32).map_err(|_| INVALID)?;
    let runtime_raw = serde_json::to_vec(&record["developer_runtime"]).map_err(|_| INVALID)?;
    let runtime = verify_controller_envelope(&runtime_raw, &key)?;
    let audit_raw = serde_json::to_vec(&runtime["native_mcp_audit"]).map_err(|_| INVALID)?;
    let audit = verify_controller_envelope(&audit_raw, &key)?;
    sdk_result_matches_docs_response(&audit, &record["sdk_result"])?;
    if let Some(expected) = pins.expected_docs_record {
        docs_result_matches_fixture(&audit, expected)?;
    }
    let agent_container = record["agent_container_inspection"]["Id"]
        .as_str()
        .filter(|id| is_sha256(id))
        .ok_or(INVALID)?;
    let agent_cgroup = format!("/machine.slice/libpod-{agent_container}.scope/container");
    let gate_pid = &record["sdk_gate"]["observation"]["pid"];
    let gate_start = record["sdk_gate"]["observation"]["identity"]["start_time"]
        .as_str()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or(INVALID)?;
    let controller_cgroup = format!("/system.slice/hol-gauntlet-rust-job-{run_id}");
    let mut relays = BTreeSet::new();
    for session in journal["sessions"].as_array().ok_or(INVALID)? {
        if pins.root_forwarded {
            if session["wire_owner"] != "root-forwarded" {
                return Err(INVALID);
            }
        } else if session.get("wire_owner").is_some() {
            return Err(INVALID);
        }
        let peer = &session["sdk_peer"];
        let native = &session["native_peer"];
        let ancestry = &session["sdk_ancestry"];
        let pid = peer["pid"].as_u64().ok_or(INVALID)?;
        let start = peer["start_ticks"].as_u64().ok_or(INVALID)?;
        let matched = report["live_kernel_activity"]["container_processes"]
            .as_array()
            .ok_or(INVALID)?
            .iter()
            .filter(|row| {
                row["container_id"] == agent_container
                    && row["pid"] == pid
                    && row["start_ticks"] == start
                    && row["cgroup"] == agent_cgroup
            })
            .count();
        if peer["schema"] != "hol-gauntlet-sdk-wire-peer.v1"
            || peer["uid"] != 10001
            || peer["gid"] != 10001
            || peer["cgroup"] != agent_cgroup
            || peer["sdk_ancestry_verified"] != false
            || peer["execution_eligible"] != false
            || !relays.insert((pid, start))
            || matched != 1
            || ancestry["schema"] != "hol-gauntlet-sdk-wire-ancestry.v1"
            || ancestry["relay_pid"] != pid
            || ancestry["ancestor_pid"] != *gate_pid
            || ancestry["ancestor_start_ticks"] != gate_start
            || ancestry["cgroup"] != agent_cgroup
            || ancestry["hops"] != 1
            || ancestry["ancestor_executable_verified"] != false
            || ancestry["execution_eligible"] != false
            || native["schema"] != "hol-gauntlet-sdk-wire-peer.v1"
            || native["uid"] != 0
            || native["gid"] != 0
            || native["pid"] != terminal["pid"]
            || native["start_ticks"] != terminal["process_start_ticks"]
            || native["cgroup"] != controller_cgroup
            || native["sdk_ancestry_verified"] != false
            || native["execution_eligible"] != false
        {
            return Err(INVALID);
        }
    }
    compare_frames(&audit, &journal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::Path;

    #[test]
    fn current_source_fixture_derives_python_frozen_clean_and_injected_docs() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../gauntlet/benchmark/fixtures/python-cli-with-tests.json");
        let raw = std::fs::read(path).unwrap();
        let (clean, injected) = source_bound_docs_records(&raw).unwrap();
        assert_eq!(
            sha256(&canonicalize(clean.to_string().as_bytes()).unwrap()),
            "ce02deec20e412dfed72a6cfd864176491449f60fa610eea0bfaf4da6d1bd76f"
        );
        assert_eq!(
            sha256(&canonicalize(injected.to_string().as_bytes()).unwrap()),
            "6be842bd8078c69cfca24cb5331e55539f195040285cd4966b03398eba4f01ac"
        );
        let mut altered: Value = serde_json::from_slice(&raw).unwrap();
        altered["attack_overlays"]["text-injection"][0]["record_id"] = json!("other");
        assert!(source_bound_docs_records(altered.to_string().as_bytes()).is_err());
    }

    #[test]
    fn frozen_python_sdk_results_match_only_the_completed_native_docs_response() {
        for case in ["006", "010"] {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../../tests/fixtures/workflow_benchmark")
                .join(format!("local_executor_conformance_{case}.json"));
            let package: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            let record = &package["controls"]["success"]["record"];
            let audit = &record["developer_runtime"]["record"]["native_mcp_audit"]["record"];
            let sdk_result = &record["sdk_result"];
            sdk_result_matches_docs_response(audit, sdk_result).unwrap();
            let response = completed_docs_result(audit).unwrap();
            docs_result_matches_fixture(audit, &response["structuredContent"]).unwrap();
            let mut forged_doc = response["structuredContent"].clone();
            forged_doc["data"]["body"] = json!("changed outside expected document");
            assert!(docs_result_matches_fixture(audit, &forged_doc).is_err());

            let mut altered_sdk = sdk_result.clone();
            altered_sdk["results"][0]["details"]["rawContent"] = json!([]);
            assert!(sdk_result_matches_docs_response(audit, &altered_sdk).is_err());
            let mut altered_sdk = sdk_result.clone();
            altered_sdk["results"][0]["toolCallId"] = json!("different-call");
            assert!(sdk_result_matches_docs_response(audit, &altered_sdk).is_err());

            let mut altered_audit = audit.clone();
            let events = altered_audit["transport_observations"]
                .as_array_mut()
                .unwrap();
            let call_id = events
                .iter()
                .find(|event| {
                    event["kind"] == "frame"
                        && event["family"] == "docs"
                        && event["direction"] == "client-to-service"
                        && event["message"]["method"] == "tools/call"
                        && event["message"]["params"]["name"] == "docs.read"
                })
                .unwrap()["message"]["id"]
                .clone();
            let response = events
                .iter()
                .find(|event| {
                    event["kind"] == "frame"
                        && event["family"] == "docs"
                        && event["direction"] == "service-to-client"
                        && event["message"]["id"] == call_id
                })
                .unwrap()
                .clone();
            events.push(response);
            assert!(sdk_result_matches_docs_response(&altered_audit, sdk_result).is_err());
        }
    }

    #[test]
    fn concurrent_family_frames_match_without_global_adjacency() {
        let docs = json!({"jsonrpc":"2.0","method":"tools/call","id":"one"});
        let mail = json!({"jsonrpc":"2.0","method":"initialize","id":"two"});
        let audit = json!({"transport_observations":[
            {"kind":"frame","family":"docs","direction":"client-to-service","message":docs},
            {"kind":"frame","family":"mail","direction":"client-to-service","message":mail},
        ]});
        let frames = native_frames(&audit).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(
            frames[&("docs".to_owned(), "client-to-service".to_owned())].len(),
            1
        );
        let mut altered = audit.clone();
        altered["transport_observations"][0]["message"]["method"] = json!("tools/other");
        assert_ne!(native_frames(&altered).unwrap(), frames);
        altered["transport_observations"][0]["message"]["id"] = Value::Null;
        assert!(native_frames(&altered).is_err());
    }

    #[test]
    fn exact_tap_frame_sequence_rejects_changed_or_missing_frames() {
        let mut native = Vec::new();
        let mut sessions = Vec::new();
        for (number, family, count) in [(1, "docs", 13), (2, "mail", 11)] {
            let mut events = Vec::new();
            for index in 0..count {
                let direction = if index % 2 == 0 {
                    "client-to-service"
                } else {
                    "service-to-client"
                };
                let id = format!("{family}-{index}");
                let message = json!({"jsonrpc":"2.0","method":"probe","id":id});
                let canonical = canonicalize(message.to_string().as_bytes()).unwrap();
                native.push(json!({
                    "kind":"frame","family":family,"direction":direction,
                    "message":message,
                }));
                events.push(json!({
                    "sequence":index + 1,"family":family,"direction":direction,
                    "frame_sha256":"a".repeat(64),
                    "canonical_message_sha256":sha256(&canonical),
                    "frame_bytes":40,"method":"probe",
                    "id_json":serde_json::to_string(&id).unwrap(),
                }));
            }
            sessions.push(json!({
                "sequence":number,"family":family,
                "wire":{
                    "schema":"hol-gauntlet-sdk-wire-tap.v1","events":events,
                    "completed_tool_calls":usize::from(family == "docs"),
                    "total_bytes":count * 40,"peer_identity_verified":false,
                    "journal_durable":false,"execution_eligible":false,
                }
            }));
        }
        let audit = json!({"transport_observations":native});
        let mut journal = json!({
            "sessions":sessions,"session_count":2,"event_count":24,
            "observed_bytes":960,
        });
        assert_eq!(compare_frames(&audit, &journal).unwrap(), 24);
        let original =
            journal["sessions"][0]["wire"]["events"][0]["canonical_message_sha256"].clone();
        journal["sessions"][0]["wire"]["events"][0]["canonical_message_sha256"] =
            json!("b".repeat(64));
        assert!(compare_frames(&audit, &journal).is_err());
        journal["sessions"][0]["wire"]["events"][0]["canonical_message_sha256"] = original;
        journal["sessions"][0]["wire"]["events"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(compare_frames(&audit, &journal).is_err());
    }
}
