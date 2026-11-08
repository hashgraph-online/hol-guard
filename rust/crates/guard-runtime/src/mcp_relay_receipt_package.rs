//! The receipts of plain relayed package calls, written by the resident.
//!
//! A package call the native relay answered leaves an `mcp_package_call`
//! record, and the daemon's `mcp_relay_package_evidence_drain` recorded it as
//! `_record_package_forward` and the proxy's package blocks do: an
//! `allow_tool_call` or `block_tool_call` receipt against the package
//! request's own artifact, with the approval-context token that request hashed
//! to, the evaluation's reason signals, and the package scanner evidence after
//! the decision's own.
//!
//! The record names that artifact by id rather than shipping it, so it is
//! rebuilt here from the call the record carries, through the parse the gate
//! ran (`parse_package_intent`): the same tool name, arguments, workspace and
//! `PATH`. The writer runs in the resident that decided the call, so a record
//! naming no `PATH` is parsed under the same ambient one the gate fell back
//! to. A rebuilt artifact that is not the one decided drops the record, as the
//! Python drain drops it.
//!
//! A plain package record is a forward under its own action, a policy block,
//! or an ask block whose desktop notice the resident already raised, from a
//! harness whose approval flow never opens the browser. The `ask` branch of
//! `_queue_package_approval_response` projects the call without the artifact,
//! so that block's receipt records no risk categories and is all it leaves.
//! A safe-alternative block's inbox row, an ask block still carrying its
//! notice or opening the approval center, and an observed forward's notices
//! are still the daemon's to write.

use std::path::Path;

use guard_command::mcp_tool_signals::risk_arguments;
use guard_command::package_intent_common::build_package_request_artifact;
use guard_contracts::{python_strip, McpToolArgumentsV1};
use serde_json::{json, Map, Value};

use super::event::{store_args, Artifact, Receipt};
use super::record::{
    approval_fits, block_taxonomy, keys_fit, relayed, string_list, Relayed, APPROVAL_KEY,
    APPROVAL_PENDING_SOURCE, BROWSER_APPROVAL_HARNESS, FORWARD_ACTIONS, RECORD_KEYS,
};
use super::{decision_evidence, receipt_evidence, strings, Call, Stamp};

/// The record kind a relayed package call is queued under.
pub(super) const KIND: &str = "mcp_package_call";
const PACKAGE_KEY: &str = "package";
/// The package facts the receipt is written from, `_PACKAGE_KEYS`.
const PACKAGE_KEYS: [&str; 7] = [
    "artifact_id",
    "artifact_hash",
    "workspace",
    "path",
    "evaluation",
    "evidence",
    "signals",
];
/// Bound only by the allow receipt, so only a forward's record carries it.
const POLICY_WORKSPACE_KEY: &str = "policy_workspace";
const BLOCK_SOURCE: &str = "policy-block";

/// A package record the resident can write the receipt of.
pub(super) struct PlainPackage<'a> {
    call: Relayed<'a>,
    forward: bool,
    package: &'a Map<String, Value>,
}

pub(super) fn plain(record: &Value) -> Option<PlainPackage<'_>> {
    let record = record.as_object()?;
    if !keys_fit(record, &RECORD_KEYS, &[PACKAGE_KEY, APPROVAL_KEY])
        || !record.contains_key(PACKAGE_KEY)
    {
        return None;
    }
    // An ask block whose desktop notice the resident raised; one still
    // carrying a notice is the daemon's to raise.
    let queued = match record.get(APPROVAL_KEY) {
        None => false,
        Some(approval) if approval_fits(approval) => true,
        Some(_) => return None,
    };
    let call = relayed(record, KIND)?;
    if queued && call.harness == BROWSER_APPROVAL_HARNESS {
        return None;
    }
    // `_record_package_forward` records the action it forwarded with as the
    // source, a block the package policy settled is a `policy-block`, and an
    // ask block is recorded as pending in the approval center.
    let block_source = if queued {
        APPROVAL_PENDING_SOURCE
    } else {
        BLOCK_SOURCE
    };
    let forward = match call.outcome {
        "forward"
            if !queued
                && FORWARD_ACTIONS.contains(&call.policy_action)
                && call.source.strip_prefix("policy-") == Some(call.policy_action) =>
        {
            true
        }
        "block" if block_taxonomy(call.policy_action).is_some() && call.source == block_source => {
            false
        }
        _ => return None,
    };
    let package = package_facts(&record[PACKAGE_KEY], forward)?;
    Some(PlainPackage {
        call,
        forward,
        package,
    })
}

/// `_package_facts`.
fn package_facts(package: &Value, forward: bool) -> Option<&Map<String, Value>> {
    let package = package.as_object()?;
    let bound = package.contains_key(POLICY_WORKSPACE_KEY);
    if bound != forward || !keys_fit(package, &PACKAGE_KEYS, &[POLICY_WORKSPACE_KEY]) {
        return None;
    }
    let filled = |key: &str| {
        package[key]
            .as_str()
            .is_some_and(|text| !python_strip(text).is_empty())
    };
    let fits = ["artifact_id", "artifact_hash", "workspace"]
        .iter()
        .all(|key| filled(key))
        && (package["path"].is_null() || filled("path"))
        && package["evaluation"].is_object()
        && package["evidence"]
            .as_array()
            .is_some_and(|items| items.iter().all(Value::is_object))
        && string_list(&package["signals"])
        && package
            .get(POLICY_WORKSPACE_KEY)
            .is_none_or(|workspace| workspace.is_string() || workspace.is_null());
    fits.then_some(package)
}

/// The `record_tool_call_evidence` arguments `allow_tool_call` or
/// `block_tool_call` writes for this record against the rebuilt package
/// artifact.
pub(super) fn compose(
    guard_home: &str,
    record: &Value,
    stamp: &Stamp,
) -> Option<Map<String, Value>> {
    let PlainPackage {
        call,
        forward,
        package,
    } = plain(record)?;
    let text = |key: &str| package[key].as_str();
    let arguments: McpToolArgumentsV1 = serde_json::from_value(record["arguments"].clone()).ok()?;
    let intent = crate::mcp_relay_decide::parse_package_intent(
        call.tool_name,
        &risk_arguments(&arguments),
        Some(Path::new(text("workspace")?)),
        text("path"),
    )?;
    let artifact = build_package_request_artifact(
        call.harness,
        &intent,
        call.artifact["config_path"].as_str()?,
        call.artifact["source_scope"].as_str()?,
    );
    // The resident decided one package request; a parse that rebuilds another
    // is not that request's receipt.
    if artifact.artifact_id != text("artifact_id")? {
        return None;
    }
    // Projected without the artifact, so no risk categories are recorded.
    let risk_categories: [String; 0] = [];
    let (raw_command_text, firewall_evidence) = receipt_evidence(
        guard_home,
        &Call {
            tool_name: call.tool_name,
            params: call.params,
            artifact_name: &artifact.name,
            description: artifact.metadata["tool_description"].as_str(),
            firewall: artifact
                .metadata
                .get("mcpSkillFirewall")
                .filter(|firewall| firewall.is_object()),
        },
        stamp,
        &risk_categories,
    )?;
    // `(*tool_decision_scanner_evidence(decision), *facts["evidence"])`.
    let mut scanner_evidence = vec![firewall_evidence];
    scanner_evidence.extend(decision_evidence(call.decision));
    scanner_evidence.extend(package["evidence"].as_array()?.iter().cloned());
    // `" ".join([command, *args]).strip()`.
    let launch_command = artifact
        .command
        .as_deref()
        .filter(|command| !command.is_empty())
        .map(|command| {
            let joined = std::iter::once(command)
                .chain(artifact.args.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" ");
            python_strip(&joined).to_owned()
        });
    let receipt = Receipt {
        harness: call.harness,
        forward,
        source: call.source,
        policy_action: call.policy_action,
        artifact: Artifact {
            artifact_id: &artifact.artifact_id,
            name: &artifact.name,
            artifact_type: &artifact.artifact_type,
            source_scope: &artifact.source_scope,
            config_path: &artifact.config_path,
            publisher: json!(artifact.publisher),
            origin_url: json!(artifact.url),
            launch_command,
            transport: json!(artifact.transport),
        },
        artifact_hash: text("artifact_hash")?,
        signals: strings(&package["signals"]),
        risk_categories: &risk_categories,
        scanner_evidence,
        raw_command_text,
    };
    store_args(&receipt, stamp)
}

#[cfg(test)]
#[path = "mcp_relay_receipt_package_tests.rs"]
mod tests;
