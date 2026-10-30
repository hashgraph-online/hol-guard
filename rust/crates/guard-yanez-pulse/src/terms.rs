//! Pulse terms for one held Guard action.
//!
//! Terms leave the machine, so they never carry a full command, an argument,
//! a path, a secret or a workspace name. They carry only a short summary the
//! caller has already reduced to safe values (`ActionSummary`): the agent, the
//! request type, Guard's risk level and headline, and the names of the
//! programs being run. The action, scope, subject, session and nonce are bound
//! through a keyed HMAC whose key never leaves Guard's secret store. A short
//! match code taken from that HMAC is shown in the YID app and in the
//! dashboard or CLI, so the user can check that both screens show the same
//! request.

use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

use crate::PulseError;

/// `terms.action` for every Guard approval.
pub const TERMS_ACTION: &str = "hol_guard.approval";
/// Version of the `hol_guard` binding block inside terms.
pub const BINDING_VERSION: i64 = 1;
/// Pulse caps compact terms at 4 KB.
pub const MAX_TERMS_BYTES: usize = 4 * 1024;

/// Longest summary value shown in the YID app; longer values are cut.
pub const MAX_SUMMARY_VALUE_CHARS: usize = 120;

const BINDING_DOMAIN: &[u8] = b"hol-guard-pulse-binding-v1";
const CONSUMER_DOMAIN: &[u8] = b"hol-guard-pulse-consumer-v1";

/// The exact Guard action a Pulse approval is for. Every field is bound into
/// the HMAC; none is sent to Pulse in the clear except `purpose`, which is a
/// fixed Guard enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionBinding<'a> {
    pub purpose: &'a str,
    pub action: &'a str,
    pub scope: &'a str,
    pub subject: &'a str,
    pub session_nonce: &'a str,
    /// Hash of the caller's OS-session signals.
    pub session_binding: &'a str,
    /// Fresh random nonce Guard minted for this Pulse request.
    pub request_nonce: &'a str,
    /// Approval-gate factor generation at request time.
    pub factor_generation: i64,
}

/// What the YID app shows about the held action, beyond its purpose. Every
/// field is optional and must already be safe to send: the caller derives
/// them from Guard's own record of the request, never from free input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActionSummary {
    /// The harness that made the request, for example "Codex".
    pub agent: Option<String>,
    /// Guard's request kind, for example "Tool call".
    pub request_type: Option<String>,
    /// Guard's risk level: high, medium or low.
    pub risk_level: Option<String>,
    /// Guard's risk headline, already passed through its secret filter.
    pub reason: Option<String>,
    /// Program names only, for example "rm" or "curl | sh".
    pub programs: Option<String>,
    /// How many paused actions one approval covers. Set only for a batch;
    /// the rows then summarize all of them.
    pub action_count: Option<usize>,
}

/// One line of display text: control characters dropped, whitespace
/// collapsed, cut to `MAX_SUMMARY_VALUE_CHARS`. `None` when nothing is left.
pub fn summary_value(value: &str) -> Option<String> {
    let collapsed = value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if collapsed.is_empty() {
        return None;
    }
    if collapsed.chars().count() <= MAX_SUMMARY_VALUE_CHARS {
        return Some(collapsed);
    }
    let cut: String = collapsed
        .chars()
        .take(MAX_SUMMARY_VALUE_CHARS - 1)
        .collect();
    Some(format!("{}…", cut.trim_end()))
}

/// Purposes Guard will ever send to Pulse, with the text the YID app shows.
pub fn purpose_label(purpose: &str) -> Option<&'static str> {
    Some(match purpose {
        "approval_decision" => "Approve an agent action Guard paused",
        "policy_write" => "Change a Guard policy",
        "policy_clear" => "Clear Guard policy memory",
        "policy_import" => "Import Guard policy",
        "policy_export_provenance" => "Export Guard policy provenance",
        "evidence_clear" => "Clear Guard evidence",
        "queue_clear" => "Clear the Guard approval queue",
        "settings_write" => "Change Guard settings",
        "native_policy" => "Change a native Guard policy",
        "tool_call_policy" => "Change a tool-call policy",
        "headless_policy_sync" => "Sync headless Guard policy",
        "supply_chain_firewall" => "Change the supply-chain firewall",
        "extension_control_mutation" => "Change an extension control",
        "local_cli_trust_mutation" => "Trust a local CLI",
        "protection_lifecycle" => "Turn Guard protection on or off",
        "pulse_enrollment" => "Use this identity to approve HOL Guard actions",
        "local_once" | "generic" => "Approve a Guard action",
        _ => return None,
    })
}

/// HMAC over every bound field, as lower-case hex.
pub fn binding_digest(key: &[u8], binding: &ActionBinding<'_>) -> Result<String, PulseError> {
    if key.len() < 32 {
        return Err(PulseError::InvalidRequest("binding_key"));
    }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map_err(|_| PulseError::InvalidRequest("binding_key"))?;
    mac.update(BINDING_DOMAIN);
    let generation = binding.factor_generation.to_string();
    for field in [
        binding.purpose,
        binding.action,
        binding.scope,
        binding.subject,
        binding.session_nonce,
        binding.session_binding,
        binding.request_nonce,
        generation.as_str(),
    ] {
        // Length-prefix each field so no two field lists hash alike.
        mac.update(&(field.len() as u64).to_be_bytes());
        mac.update(field.as_bytes());
    }
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Six-character code shown on both screens.
pub fn match_code(digest_hex: &str) -> String {
    digest_hex
        .chars()
        .take(6)
        .collect::<String>()
        .to_ascii_uppercase()
}

/// Deterministic, durable `consumer_token` for one receipt, so a retried
/// consume reuses the same value without Guard writing it down first.
pub fn consumer_token(key: &[u8], jti: &str) -> Result<String, PulseError> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map_err(|_| PulseError::InvalidRequest("binding_key"))?;
    mac.update(CONSUMER_DOMAIN);
    mac.update(jti.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Build the terms object sent to Pulse and later compared to the receipt,
/// with no action summary beyond the purpose.
pub fn build_terms(key: &[u8], binding: &ActionBinding<'_>) -> Result<Value, PulseError> {
    build_terms_with_summary(key, binding, &ActionSummary::default())
}

/// Build the terms object, including the safe action summary rows.
pub fn build_terms_with_summary(
    key: &[u8],
    binding: &ActionBinding<'_>,
    summary: &ActionSummary,
) -> Result<Value, PulseError> {
    let label = purpose_label(binding.purpose).ok_or(PulseError::InvalidRequest("purpose"))?;
    let batch = summary
        .action_count
        .filter(|n| *n > 1 && binding.purpose == "approval_decision");
    let label = match batch {
        Some(n) => format!("Approve {n} agent actions Guard paused"),
        None => label.to_owned(),
    };
    let plural = |one: &'static str, many: &'static str| if batch.is_some() { many } else { one };
    if binding.request_nonce.len() < 16 {
        return Err(PulseError::InvalidRequest("request_nonce"));
    }
    let digest = binding_digest(key, binding)?;
    let code = match_code(&digest);
    let clean = |value: &Option<String>| value.as_deref().and_then(summary_value);
    let programs = clean(&summary.programs);
    let mut details = vec![json!({"label": "Request", "value": label, "emphasized": true})];
    for (row, value, emphasized) in [
        (plural("Program", "Programs"), programs.clone(), true),
        (plural("Agent", "Agents"), clean(&summary.agent), false),
        (
            plural("Request type", "Request types"),
            clean(&summary.request_type),
            false,
        ),
        (
            plural("Risk level", "Highest risk level"),
            clean(&summary.risk_level),
            false,
        ),
        ("Reason", clean(&summary.reason), false),
    ] {
        if let Some(value) = value {
            details.push(json!({"label": row, "value": value, "emphasized": emphasized}));
        }
    }
    details.push(json!({"label": "Match code", "value": code, "emphasized": true}));
    let headline = match &programs {
        Some(programs) => format!("{label}: {programs}. Match code {code}."),
        None => format!("{label}. Match code {code}."),
    };
    let terms = json!({
        "schema_version": 1,
        "action": TERMS_ACTION,
        "approval_title": "HOL Guard approval",
        "summary": headline,
        "merchant": "HOL Guard",
        "details": details,
        "hol_guard": {
            "binding_version": BINDING_VERSION,
            "purpose": binding.purpose,
            "binding": digest,
            "nonce": binding.request_nonce,
        },
    });
    let size = serde_json::to_vec(&terms)
        .map_err(|_| PulseError::InvalidRequest("terms"))?
        .len();
    if size > MAX_TERMS_BYTES {
        return Err(PulseError::InvalidRequest("terms_size"));
    }
    Ok(terms)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    fn binding<'a>(action: &'a str) -> ActionBinding<'a> {
        ActionBinding {
            purpose: "approval_decision",
            action,
            scope: "workspace",
            subject: "rm -rf /Users/me/secret-project",
            session_nonce: "sn-1",
            session_binding: "sb-1",
            request_nonce: "0123456789abcdef0123",
            factor_generation: 2,
        }
    }

    #[test]
    fn terms_never_contain_the_subject_or_action_text() {
        let terms = build_terms(&KEY, &binding("allow-once:cmd-hash")).unwrap();
        let text = serde_json::to_string(&terms).unwrap();
        assert!(!text.contains("secret-project"));
        assert!(!text.contains("cmd-hash"));
        assert!(!text.contains("workspace"));
        assert_eq!(terms["schema_version"], 1);
    }

    #[test]
    fn every_bound_field_changes_the_digest() {
        let base = binding_digest(&KEY, &binding("a")).unwrap();
        assert_ne!(base, binding_digest(&KEY, &binding("b")).unwrap());
        let mut other = binding("a");
        other.session_binding = "sb-2";
        assert_ne!(base, binding_digest(&KEY, &other).unwrap());
        let mut other = binding("a");
        other.factor_generation = 3;
        assert_ne!(base, binding_digest(&KEY, &other).unwrap());
        assert_ne!(base, binding_digest(&[8; 32], &binding("a")).unwrap());
    }

    #[test]
    fn field_boundaries_are_unambiguous() {
        let mut left = binding("ab");
        left.scope = "c";
        let mut right = binding("a");
        right.scope = "bc";
        assert_ne!(
            binding_digest(&KEY, &left).unwrap(),
            binding_digest(&KEY, &right).unwrap()
        );
    }

    #[test]
    fn unknown_purpose_and_short_key_are_refused() {
        let mut b = binding("a");
        b.purpose = "something_else";
        assert!(build_terms(&KEY, &b).is_err());
        assert!(build_terms(&[1; 8], &binding("a")).is_err());
    }

    fn summary() -> ActionSummary {
        ActionSummary {
            agent: Some("Codex".into()),
            request_type: Some("Tool call".into()),
            risk_level: Some("high".into()),
            reason: Some("Deletes files.".into()),
            programs: Some("rm".into()),
            action_count: None,
        }
    }

    fn rows(terms: &Value) -> Vec<(String, String)> {
        terms["details"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                (
                    row["label"].as_str().unwrap().to_owned(),
                    row["value"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    #[test]
    fn the_summary_adds_its_rows_in_order() {
        let terms = build_terms_with_summary(&KEY, &binding("a"), &summary()).unwrap();
        let labels: Vec<String> = rows(&terms).into_iter().map(|(label, _)| label).collect();
        assert_eq!(
            labels,
            [
                "Request",
                "Program",
                "Agent",
                "Request type",
                "Risk level",
                "Reason",
                "Match code"
            ]
        );
        let headline = terms["summary"].as_str().unwrap();
        assert!(headline.starts_with("Approve an agent action Guard paused: rm. Match code "));
    }

    #[test]
    fn empty_summary_fields_add_no_rows() {
        let partial = ActionSummary {
            programs: Some("   ".into()),
            risk_level: Some("medium".into()),
            ..ActionSummary::default()
        };
        let terms = build_terms_with_summary(&KEY, &binding("a"), &partial).unwrap();
        let labels: Vec<String> = rows(&terms).into_iter().map(|(label, _)| label).collect();
        assert_eq!(labels, ["Request", "Risk level", "Match code"]);
        assert_eq!(
            build_terms(&KEY, &binding("a")).unwrap(),
            build_terms_with_summary(&KEY, &binding("a"), &ActionSummary::default()).unwrap()
        );
    }

    #[test]
    fn summary_values_are_one_short_line() {
        assert_eq!(summary_value("  a\n\tb\u{7}c  ").as_deref(), Some("a b c"));
        let long = summary_value(&"x".repeat(500)).unwrap();
        assert_eq!(long.chars().count(), MAX_SUMMARY_VALUE_CHARS);
        assert!(long.ends_with('…'));
        assert_eq!(summary_value("\n\t"), None);
    }

    #[test]
    fn a_full_summary_stays_inside_pulse_size_limit() {
        let huge = ActionSummary {
            agent: Some("a".repeat(5000)),
            request_type: Some("b".repeat(5000)),
            risk_level: Some("c".repeat(5000)),
            reason: Some("d".repeat(5000)),
            programs: Some("e".repeat(5000)),
            action_count: Some(usize::MAX),
        };
        let terms = build_terms_with_summary(&KEY, &binding("a"), &huge).unwrap();
        assert!(serde_json::to_vec(&terms).unwrap().len() <= MAX_TERMS_BYTES);
    }

    #[test]
    fn a_batch_names_the_count_and_plural_rows() {
        let summary = ActionSummary {
            agent: Some("Claude Code".into()),
            programs: Some("rm, git, npm".into()),
            risk_level: Some("high".into()),
            action_count: Some(3),
            ..ActionSummary::default()
        };
        let terms = build_terms_with_summary(&KEY, &binding("allow"), &summary).unwrap();
        let headline = terms["summary"].as_str().unwrap();
        assert!(
            headline.starts_with("Approve 3 agent actions Guard paused: rm, git, npm. Match code "),
            "{headline}"
        );
        let labels: Vec<&str> = terms["details"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["label"].as_str().unwrap())
            .collect();
        assert_eq!(
            labels,
            [
                "Request",
                "Programs",
                "Agents",
                "Highest risk level",
                "Match code"
            ]
        );
        let single = ActionSummary {
            action_count: Some(1),
            ..summary
        };
        let terms = build_terms_with_summary(&KEY, &binding("allow"), &single).unwrap();
        assert!(terms["summary"]
            .as_str()
            .unwrap()
            .starts_with("Approve an agent action Guard paused: "));
    }
}
