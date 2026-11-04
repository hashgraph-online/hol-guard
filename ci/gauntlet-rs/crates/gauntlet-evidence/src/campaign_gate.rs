//! Pure Python-parity reduction of an already-audited campaign ledger.
//!
//! This does not load or authenticate attempts, provider usage, effects,
//! product custody or native surfaces. It cannot grant CI eligibility.

use crate::crypto::sha256;
use crate::episode_score::evaluate_audited_episode;
use crate::{canonical_value, EvidenceError, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

fn required_u64(value: &Value, field: &str) -> Result<u64> {
    value[field]
        .as_u64()
        .ok_or(EvidenceError::Invalid("invalid audited campaign budget"))
}

fn token_charge(report: &Value, budgets: &Value) -> Result<u64> {
    let reserved = match report["group"].as_str() {
        Some("approval") => required_u64(budgets, "model_tokens")?
            .checked_mul(2)
            .ok_or(EvidenceError::Invalid(
                "approval token reservation overflow",
            ))?,
        _ => required_u64(budgets, "model_tokens")?,
    };
    let observed = report["model_tokens"].as_u64();
    if matches!(report["group"].as_str(), Some("developer" | "approval")) && observed.is_none() {
        return Err(EvidenceError::Invalid("invalid audited provider usage"));
    }
    Ok(match (report["model_usage_known"].as_bool(), observed) {
        (Some(true), Some(tokens)) => tokens,
        (_, Some(tokens)) => tokens.max(reserved),
        _ => reserved,
    })
}

fn policy_rules<'a>(cells: &[Value], policy: &'a Value) -> Result<BTreeMap<&'a str, &'a Value>> {
    let entries = policy["cells"]
        .as_array()
        .ok_or(EvidenceError::Invalid("audited policy cells missing"))?;
    let mut rules = BTreeMap::new();
    for rule in entries {
        let id = rule["episode_id"]
            .as_str()
            .ok_or(EvidenceError::Invalid("audited policy episode missing"))?;
        if rules.insert(id, rule).is_some() {
            return Err(EvidenceError::Invalid("duplicate audited policy episode"));
        }
    }
    let ids: BTreeSet<&str> = cells
        .iter()
        .map(|cell| {
            cell["id"]
                .as_str()
                .ok_or(EvidenceError::Invalid("audited campaign cell ID missing"))
        })
        .collect::<Result<_>>()?;
    if ids.len() != cells.len() || ids != rules.keys().copied().collect() {
        return Err(EvidenceError::Invalid(
            "audited policy coverage differs from selection",
        ));
    }
    Ok(rules)
}

/// Match Python `_evaluate_audited_state` over state already authenticated by
/// a separate trusted reader. `observations` is indexed by episode ID and
/// contains separately proven `cleanup_verified` and `surfaces` values.
pub fn evaluate_audited_campaign(
    state: &Value,
    policy: &Value,
    observations: &Value,
) -> Result<Value> {
    let config = &state["config"];
    let valid_layout = (config["schema"] == "gauntlet-local-campaign.v1"
        && config.get("attempt_layout").is_none())
        || (config["schema"] == "gauntlet-local-campaign.v2"
            && config["attempt_layout"] == "compact-v1");
    if !valid_layout {
        return Err(EvidenceError::Invalid("unsupported audited attempt layout"));
    }
    let cells = config["cells"]
        .as_array()
        .ok_or(EvidenceError::Invalid("audited campaign cells missing"))?;
    let rules = policy_rules(cells, policy)?;
    let budgets = &config["campaign"]["budgets"];
    let retries = required_u64(budgets, "max_retries")?;
    let ledger = state["ledger"]
        .as_array()
        .ok_or(EvidenceError::Invalid("audited campaign ledger missing"))?;
    let mut errors = BTreeSet::new();
    if config["execution_lane"] != "live" || config["runtime"]["isolated"] != true {
        errors.insert("isolated-live-execution-required");
    }
    if config["runtime"]["protected_adapter"] == "hol-guard"
        && cells.iter().any(|cell| cell["protected"] == true)
        && config["runtime"]["product_isolated"] != true
    {
        errors.insert("product-isolation-required");
    }
    let mut charged = 0_u64;
    let mut elapsed_integer = 0_u64;
    let mut elapsed_floating = 0_f64;
    let mut elapsed_has_float = false;
    let mut final_events: BTreeMap<&str, Option<&Value>> = BTreeMap::new();
    for entry in ledger {
        let event = &entry["event"];
        let key = event["episode_id"]
            .as_str()
            .ok_or(EvidenceError::Invalid("audited event episode missing"))?;
        match event["type"].as_str() {
            Some("unsupported") => {
                if final_events.insert(key, None).is_some() {
                    errors.insert("duplicate-terminal-outcome");
                }
            }
            Some("finish") => {
                let report = &event["report"];
                let cost = token_charge(report, budgets)?;
                charged = charged
                    .checked_add(cost)
                    .ok_or(EvidenceError::Invalid("audited token charge overflow"))?;
                let seconds = &event["elapsed_seconds"];
                let valid = seconds
                    .as_f64()
                    .filter(|value| value.is_finite() && *value >= 0.0);
                if let Some(value) = valid {
                    if seconds.is_i64() || seconds.is_u64() {
                        elapsed_integer = elapsed_integer
                            .checked_add(
                                seconds
                                    .as_u64()
                                    .ok_or(EvidenceError::Invalid("negative elapsed time"))?,
                            )
                            .ok_or(EvidenceError::Invalid("elapsed time overflow"))?;
                    } else {
                        elapsed_has_float = true;
                        elapsed_floating += value;
                    }
                } else {
                    errors.insert("attempt-elapsed-time-invalid");
                }
                if event["charged_tokens"].as_u64() != Some(cost) {
                    errors.insert("attempt-token-charge-mismatch");
                }
                let no_inference = report["inference_started"] == false
                    && report["zero_model_requests_proven"] == true
                    && report["model_tokens"] == 0;
                if report["model_usage_known"] != true && !no_inference {
                    errors.insert("attempt-model-usage-unknown");
                }
                let retry = event["retry"]
                    .as_bool()
                    .ok_or(EvidenceError::Invalid("audited retry bit missing"))?;
                if retry && report["score"]["security_status"] == "violated" {
                    errors.insert("security-violation-in-retried-attempt");
                }
                if !retry {
                    if event["attempt"]
                        .as_u64()
                        .is_none_or(|attempt| attempt > retries)
                    {
                        return Err(EvidenceError::Invalid(
                            "audited attempt exceeds retry bounds",
                        ));
                    }
                    if final_events.insert(key, Some(event)).is_some() {
                        errors.insert("duplicate-terminal-outcome");
                    }
                }
            }
            _ => {}
        }
    }
    if charged > required_u64(budgets, "campaign_tokens")? {
        errors.insert("campaign-model-token-cap-exceeded");
    }
    let elapsed = elapsed_integer as f64 + elapsed_floating;
    if elapsed > required_u64(budgets, "campaign_seconds")? as f64 {
        errors.insert("campaign-active-time-cap-exceeded");
    }
    let mut rows = Vec::new();
    for cell in cells {
        let id = cell["id"]
            .as_str()
            .ok_or(EvidenceError::Invalid("audited campaign cell ID missing"))?;
        let rule = rules[id];
        let event = match final_events.get(id) {
            Some(Some(event)) => *event,
            other => {
                rows.push(json!({
                    "episode_id": id,
                    "outcome": rule["outcome"],
                    "status": "failed",
                    "reasons": [if other.is_some() { "required-surface-unsupported" } else { "scheduled-outcome-missing" }],
                }));
                continue;
            }
        };
        let observed = &observations[id];
        let cleanup = observed["cleanup_verified"]
            .as_bool()
            .ok_or(EvidenceError::Invalid(
                "audited cleanup observation missing",
            ))?;
        let surfaces: BTreeSet<String> = observed["surfaces"]
            .as_array()
            .ok_or(EvidenceError::Invalid(
                "audited surface observations missing",
            ))?
            .iter()
            .map(|surface| {
                surface
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(EvidenceError::Invalid("invalid audited native surface"))
            })
            .collect::<Result<_>>()?;
        let profile = config["runtime"]["mcp_protocol_profiles"]
            .get(id)
            .filter(|value| !value.is_null());
        rows.push(evaluate_audited_episode(
            cell,
            rule,
            &event["report"],
            cleanup,
            &surfaces,
            profile,
        )?);
    }
    let passed = errors.is_empty() && rows.iter().all(|row| row["status"] != "failed");
    let elapsed_value = if elapsed_has_float {
        json!(elapsed)
    } else {
        json!(elapsed_integer)
    };
    Ok(json!({
        "schema": "gauntlet-ci-gate-result.v1",
        "policy_id": policy["id"],
        "config_digest": config["config_digest"],
        "policy_digest": sha256(&canonical_value(policy)?),
        "status": if passed { "passed" } else { "failed" },
        "exit_code": if passed { 0 } else { 1 },
        "errors": errors,
        "cells": rows,
        "selected_cases": cells.len(),
        "charged_model_tokens_all_attempts": charged,
        "active_seconds_all_attempts": elapsed_value,
        "qualification_eligible": false,
        "trust_status": "local-integrity-only",
        "limitations": [
            "requires independently reviewed trusted-base consumer for production",
            "native contained execution requires scoped local conformance; Guard external approval remains unsupported"
        ],
    }))
}
