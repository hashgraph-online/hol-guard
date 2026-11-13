//! Benign and attack task corpora for the shipped cloud action packs.
//!
//! Each case is one call an agent would make while doing a task. The benign
//! corpus is ordinary work: under the Balanced preset at most a small share of
//! it may ask the user and none of it may be blocked. The attack corpus is
//! what a compromised or confused agent attempts: none of it may run without
//! the user. Every case also states its exact expected decision, so a policy
//! change that moves one shows up here by name.

use std::collections::BTreeMap;

use guard_contracts::{ActionFactsV2, Fact, FindingV2, PiiKindV2, SensitivityV2, SessionFlowV2};
use serde_json::{json, Value};

use crate::cloud_action_inspect::{inspect, INSPECT_REQUEST_SCHEMA};
use crate::cloud_pack::{parse_pack, CloudActionPack, PackAction};
use crate::cloud_pack_facts::extract;
use crate::cloud_pack_request::{check_arguments, render};
use crate::cloud_policy_pack::{shipped, FactCall, Preset};
use crate::effect_decision::GuardAction;

const PACKS: [&str; 6] = [
    include_str!("../../../../contributions/cloud-actions/calendar.json"),
    include_str!("../../../../contributions/cloud-actions/drive.json"),
    include_str!("../../../../contributions/cloud-actions/github.json"),
    include_str!("../../../../contributions/cloud-actions/gmail.json"),
    include_str!("../../../../contributions/cloud-actions/notion.json"),
    include_str!("../../../../contributions/cloud-actions/slack.json"),
];
const BENIGN: &str = include_str!("../../../../tests/fixtures/cloud_benign_corpus.json");
const ATTACK: &str = include_str!("../../../../tests/fixtures/cloud_attack_corpus.json");
const REFUSED: &str = "invalid_argument";

/// Credentials assembled at run time so no file in this repository holds a
/// whole token of a shape a credential scanner recognises.
fn secret(kind: &str) -> String {
    match kind {
        "github" => format!("{}{}{}", "ghp_", "7Qk2TzVx9Lm", "R4Hb8Nd3PwYs6"),
        "slack" => format!(
            "{}{}{}",
            "xox", "b-2840117355-", "6120394817265-Qz8Lm3Tk9Vx2Rb7Nw4Hd5Ps1"
        ),
        "aws" => format!(
            "{}{} aws_secret_access_key={}{}",
            "AKIA", "QYLPT3K7R4FXM2WD", "wJ7rXu9Kp2Lm4Nq8Tv3Bz6Yc", "5Hd1Fg0Se7Ra2Wx9Qk4"
        ),
        "pem" => format!(
            "-----{} RSA {} KEY-----\n{}\n{}\n-----END RSA {} KEY-----",
            "BEGIN",
            "PRIVATE",
            "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MaGBlS1pYh5XQkGq",
            "pYh5XQkGqFZ7v2pM9VbTcN8dK3sLr4QwXyUe6HgJm1nOaIbRcDfEgHiJkLmNoPqR",
            "PRIVATE"
        ),
        "stripe" => format!("{}{}{}", "sk_", "live_", "4eC39HqLyjWDarjtT1zdp7dc"),
        other => panic!("unknown secret kind {other}"),
    }
}

fn fill_secrets(value: &mut Value) {
    match value {
        Value::String(text) => {
            while let Some(start) = text.find("${secret:") {
                let end = start + text[start..].find('}').expect("closed placeholder");
                let kind = text[start + 9..end].to_string();
                text.replace_range(start..=end, &secret(&kind));
            }
        }
        Value::Array(items) => items.iter_mut().for_each(fill_secrets),
        Value::Object(map) => map.values_mut().for_each(fill_secrets),
        _ => {}
    }
}

fn packs() -> Vec<CloudActionPack> {
    PACKS
        .iter()
        .map(|text| parse_pack(text.as_bytes()).expect("shipped pack"))
        .collect()
}

fn find<'a>(packs: &'a [CloudActionPack], id: &str) -> (&'a str, &'a PackAction) {
    packs
        .iter()
        .find_map(|pack| {
            pack.actions
                .iter()
                .find(|action| action.action_id == id)
                .map(|action| (pack.provider.id.as_str(), action))
        })
        .unwrap_or_else(|| panic!("no shipped action {id}"))
}

fn inspected(arguments: &Value, result: &Value) -> Value {
    let line = json!({
        "schema": INSPECT_REQUEST_SCHEMA,
        "request_id": "corpus",
        "arguments": arguments,
        "result": result,
    });
    let output = inspect(&serde_json::to_vec(&line).unwrap());
    assert_eq!(output["error"], Value::Null, "inspection refused: {output}");
    output
}

fn merge<T: serde::de::DeserializeOwned + Ord>(into: &mut Vec<T>, found: &Value) {
    into.extend(serde_json::from_value::<Vec<T>>(found.clone()).unwrap());
    into.sort();
    into.dedup();
}

/// Folds what content inspection found into the facts, as the gateway does
/// before deciding.
fn with_findings(mut facts: ActionFactsV2, output: &Value) -> ActionFactsV2 {
    merge::<FindingV2>(&mut facts.findings, &output["fact_findings"]);
    merge::<PiiKindV2>(&mut facts.pii_kinds, &output["pii_kinds"]);
    if let Fact::Known(sensitivity) = &mut facts.sensitivity {
        merge::<SensitivityV2>(sensitivity, &output["sensitivity_hints"]);
    }
    facts
}

fn session(case: &Value) -> Option<SessionFlowV2> {
    let session = case.get("session")?;
    let prior = inspected(&Value::Null, &json!({"body": session["prior"]}));
    let injection = prior["fact_findings"]
        .as_array()
        .unwrap()
        .contains(&json!("injection_signal_in_result"));
    Some(SessionFlowV2 {
        untrusted_content_seen: true,
        sensitive_data_seen: session["sensitiveDataSeen"].as_bool().unwrap_or(false),
        injection_signal_seen: injection,
    })
}

/// The decision for one case, or [`REFUSED`] when the pack refuses its
/// arguments before any decision is made.
fn decide(packs: &[CloudActionPack], case: &Value) -> String {
    let (provider, action) = find(packs, case["actionId"].as_str().unwrap());
    let mut arguments = case["arguments"].clone();
    fill_secrets(&mut arguments);
    let Ok(record) = check_arguments(action, &arguments) else {
        return REFUSED.to_string();
    };
    if render(action, &arguments).is_err() {
        return REFUSED.to_string();
    }
    let facts = with_findings(
        extract(action, record),
        &inspected(&arguments, &Value::Null),
    );
    let flow = session(case);
    let mut windows = BTreeMap::from([("recoverable_deletes_1h".to_string(), 0)]);
    if let Some(given) = case.get("windows").and_then(Value::as_object) {
        for (id, count) in given {
            windows.insert(id.clone(), count.as_u64().unwrap());
        }
    }
    let call = FactCall {
        provider,
        action_id: &action.action_id,
        effect: action.safety.effect,
        facts: &facts,
        session: flow.as_ref(),
        windows: Some(&windows),
    };
    shipped(Preset::Balanced).decide(&call).as_str().to_string()
}

fn corpus(text: &str, kind: &str) -> (Value, Vec<(Value, String)>) {
    let corpus: Value = serde_json::from_str(text).unwrap();
    assert_eq!(corpus["schema"], "guard.cloud-action-corpus.v1");
    assert_eq!(corpus["kind"], kind);
    assert_eq!(corpus["preset"], "balanced");
    let packs = packs();
    let decided = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| (case.clone(), decide(&packs, case)))
        .collect();
    (corpus, decided)
}

fn mismatches(decided: &[(Value, String)]) -> Vec<String> {
    decided
        .iter()
        .filter(|(case, got)| case["expect"].as_str() != Some(got.as_str()))
        .map(|(case, got)| {
            format!(
                "{} {}: expected {}, got {got}",
                case["id"], case["actionId"], case["expect"]
            )
        })
        .collect()
}

#[test]
fn benign_tasks_rarely_ask_and_are_never_blocked() {
    let (corpus, decided) = corpus(BENIGN, "benign");
    assert!(
        decided.len() >= 150,
        "benign corpus has {} cases",
        decided.len()
    );
    let wrong = mismatches(&decided);
    assert!(
        wrong.is_empty(),
        "benign decisions moved:\n{}",
        wrong.join("\n")
    );
    let blocked: Vec<_> = decided
        .iter()
        .filter(|(_, got)| got == GuardAction::Block.as_str() || got == REFUSED)
        .map(|(case, _)| case["id"].clone())
        .collect();
    assert!(blocked.is_empty(), "benign cases blocked: {blocked:?}");
    let asked = decided
        .iter()
        .filter(|(_, got)| got != GuardAction::Allow.as_str())
        .count();
    let limit = corpus["maxReviewRate"].as_f64().unwrap();
    let rate = asked as f64 / decided.len() as f64;
    assert!(
        rate <= limit,
        "benign review rate {rate:.3} exceeds {limit}"
    );
}

#[test]
fn no_attack_runs_without_the_user() {
    let (_, decided) = corpus(ATTACK, "attack");
    assert!(
        decided.len() >= 80,
        "attack corpus has {} cases",
        decided.len()
    );
    let ran: Vec<_> = decided
        .iter()
        .filter(|(_, got)| got == GuardAction::Allow.as_str() || got == GuardAction::Warn.as_str())
        .map(|(case, got)| format!("{} {} {got}", case["id"], case["actionId"]))
        .collect();
    assert!(
        ran.is_empty(),
        "attacks ran without the user:\n{}",
        ran.join("\n")
    );
    let wrong = mismatches(&decided);
    assert!(
        wrong.is_empty(),
        "attack decisions moved:\n{}",
        wrong.join("\n")
    );
}

#[test]
fn every_secret_kind_is_one_the_inspector_finds() {
    for kind in ["github", "slack", "aws", "pem", "stripe"] {
        let output = inspected(&json!({"text": secret(kind)}), &Value::Null);
        assert_eq!(
            output["fact_findings"],
            json!(["secret_in_arguments"]),
            "{kind}"
        );
    }
}
