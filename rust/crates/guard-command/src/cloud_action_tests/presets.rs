//! Every cell of the risk-family table (PRD 6.2), decided by the evaluator
//! under the shipped Relaxed, Balanced and Strict policy packs.

use super::v2::{assert_v2, facts, v2_request};
use super::*;
use crate::cloud_action_classifier::classify;
use crate::cloud_policy_pack::{shipped, PolicyPack, Preset};

const WINDOW: &str = "recoverable_deletes_1h";

pub(super) fn preset(preset: Preset) -> PolicyPack {
    let pack = shipped(preset).clone();
    assert_eq!(pack.preset, preset);
    pack
}

/// One call: its facts, the session so far and the window counters.
pub(super) struct Call {
    pub(super) facts: Value,
    pub(super) session: Value,
    pub(super) windows: Value,
}

pub(super) fn call(class: &str, patch: Value) -> Call {
    let mut base = facts(class);
    for (key, value) in patch.as_object().unwrap() {
        if key == "audience" {
            for (field, fact) in value.as_object().unwrap() {
                base["audience"][field] = fact.clone();
            }
        } else {
            base[key] = value.clone();
        }
    }
    Call {
        facts: base,
        session: json!({"untrusted_content_seen": false, "sensitive_data_seen": false,
                        "injection_signal_seen": false}),
        windows: json!({ WINDOW: 0 }),
    }
}

impl Call {
    fn session(mut self, flags: &[&str]) -> Self {
        for flag in flags {
            self.session[*flag] = true.into();
        }
        self
    }

    fn windows(mut self, windows: Value) -> Self {
        self.windows = windows;
        self
    }
}

/// The binding whose effect matches the class, so the facts alone decide.
fn binding_for(class: &str) -> (&'static str, Value) {
    match class {
        "read" => (LIST, json!({})),
        "delete" => (ARCHIVE, json!({"channel": "C0SYNTH01"})),
        "admin" => (TRANSFER, json!({"user": "U0SYNTH01"})),
        _ => (POST, json!({"channel": "C0SYNTH01", "text": "hi"})),
    }
}

pub(super) fn decide(pack: &PolicyPack, call: &Call) -> Value {
    let evaluator = evaluator();
    let mut request = v2_request(&evaluator);
    let class = call.facts["class"].as_str().unwrap();
    let (action_id, arguments) = binding_for(class);
    set_action(&mut request, action_id, arguments);
    request["facts"] = call.facts.clone();
    request["session_flow"] = call.session.clone();
    request["usage_windows"] = call.windows.clone();
    request["policy"]["fact_rules"] = json!(pack.fact_rules());
    request["policy"]["pack_digest"] = pack.digest().into();
    let result = run(&evaluator, &request);
    assert_v2(&result);
    result
}

fn known<T: serde::Serialize>(value: T) -> Value {
    json!({"state": "known", "value": value})
}

fn unknown() -> Value {
    json!({"state": "unknown"})
}

fn money(amount_minor: u64) -> Value {
    known(json!({"amount_minor": amount_minor, "currency": "USD", "direction": "out"}))
}

fn named(external: bool, domain: &str, recipients: u64) -> Value {
    json!({
        "recipient_count": known(recipients),
        "audience": {
            "kind": known("named"),
            "recipient_domains": known([domain]),
            "external": known(external),
        },
    })
}

fn merge(mut left: Value, right: Value) -> Value {
    for (key, value) in right.as_object().unwrap() {
        left[key] = value.clone();
    }
    left
}

fn one(object: &str) -> Value {
    json!({"object": known(object), "scope": known("single"), "record_count": known(1)})
}

/// (family, call, [relaxed, balanced, strict])
fn table() -> Vec<(&'static str, Call, [&'static str; 3])> {
    let permanent = |count: Value, scope: &str| json!({"reversibility": known("permanent"), "record_count": count, "scope": known(scope)});
    let recoverable = |count: u64| json!({"record_count": known(count)});
    let table_drop = |environment: Value| {
        json!({"object": known("table"), "reversibility": known("permanent"),
               "environment": environment})
    };
    let internal = named(false, "example.com", 3);
    vec![
        ("read", call("read", json!({})), ["allow", "allow", "allow"]),
        (
            "draft",
            call("draft", json!({})),
            ["allow", "allow", "allow"],
        ),
        (
            "R1",
            call("delete", permanent(known(12), "enumerated")),
            ["review", "review", "block"],
        ),
        (
            "R1 bulk",
            call("delete", permanent(known(60), "enumerated")),
            ["review", "require-reapproval", "block"],
        ),
        (
            "R1 all",
            call("delete", permanent(unknown(), "all")),
            ["review", "require-reapproval", "block"],
        ),
        (
            "R1 unknown count",
            call("delete", permanent(unknown(), "query_selected")),
            ["review", "require-reapproval", "block"],
        ),
        (
            "R2",
            call("delete", recoverable(12)),
            ["allow", "allow", "review"],
        ),
        (
            "R2 at limit",
            call("delete", recoverable(25)).windows(json!({ WINDOW: 75 })),
            ["allow", "allow", "review"],
        ),
        (
            "R2 per call",
            call("delete", recoverable(30)),
            ["allow", "review", "review"],
        ),
        (
            "R2 per hour",
            call("delete", recoverable(12)).windows(json!({ WINDOW: 95 })),
            ["allow", "review", "review"],
        ),
        (
            "R2 no counter",
            call("delete", recoverable(12)).windows(json!({})),
            ["allow", "review", "review"],
        ),
        (
            "R3 production",
            call("delete", table_drop(known("production"))),
            ["require-reapproval", "block", "block"],
        ),
        (
            "R3 non-production",
            call("delete", table_drop(known("non_production"))),
            ["require-reapproval", "require-reapproval", "block"],
        ),
        (
            "R3 unknown environment",
            call("delete", table_drop(unknown())),
            ["require-reapproval", "block", "block"],
        ),
        (
            "R3 truncate",
            call("execute", table_drop(known("production"))),
            ["require-reapproval", "block", "block"],
        ),
        (
            "R4 single",
            call("update", one("record")),
            ["allow", "allow", "review"],
        ),
        (
            "R4 bulk",
            call("update", json!({"record_count": known(150)})),
            ["allow", "review", "review"],
        ),
        (
            "R4 query",
            call(
                "update",
                json!({"scope": known("query_selected"), "record_count": unknown()}),
            ),
            ["allow", "review", "review"],
        ),
        (
            "R5",
            call("send", merge(one("message"), named(true, "example.org", 1))),
            ["allow", "review", "review"],
        ),
        (
            "R6",
            call("send", merge(one("message"), internal.clone())),
            ["allow", "allow", "review"],
        ),
        (
            "R6 wide",
            call(
                "send",
                merge(one("message"), named(false, "example.com", 25)),
            ),
            ["allow", "review", "review"],
        ),
        (
            "R7",
            call(
                "share",
                merge(
                    one("file"),
                    json!({"audience": {"kind": known("public"), "external": known(true)}, "sensitivity": known(["public"])}),
                ),
            ),
            ["review", "review", "block"],
        ),
        (
            "R7 confidential",
            call(
                "share",
                merge(
                    one("file"),
                    json!({"audience": {"kind": known("public"), "external": known(true)}, "sensitivity": known(["confidential"])}),
                ),
            ),
            ["review", "block", "block"],
        ),
        (
            "R7 unknown sensitivity",
            call(
                "share",
                merge(
                    one("file"),
                    json!({"audience": {"kind": known("public"), "external": known(true)}}),
                ),
            ),
            ["review", "block", "block"],
        ),
        (
            "R8",
            call(
                "share",
                merge(one("file"), named(true, "partner.example", 1)),
            ),
            ["allow", "review", "review"],
        ),
        (
            "R8 internal",
            call("share", merge(one("file"), internal.clone())),
            ["allow", "allow", "review"],
        ),
        (
            "R9",
            call(
                "export",
                json!({"byte_count": known(1024), "record_count": known(10)}),
            ),
            ["allow", "allow", "review"],
        ),
        (
            "R9 bytes",
            call(
                "export",
                json!({"byte_count": known(20 * 1024 * 1024), "record_count": known(10)}),
            ),
            ["allow", "review", "review"],
        ),
        (
            "R9 records",
            call(
                "export",
                json!({"byte_count": known(1024), "record_count": known(5000)}),
            ),
            ["allow", "review", "review"],
        ),
        (
            "R10",
            call("pay", merge(one("payment"), json!({"money": money(5000)}))),
            ["review", "review", "block"],
        ),
        (
            "R11",
            call("admin", one("user")),
            ["block", "block", "block"],
        ),
        (
            "R12",
            call(
                "send",
                merge(
                    merge(one("message"), internal.clone()),
                    json!({"findings": ["secret_in_arguments"]}),
                ),
            ),
            ["review", "block", "block"],
        ),
        (
            "R13",
            call("send", merge(one("message"), internal.clone()))
                .session(&["untrusted_content_seen", "sensitive_data_seen"]),
            ["warn", "review", "block"],
        ),
        (
            "R13 untrusted only",
            call("send", merge(one("message"), internal.clone()))
                .session(&["untrusted_content_seen"]),
            ["allow", "allow", "review"],
        ),
        (
            "R14 delete",
            call("delete", permanent(known(12), "enumerated")).session(&["injection_signal_seen"]),
            ["review", "require-reapproval", "block"],
        ),
        (
            "R14 recoverable delete",
            call("delete", recoverable(12)).session(&["injection_signal_seen"]),
            ["allow", "require-reapproval", "require-reapproval"],
        ),
        (
            "R14 money",
            call("pay", merge(one("payment"), json!({"money": money(5000)})))
                .session(&["injection_signal_seen"]),
            ["review", "require-reapproval", "block"],
        ),
        (
            "R14 read",
            call("read", json!({})).session(&["injection_signal_seen"]),
            ["allow", "allow", "allow"],
        ),
        (
            "R15 merge",
            call("update", one("branch")),
            ["review", "review", "block"],
        ),
        (
            "R15 branch delete",
            call(
                "delete",
                merge(one("branch"), json!({"reversibility": known("permanent")})),
            ),
            ["review", "block", "block"],
        ),
        (
            "R15 force push",
            call(
                "update",
                merge(one("branch"), json!({"reversibility": known("permanent")})),
            ),
            ["review", "block", "block"],
        ),
        (
            "R15 deploy",
            call(
                "execute",
                merge(
                    one("deployment"),
                    json!({"environment": known("production")}),
                ),
            ),
            ["review", "review", "block"],
        ),
        (
            "R15 secret",
            call("update", one("secret")),
            ["review", "review", "block"],
        ),
    ]
}

#[test]
fn every_risk_family_decides_as_the_table_says() {
    let packs = [
        preset(Preset::Relaxed),
        preset(Preset::Balanced),
        preset(Preset::Strict),
    ];
    let mut failures = Vec::new();
    for (family, call, expected) in table() {
        for (pack, want) in packs.iter().zip(expected) {
            let result = decide(pack, &call);
            if result["action"] != want {
                failures.push(format!(
                    "{family} {}: want {want}, got {} ({})",
                    pack.preset.as_str(),
                    result["action"],
                    result["matched_rule_ids"]
                ));
            }
            assert_eq!(result["pack_digest"], pack.digest(), "{family}");
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn an_unclassified_action_is_never_allowed() {
    for (name, want) in [
        ("list_widgets", ["review", "review", "block"]),
        (
            "purgeWidgetCache",
            ["review", "require-reapproval", "block"],
        ),
        (
            "widgets.transfer_ownership",
            ["review", "require-reapproval", "block"],
        ),
    ] {
        let proposal = classify(name, None);
        for (preset_id, want) in [Preset::Relaxed, Preset::Balanced, Preset::Strict]
            .into_iter()
            .zip(want)
        {
            let action = preset(preset_id).unclassified_action(&proposal);
            assert_eq!(action.as_str(), want, "{name} {}", preset_id.as_str());
        }
    }
}

#[test]
fn a_preset_digest_is_stable_and_names_its_bytes() {
    let balanced = preset(Preset::Balanced);
    assert_eq!(balanced.digest(), preset(Preset::Balanced).digest());
    assert!(is_hex_digest(&balanced.digest().into()));
    let digests: std::collections::BTreeSet<_> =
        [Preset::Relaxed, Preset::Balanced, Preset::Strict]
            .into_iter()
            .map(|p| preset(p).digest().to_owned())
            .collect();
    assert_eq!(digests.len(), 3);
}
