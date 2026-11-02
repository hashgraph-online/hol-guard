//! Generated differential cases for hosted cloud action evaluation.
//!
//! Three families, all deterministic from fixed seeds:
//! - canonicalization: random argument documents, each written several
//!   equivalent ways, must give one identity and one decision, and a one-leaf
//!   change must give a different identity;
//! - bounds: arguments exactly at the size limit stay accepted however they
//!   are spelled, and one canonical byte more is refused however it is spelled;
//! - capabilities: every binding, every subset of target capabilities and
//!   every starting rule, with and without a matching saved consent, against
//!   a model of the documented decision order.
//!
//! A generated mismatch is shrunk to a minimal case, written to a file and
//! printed, so it can be added to `differential-corpus.json`, which every run
//! replays.

mod generate;

use super::*;
use generate::*;

const CORPUS: &str = include_str!("../../tests/fixtures/cloud-action/differential-corpus.json");
const SEEDS: u64 = 160;
const CAPABILITIES: [&str; 5] = [
    "egress-pinned",
    "bounded-output",
    "resource-allowlist",
    "no-filesystem",
    "no-subprocess",
];
/// Identity and action for one raw argument text on the read binding.
fn answer(evaluator: &CloudActionEvaluator, raw: &str) -> (Value, Value) {
    let mut request = request_for(evaluator);
    set_action(&mut request, LIST, json!({}));
    let result = evaluator.evaluate(line_with_raw_arguments(&request, raw).as_bytes());
    let outcome = result
        .get("error")
        .map_or(result["action"].clone(), |error| error["code"].clone());
    (result["action_identity_sha256"].clone(), outcome)
}

/// The spellings that disagree with the first, if any.
fn disagreement(evaluator: &CloudActionEvaluator, texts: &[String]) -> Option<String> {
    let first = answer(evaluator, &texts[0]);
    texts[1..]
        .iter()
        .find(|text| answer(evaluator, text) != first)
        .map(|text| format!("{} vs {text}: {first:?}", texts[0]))
}

/// Write a minimal failing case where a person can pick it up, and return
/// a message that carries it in full.
fn retain(family: &str, seed: u64, case: Value) -> String {
    let directory = std::env::temp_dir().join("guard-cloud-action-differential");
    retain_in(&directory, family, seed, case)
}

fn retain_in(directory: &std::path::Path, family: &str, seed: u64, case: Value) -> String {
    let path = directory.join(format!("{family}-{seed}.json"));
    let written = std::fs::create_dir_all(directory)
        .and_then(|()| std::fs::write(&path, serde_json::to_vec_pretty(&case).unwrap()));
    let location = written.map_or_else(
        |error| format!("not written: {error}"),
        |()| path.display().to_string(),
    );
    format!("{family} mismatch at seed {seed}; minimal case ({location}):\n{case:#}")
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    schema: String,
    #[serde(rename = "note")]
    _note: String,
    cases: Vec<CorpusCase>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusCase {
    id: String,
    #[serde(rename = "why")]
    _why: String,
    spellings: Vec<String>,
    distinct: Vec<String>,
}

#[test]
fn the_retained_corpus_still_holds() {
    let corpus: Corpus = serde_json::from_str(CORPUS).unwrap();
    assert_eq!(corpus.schema, "guard.cloud-action-differential-corpus.v1");
    let evaluator = evaluator();
    for case in &corpus.cases {
        assert!(case.spellings.len() >= 2, "{}", case.id);
        let first = answer(&evaluator, &case.spellings[0]);
        assert!(first.0.is_string(), "{}: {first:?}", case.id);
        assert_eq!(
            disagreement(&evaluator, &case.spellings),
            None,
            "{}",
            case.id
        );
        for other in &case.distinct {
            let identity = answer(&evaluator, other).0;
            assert!(identity.is_string(), "{}: {other}: {identity:?}", case.id);
            assert_ne!(identity, first.0, "{}: {other}", case.id);
        }
    }
}

#[test]
fn equivalent_spellings_share_one_identity_and_one_decision() {
    let evaluator = evaluator();
    for seed in 0..SEEDS {
        let arguments = object(&mut Rng::new(seed), 3);
        let decided = answer(&evaluator, &arguments.to_string());
        assert!(decided.0.is_string(), "seed {seed}: {decided:?}");
        let fails = |candidate: &Value| {
            candidate.is_object() && disagreement(&evaluator, &spellings(seed, candidate)).is_some()
        };
        if fails(&arguments) {
            let minimal = shrink(arguments, &fails);
            let detail = disagreement(&evaluator, &spellings(seed, &minimal));
            let case = json!({"spellings": spellings(seed, &minimal), "detail": detail});
            panic!("{}", retain("canonical", seed, case));
        }
    }
}

#[test]
fn changing_any_one_leaf_changes_the_identity() {
    let evaluator = evaluator();
    for seed in 0..SEEDS {
        let arguments = object(&mut Rng::new(seed), 3);
        let before = answer(&evaluator, &arguments.to_string());
        assert!(before.0.is_string(), "seed {seed}: {before:?}");
        let mut paths = Vec::new();
        leaves(&arguments, &mut Vec::new(), &mut paths);
        for path in &paths {
            let mut edited = arguments.clone();
            let mut slot = &mut edited;
            for step in path {
                slot = match step {
                    Value::String(key) => &mut slot[key.as_str()],
                    _ => &mut slot[step.as_u64().unwrap() as usize],
                };
            }
            *slot = changed(slot);
            let after = answer(&evaluator, &edited.to_string());
            // A rejected edit has no identity, so it would differ without
            // proving a second valid action.
            if !after.0.is_string() || before.0 == after.0 {
                let case = json!({"distinct": [arguments.to_string(), edited.to_string()]});
                panic!("{}", retain("sensitivity", seed, case));
            }
        }
    }
}

#[test]
fn the_size_limit_is_on_canonical_bytes_however_arguments_are_spelled() {
    let evaluator = evaluator();
    let overhead = canonical_bytes(&json!({"pad": ""})).unwrap().len();
    for (extra, expected) in [(0, "allow"), (1, "too_large")] {
        let pad = "a".repeat(MAX_ARGUMENT_BYTES - overhead + extra);
        let plain = json!({"pad": pad}).to_string();
        // Six raw bytes per canonical byte: the text is far past the limit.
        let escaped = format!("{{ \"pad\" : \"{}\" }}", "\\u0061".repeat(pad.len()));
        let answers = [answer(&evaluator, &plain), answer(&evaluator, &escaped)];
        assert_eq!(answers[0], answers[1], "{extra}");
        assert_eq!(answers[0].1, expected, "{extra}");
    }
}

fn effect_floor(effect: &str) -> GuardAction {
    match effect {
        "read" => GuardAction::Allow,
        "write" => GuardAction::Review,
        "destructive" => GuardAction::RequireReapproval,
        _ => GuardAction::Block,
    }
}

/// The documented order, written out independently of the evaluator.
fn modelled(
    effect: &str,
    rule: Option<GuardAction>,
    missing: bool,
    consent: bool,
) -> (GuardAction, Vec<&'static str>) {
    let (mut action, base) = match (effect, rule) {
        ("admin", _) => (GuardAction::Block, "admin_effect_unsupported"),
        (_, Some(rule)) => (rule, "policy_rule"),
        (_, None) => (effect_floor(effect), "effect_floor"),
    };
    if missing && action.severity() < GuardAction::SandboxRequired.severity() {
        action = GuardAction::SandboxRequired;
    }
    let reviewable = matches!(action, GuardAction::Review | GuardAction::RequireReapproval);
    let consent_applies = consent && reviewable;
    if consent_applies {
        action = GuardAction::Allow;
    }
    let raised: &[&str] = match (missing && action != GuardAction::Block, consent_applies) {
        (_, true) => &["saved_consent_always"],
        (true, false) if action == GuardAction::SandboxRequired => &["capability_unavailable"],
        _ => &[],
    };
    let mut reasons = vec![base];
    reasons.extend_from_slice(raised);
    (action, reasons)
}

#[test]
fn every_capability_subset_and_rule_matches_the_decision_order() {
    let set: Value = serde_json::from_str(BINDINGS).unwrap();
    let evaluator = evaluator();
    let rules = [
        None,
        Some(GuardAction::Allow),
        Some(GuardAction::Warn),
        Some(GuardAction::Review),
        Some(GuardAction::RequireReapproval),
        Some(GuardAction::Block),
    ];
    let mut checked = 0;
    for binding in set["bindings"].as_array().unwrap() {
        let action_id = binding["action_id"].as_str().unwrap();
        let effect = binding["effect"].as_str().unwrap();
        let required: Vec<&str> = binding["required_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        for mask in 0..(1u32 << CAPABILITIES.len()) {
            let present: Vec<&str> = (0..CAPABILITIES.len())
                .filter(|bit| mask & (1 << bit) != 0)
                .map(|bit| CAPABILITIES[bit])
                .collect();
            let missing: Vec<&str> = required
                .iter()
                .filter(|needed| !present.contains(needed))
                .copied()
                .collect();
            for rule_action in rules {
                let mut request = request_for(&evaluator);
                request["connection"]["provider"] = binding["adapter"]["provider"].clone();
                let arguments = match action_id {
                    POST => json!({"channel": "C0SYNTH01", "text": "hello"}),
                    ARCHIVE => json!({"channel": "C0SYNTH01"}),
                    TRANSFER => json!({"user": "U0SYNTH01"}),
                    LIST => json!({}),
                    _ => json!({"query": "differential"}),
                };
                set_action(&mut request, action_id, arguments);
                request["target_capabilities"] = json!(present);
                if let Some(rule_action) = rule_action {
                    request["policy"]["rules"] =
                        json!([rule("r", rule_action.as_str(), action_id)]);
                }
                let identity = identity_of(&evaluator, &request);
                for consent_given in [false, true] {
                    if consent_given {
                        request["saved_consents"] = json!([consent("c", "always", &identity)]);
                    }
                    let result = run(&evaluator, &request);
                    let (action, reasons) =
                        modelled(effect, rule_action, !missing.is_empty(), consent_given);
                    let context = format!(
                        "{action_id} present={present:?} rule={rule_action:?} consent={consent_given}: {result}"
                    );
                    assert_eq!(result["action"], action.as_str(), "{context}");
                    let mut reported: Vec<&str> = result["missing_capabilities"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter_map(Value::as_str)
                        .collect();
                    reported.sort_unstable();
                    let mut expected = missing.clone();
                    expected.sort_unstable();
                    assert_eq!(reported, expected, "{context}");
                    assert_eq!(
                        result["dispatch_permitted"],
                        matches!(action, GuardAction::Allow | GuardAction::Warn),
                        "{context}"
                    );
                    assert_eq!(result["reason_codes"], json!(reasons), "{context}");
                    checked += 1;
                }
            }
        }
    }
    assert_eq!(checked, 5 * 32 * 6 * 2);
}

#[test]
fn a_mismatch_shrinks_to_a_minimal_retained_case() {
    let mut rng = Rng::new(7);
    let mut noisy = object(&mut rng, 3);
    noisy["needle"] = json!({"deep": ["x", "planted"]});
    let contains_planted = |value: &Value| value.to_string().contains("planted");
    let minimal = shrink(noisy, &contains_planted);
    assert_eq!(minimal, json!({"needle": {"deep": ["planted"]}}));
    // A scratch directory of its own: the shared one keeps real mismatches.
    let scratch = tempfile::tempdir().unwrap();
    let message = retain_in(
        scratch.path(),
        "self-check",
        0,
        json!({"spellings": [minimal.to_string()]}),
    );
    assert!(message.contains("planted"), "{message}");
}
