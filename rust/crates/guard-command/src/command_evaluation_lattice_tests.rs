//! Decision-floor lattice and observation projection unit tests.

use crate::command_evaluation::*;

fn rule(severity: &str, mode: &str, compat: bool) -> CommandSafetyRule {
    CommandSafetyRule {
        rule_id: "r".to_owned(),
        severity: severity.to_owned(),
        risk_classes: vec![],
        action_classes: vec![],
        description: "desc".to_owned(),
        safer_alternatives: vec![],
        default_mode: mode.to_owned(),
        compatibility_fallback: compat,
        rule_version: "1".to_owned(),
    }
}

fn owned(rule: CommandSafetyRule, required: bool) -> OwnedCommandRuleMatch {
    OwnedCommandRuleMatch {
        extension_id: "ext".to_owned(),
        extension_required: required,
        extension_provenance_digest: String::new(),
        extension_trust_class: "internal".to_owned(),
        rule,
        action_class: None,
        reason: "r".to_owned(),
        matcher_evidence: vec![],
        parse_confidence: "exact".to_owned(),
    }
}

#[test]
fn rule_floor_required_critical_blocks() {
    assert_eq!(
        rule_floor(&owned(rule("critical", "review", false), true)),
        CommandDecisionFloor::Block
    );
}

#[test]
fn rule_floor_required_noncritical_reviews() {
    assert_eq!(
        rule_floor(&owned(rule("high", "enforce", false), true)),
        CommandDecisionFloor::Review
    );
}

#[test]
fn rule_floor_disabled_allows() {
    assert_eq!(
        rule_floor(&owned(rule("low", "disabled", false), true)),
        CommandDecisionFloor::Allow
    );
}

#[test]
fn rule_floor_maps_mode() {
    assert_eq!(
        rule_floor(&owned(rule("low", "monitor", false), false)),
        CommandDecisionFloor::Monitor
    );
    assert_eq!(
        rule_floor(&owned(rule("low", "enforce", false), false)),
        CommandDecisionFloor::Block
    );
}

#[test]
fn stronger_floor_takes_higher_rank() {
    assert_eq!(
        stronger_floor(CommandDecisionFloor::Monitor, CommandDecisionFloor::Block),
        CommandDecisionFloor::Block
    );
    assert_eq!(
        stronger_floor(CommandDecisionFloor::Block, CommandDecisionFloor::Allow),
        CommandDecisionFloor::Block
    );
}

#[test]
fn decision_action_floor_maps_classes() {
    assert_eq!(decision_action_floor("allow"), CommandDecisionFloor::Allow);
    assert_eq!(decision_action_floor("warn"), CommandDecisionFloor::Monitor);
    assert_eq!(decision_action_floor("block"), CommandDecisionFloor::Block);
    assert_eq!(
        decision_action_floor("review"),
        CommandDecisionFloor::Review
    );
    assert_eq!(decision_action_floor("other"), CommandDecisionFloor::Review);
}

#[test]
fn precedence_prefers_floor_then_severity_then_noncompat() {
    let a = owned(rule("critical", "enforce", false), false);
    let b = owned(rule("low", "enforce", false), false);
    assert!(match_precedence_key(&a) > match_precedence_key(&b));
    let c = owned(rule("critical", "enforce", true), false);
    assert!(match_precedence_key(&a) > match_precedence_key(&c));
}

#[test]
fn risk_table_matches_python_entries() {
    assert_eq!(
        risk_classes_for_command_action("destructive shell command"),
        &["destructive_shell"]
    );
    assert_eq!(
        risk_classes_for_command_action("credential exfiltration shell command"),
        &[
            "data_flow_exfiltration",
            "credential_exfiltration",
            "network_egress"
        ]
    );
    // Normalization: strip + lowercase.
    assert_eq!(
        risk_classes_for_command_action("  Git Destructive Command "),
        &["destructive_shell"]
    );
    assert_eq!(
        risk_classes_for_command_action("unknown class"),
        &[] as &[&str]
    );
}

#[test]
fn observation_effective_evidence_excludes_safe_variant_segments() {
    let obs = NativeCommandExtensionObservation {
        extension_id: "e".to_owned(),
        extension_version: "1".to_owned(),
        extension_required: true,
        rule_id: "r".to_owned(),
        rule_version: "1".to_owned(),
        rule_severity: "high".to_owned(),
        rule_default_mode: "review".to_owned(),
        rule_risk_classes: vec![],
        rule_action_classes: vec![],
        matcher_evidence: vec![
            NativeMatcherEvidence {
                segment_index: 0,
                executable: None,
                detail: "d0".to_owned(),
            },
            NativeMatcherEvidence {
                segment_index: 1,
                executable: None,
                detail: "d1".to_owned(),
            },
        ],
        safe_variants: vec![NativeSafeVariantObservation {
            variant_id: "v".to_owned(),
            matcher_evidence: vec![NativeMatcherEvidence {
                segment_index: 1,
                executable: None,
                detail: "d1".to_owned(),
            }],
        }],
        uncertainty_reasons: vec![],
    };
    let eff = obs.effective_evidence();
    assert_eq!(eff.len(), 1);
    assert_eq!(eff[0].segment_index, 0);
    assert_eq!(obs.match_class(), "unsafe");
    assert_eq!(obs.match_classes(), vec!["unsafe"]);
}
