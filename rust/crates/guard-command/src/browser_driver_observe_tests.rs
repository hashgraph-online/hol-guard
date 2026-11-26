use serde_json::json;

use super::*;
use crate::browser_driver_compile::{compile_browser_driver, BrowserDriverOrigin};
use GuardAction::{Allow, Block, Review, Warn};

const PILOT: &str = "browser.example-pilot";
const FIRST: &str = "browser.example-first";

fn driver(id: &str, origin: BrowserDriverOrigin) -> CompiledBrowserDriverV1 {
    let profile = json!({
        "schemaVersion": "guard.browser-driver.v1",
        "id": id,
        "name": "Example browser tools",
        "publisher": {"name": "Example Org", "verified": false},
        "match": {
            "mcpServerNames": [],
            "packages": [],
            "toolNamespaces": [format!("mcp__{}__", id.trim_start_matches("browser."))],
            "harnessTools": []
        },
        "profileMode": {"default": "unknown"},
        "tools": [{"name": "open_page", "verb": "Navigate", "url": ["url"]}]
    });
    compile_browser_driver(&serde_json::to_vec(&profile).unwrap(), origin, &[]).unwrap()
}

fn control(
    layer: ControlLayerKind,
    id: &str,
    effect: BrowserMappingEffect,
) -> BrowserMappingEffectControl {
    BrowserMappingEffectControl {
        layer,
        driver_id: id.to_owned(),
        effect,
    }
}

fn decide(
    floor: GuardAction,
    without_mapping: GuardAction,
    with_mapping: GuardAction,
    effect: BrowserMappingEffect,
) -> BrowserMappingDecision {
    browser_mapping_decision(BrowserMappingDecisionInput {
        floor,
        without_mapping,
        with_mapping,
        effect,
    })
}

#[test]
fn a_contributed_profile_is_enforced_unless_a_layer_asks_to_observe() {
    let pilot = driver(PILOT, BrowserDriverOrigin::Contributed);
    assert_eq!(
        browser_mapping_effect(&pilot, &[]),
        BrowserMappingEffect::Enforce
    );
    for layer in [ControlLayerKind::LocalAdmin, ControlLayerKind::SignedCloud] {
        let observe = [control(layer, PILOT, BrowserMappingEffect::Observe)];
        assert_eq!(
            browser_mapping_effect(&pilot, &observe),
            BrowserMappingEffect::Observe
        );
    }
    let other = [control(
        ControlLayerKind::LocalAdmin,
        FIRST,
        BrowserMappingEffect::Observe,
    )];
    assert_eq!(
        browser_mapping_effect(&pilot, &other),
        BrowserMappingEffect::Enforce
    );
}

#[test]
fn any_enforce_wins_over_observe() {
    let pilot = driver(PILOT, BrowserDriverOrigin::Contributed);
    for controls in [
        [
            control(
                ControlLayerKind::LocalAdmin,
                PILOT,
                BrowserMappingEffect::Observe,
            ),
            control(
                ControlLayerKind::SignedCloud,
                PILOT,
                BrowserMappingEffect::Enforce,
            ),
        ],
        [
            control(
                ControlLayerKind::SignedCloud,
                PILOT,
                BrowserMappingEffect::Enforce,
            ),
            control(
                ControlLayerKind::LocalAdmin,
                PILOT,
                BrowserMappingEffect::Observe,
            ),
        ],
    ] {
        assert_eq!(
            browser_mapping_effect(&pilot, &controls),
            BrowserMappingEffect::Enforce
        );
    }
}

#[test]
fn a_first_party_profile_ignores_observe() {
    let first = driver(FIRST, BrowserDriverOrigin::FirstParty);
    let observe = [control(
        ControlLayerKind::LocalAdmin,
        FIRST,
        BrowserMappingEffect::Observe,
    )];
    assert_eq!(
        browser_mapping_effect(&first, &observe),
        BrowserMappingEffect::Enforce
    );
}

#[test]
fn an_observed_louder_mapping_keeps_the_decision_and_records_what_it_would_do() {
    let decision = decide(Allow, Allow, Review, BrowserMappingEffect::Observe);
    assert_eq!(decision.policy_action, Allow);
    assert_eq!(decision.observed_policy_action, Some(Review));
    assert_eq!(decision.reason_code, Some(BROWSER_MAPPING_OBSERVED));
    assert_eq!(
        serde_json::to_value(decision).unwrap(),
        json!({
            "policy_action": "allow",
            "observed_policy_action": "review",
            "reason_code": "browser.driver_mapping_observed",
        })
    );

    let decision = decide(Warn, Review, Block, BrowserMappingEffect::Observe);
    assert_eq!(decision.policy_action, Review);
    assert_eq!(decision.observed_policy_action, Some(Block));
}

#[test]
fn an_enforced_louder_mapping_decides_the_call() {
    let decision = decide(Allow, Allow, Review, BrowserMappingEffect::Enforce);
    assert_eq!(decision.policy_action, Review);
    assert_eq!(decision.observed_policy_action, None);
    assert_eq!(decision.reason_code, None);
    assert_eq!(
        serde_json::to_value(decision).unwrap(),
        json!({"policy_action": "review"})
    );
}

#[test]
fn the_floor_holds_under_either_effect() {
    for effect in [BrowserMappingEffect::Observe, BrowserMappingEffect::Enforce] {
        // A sensitive-surface screen's review stands whatever the mapping says.
        let decision = decide(Review, Allow, Allow, effect);
        assert_eq!(decision.policy_action, Review, "{effect:?}");
        assert_eq!(decision.observed_policy_action, None, "{effect:?}");
        // A mapping no louder than the floor has nothing to observe.
        let decision = decide(Block, Allow, Review, effect);
        assert_eq!(decision.policy_action, Block, "{effect:?}");
        assert_eq!(decision.observed_policy_action, None, "{effect:?}");
    }
    // Observe keeps Guard's own decision at the floor and records the louder mapping above it.
    let decision = decide(Review, Allow, Block, BrowserMappingEffect::Observe);
    assert_eq!(decision.policy_action, Review);
    assert_eq!(decision.observed_policy_action, Some(Block));
}

#[test]
fn a_mapping_that_is_not_louder_applies_as_written() {
    for effect in [BrowserMappingEffect::Observe, BrowserMappingEffect::Enforce] {
        let quieter = decide(Allow, Review, Allow, effect);
        assert_eq!(quieter.policy_action, Allow, "{effect:?}");
        assert_eq!(quieter.observed_policy_action, None, "{effect:?}");
        let same = decide(Allow, Review, Review, effect);
        assert_eq!(same.policy_action, Review, "{effect:?}");
        assert_eq!(same.observed_policy_action, None, "{effect:?}");
    }
}

#[test]
fn every_action_pair_is_decided_both_ways() {
    let lattice = [
        Allow,
        Warn,
        Review,
        GuardAction::RequireReapproval,
        GuardAction::SandboxRequired,
        Block,
    ];
    for floor in lattice {
        for without_mapping in lattice {
            for with_mapping in lattice {
                let enforced = decide(
                    floor,
                    without_mapping,
                    with_mapping,
                    BrowserMappingEffect::Enforce,
                );
                let observed = decide(
                    floor,
                    without_mapping,
                    with_mapping,
                    BrowserMappingEffect::Observe,
                );
                // Never below the floor, and observe is never louder than enforce.
                assert!(enforced.policy_action.severity() >= floor.severity());
                assert!(observed.policy_action.severity() >= floor.severity());
                assert!(observed.policy_action.severity() <= enforced.policy_action.severity());
                match observed.observed_policy_action {
                    // What observe records is exactly what enforce decides.
                    Some(action) => {
                        assert_eq!(action, enforced.policy_action);
                        assert!(action.severity() > observed.policy_action.severity());
                    }
                    None => assert_eq!(observed, enforced),
                }
            }
        }
    }
}
