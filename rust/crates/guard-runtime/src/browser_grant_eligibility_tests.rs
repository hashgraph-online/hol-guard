use serde_json::{json, Value};

use super::*;

const CATEGORY: &str = "browser_interaction";
const HARD: [&str; 11] = [
    "browser_guard_origin",
    "browser_transfer",
    "browser_privileged",
    "browser_sensitive_surface",
    "secret_access",
    "filesystem_access",
    "command_execution",
    "destructive_mutation",
    "privileged_system_mutation",
    "tool_schema_mismatch",
    "browser_navigation",
];
const TARGETS: [&str; 7] = [
    "exact",
    "category",
    "server",
    "session-site",
    "site-category",
    "site",
    "site-group",
];

#[test]
fn the_tier_follows_the_risks_beyond_the_routine_category() {
    let routine = Some(GrantTier::Routine);
    let shared = Some(GrantTier::SharedSession);
    let rows: [(&[&str], Option<GrantTier>); 7] = [
        (&[CATEGORY], routine),
        (&[CATEGORY, "browser_external_domain"], routine),
        (&[CATEGORY, SHARED_PROFILE_RISK], shared),
        (
            &[CATEGORY, SHARED_PROFILE_RISK, "browser_external_domain"],
            shared,
        ),
        (&[SHARED_PROFILE_RISK], None),
        (&["browser_external_domain"], None),
        (&[], None),
    ];
    for (risks, expected) in rows {
        assert_eq!(grant_tier(CATEGORY, risks), expected, "{risks:?}");
    }
}

#[test]
fn every_hard_exclusion_fails_both_tiers() {
    for hard in HARD {
        for base in [vec![CATEGORY], vec![CATEGORY, SHARED_PROFILE_RISK]] {
            let mut risks = base.clone();
            risks.push(hard);
            assert_eq!(grant_tier(CATEGORY, &risks), None, "{risks:?}");
        }
    }
}

fn surface(fields: Value) -> bool {
    surface_clean(fields.as_object().expect("object"))
}

#[test]
fn a_clean_surface_names_no_sensitive_flag_element_or_input() {
    let clean = [
        json!({}),
        json!({"sensitive_surface_flags": []}),
        json!({"sensitive_surface_flags": null, "element": null, "input": null}),
        json!({"element": {"is_password": false, "is_payment": false, "role": "button"}}),
        json!({"input": {"kind": "text", "preview_class": "plain"}}),
        json!({"input": {"preview_class": "empty"}}),
    ];
    for fields in clean {
        assert!(surface(fields.clone()), "{fields}");
    }
    let unclean = [
        json!({"sensitive_surface_flags": ["cookies"]}),
        json!({"sensitive_surface_flags": ["password_field"]}),
        json!({"sensitive_surface_flags": "cookies"}),
        json!({"element": {"is_password": true}}),
        json!({"element": {"is_payment": true}}),
        json!({"element": {"is_password": "false"}}),
        json!({"element": "password"}),
        json!({"input": {"preview_class": "looks_like_secret"}}),
        json!({"input": {"preview_class": "looks_like_payment"}}),
        json!({"input": {"preview_class": 1}}),
        json!({"input": "secret"}),
    ];
    for fields in unclean {
        assert!(!surface(fields.clone()), "{fields}");
    }
}

#[test]
fn each_tier_allows_its_targets_by_surface() {
    for target in TARGETS {
        let legacy = matches!(target, "exact" | "category" | "server");
        assert!(GrantTier::Routine.allows(target, true), "{target}");
        assert_eq!(GrantTier::Routine.allows(target, false), legacy, "{target}");
        assert_eq!(
            GrantTier::SharedSession.allows(target, true),
            target == "session-site",
            "{target}"
        );
        assert!(!GrantTier::SharedSession.allows(target, false), "{target}");
    }
}
