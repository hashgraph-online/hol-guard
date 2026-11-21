use super::*;
use guard_command::extension_control::{
    ControlLayerKind, ControlState, ControlTarget, ControlTargetKind,
};

// Digests the Python `ExtensionControlMutation` and `ExtensionControlEnrollment`
// computed for these exact inputs before the resident took them over.
const MUTATION_DIGEST: &str = "864b425798605db58a8af6761e9224c5f8efca61761e95a8d3ecba1964c1febf";
const ENROLLMENT_DIGEST: &str = "c11b524f977b40ba53292b2d956770a4186c3e46c9f88d2e46a1536ba2ec29e0";
const EMPTY_MUTATION_DIGEST: &str =
    "f5c1464cd84e8f1e9404ed558c883b56bfccb210848ec404defc911b617f8426";
const ACTOR: &str = "local-admin \u{e9}";

fn catalog() -> String {
    "ab".repeat(32)
}

fn control(kind: ControlTargetKind, target_id: &str, state: ControlState) -> ExtensionControl {
    ExtensionControl {
        target: ControlTarget::new(kind, target_id.to_owned()).unwrap(),
        state,
    }
}

fn layer(
    kind: ControlLayerKind,
    lockdown: bool,
    controls: Vec<ExtensionControl>,
) -> ExtensionControlLayer {
    ExtensionControlLayer {
        schema_version: "1.0.0".to_owned(),
        kind,
        catalog_digest: catalog(),
        global_lockdown: lockdown,
        controls,
    }
}

fn local_controls() -> Vec<ExtensionControl> {
    vec![
        control(
            ControlTargetKind::Permission,
            "command.alpha.permission.write",
            ControlState::Enabled,
        ),
        control(
            ControlTargetKind::Extension,
            "command.alpha",
            ControlState::Disabled,
        ),
        control(
            ControlTargetKind::Extension,
            "command.alpha",
            ControlState::Enabled,
        ),
    ]
}

fn mutation<'a>(catalog: &'a str, layers: &'a [ExtensionControlLayer]) -> Mutation<'a> {
    Mutation {
        previous_revision: 7,
        catalog_digest: catalog,
        layers,
        actor_id: ACTOR,
        idempotency_key: "mutation-1",
        nonce: "nonce-1",
    }
}

#[test]
fn mutation_digest_matches_the_python_digest() {
    let catalog = catalog();
    let layers = [
        layer(ControlLayerKind::SignedCloud, true, Vec::new()),
        layer(ControlLayerKind::LocalAdmin, false, local_controls()),
    ];
    assert_eq!(
        mutation_digest(&mutation(&catalog, &layers)).unwrap(),
        MUTATION_DIGEST
    );
}

#[test]
fn mutation_digest_ignores_layer_and_control_order() {
    let catalog = catalog();
    let mut reversed = local_controls();
    reversed.reverse();
    let layers = [
        layer(ControlLayerKind::LocalAdmin, false, reversed),
        layer(ControlLayerKind::SignedCloud, true, Vec::new()),
    ];
    assert_eq!(
        mutation_digest(&mutation(&catalog, &layers)).unwrap(),
        MUTATION_DIGEST
    );
}

#[test]
fn empty_mutation_digest_matches_the_python_digest() {
    let catalog = catalog();
    let digest = mutation_digest(&Mutation {
        previous_revision: 0,
        catalog_digest: &catalog,
        layers: &[],
        actor_id: "a",
        idempotency_key: "i",
        nonce: "n",
    })
    .unwrap();
    assert_eq!(digest, EMPTY_MUTATION_DIGEST);
}

#[test]
fn every_bound_field_changes_the_mutation_digest() {
    let catalog = catalog();
    let layers = [layer(ControlLayerKind::LocalAdmin, false, local_controls())];
    let base = mutation_digest(&mutation(&catalog, &layers)).unwrap();
    let other_catalog = "cd".repeat(32);
    let lockdown = [layer(ControlLayerKind::LocalAdmin, true, local_controls())];
    let variants = [
        Mutation {
            previous_revision: 8,
            ..mutation(&catalog, &layers)
        },
        Mutation {
            catalog_digest: &other_catalog,
            ..mutation(&catalog, &layers)
        },
        Mutation {
            layers: &lockdown,
            ..mutation(&catalog, &layers)
        },
        Mutation {
            actor_id: "other",
            ..mutation(&catalog, &layers)
        },
        Mutation {
            idempotency_key: "mutation-2",
            ..mutation(&catalog, &layers)
        },
        Mutation {
            nonce: "nonce-2",
            ..mutation(&catalog, &layers)
        },
    ];
    for variant in &variants {
        assert_ne!(mutation_digest(variant).unwrap(), base);
    }
}

#[test]
fn mutation_digest_refuses_invalid_fields() {
    let catalog = catalog();
    let upper = catalog.to_uppercase();
    let long = "x".repeat(257);
    let cases = [
        (
            Mutation {
                previous_revision: -1,
                ..mutation(&catalog, &[])
            },
            INVALID_REVISION,
        ),
        (
            Mutation {
                catalog_digest: &upper,
                ..mutation(&catalog, &[])
            },
            INVALID_CATALOG_DIGEST,
        ),
        (
            Mutation {
                catalog_digest: "ab",
                ..mutation(&catalog, &[])
            },
            INVALID_CATALOG_DIGEST,
        ),
        (
            Mutation {
                actor_id: " \t\u{1f}",
                ..mutation(&catalog, &[])
            },
            INVALID_IDENTITY,
        ),
        (
            Mutation {
                idempotency_key: "",
                ..mutation(&catalog, &[])
            },
            INVALID_IDENTITY,
        ),
        (
            Mutation {
                nonce: &long,
                ..mutation(&catalog, &[])
            },
            INVALID_IDENTITY,
        ),
    ];
    for (case, code) in &cases {
        assert_eq!(mutation_digest(case), Err(*code));
    }
}

#[test]
fn identity_length_counts_characters() {
    let catalog = catalog();
    let wide = "\u{e9}".repeat(256);
    assert!(mutation_digest(&Mutation {
        actor_id: &wide,
        ..mutation(&catalog, &[])
    })
    .is_ok());
}

#[test]
fn enrollment_digest_matches_the_python_digest() {
    assert_eq!(
        enrollment_digest(&catalog(), ACTOR, "enrollment-nonce").unwrap(),
        ENROLLMENT_DIGEST
    );
}

#[test]
fn enrollment_digest_refuses_invalid_fields() {
    let catalog = catalog();
    assert_eq!(
        enrollment_digest("", ACTOR, "nonce"),
        Err(INVALID_CATALOG_DIGEST)
    );
    assert_eq!(
        enrollment_digest(&catalog, "  ", "nonce"),
        Err(INVALID_IDENTITY)
    );
    assert_eq!(
        enrollment_digest(&catalog, ACTOR, &"n".repeat(257)),
        Err(INVALID_IDENTITY)
    );
}
