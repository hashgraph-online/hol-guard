//! Managed-controls state verification and composition.

use guard_command::extension_control::{ControlLayerKind, ControlState};
use guard_contracts::ExtensionControlAuthorityRequestV1;
use serde_json::{json, Value};

use super::layers::layers_to_json;
use super::records::{authenticated_record, canonical, sha256_hex};
use super::tests::{catalog, layer, local, manifest, object, read_request, run, Home, KEY};

fn revision_state(revision: i64) -> Value {
    let (record, digest, mac) = authenticated_record(
        &object(json!({ "revision": revision })),
        &KEY,
        "managed-controls.revision",
    )
    .unwrap();
    json!({ "revision": revision, "authentication": { "record": record, "digest": digest, "mac": mac } })
}

fn activation_state(catalog_digest: &str, revision: i64) -> Value {
    let layers = layers_to_json(&[layer(
        ControlLayerKind::SignedCloud,
        catalog_digest,
        ControlState::Enabled,
    )])
    .unwrap();
    let mut unsigned = object(json!({
        "schemaVersion": "guard.managed-controls-activation.v1",
        "complete": true,
        "catalogDigest": catalog_digest,
        "extensionAuthorityRevision": revision,
        "signedCloudLayersJson": layers,
        "bundleHash": "bundle-hash",
        "bundleVersion": "7",
    }));
    let mut projection = unsigned.clone();
    projection.remove("complete");
    let projection_digest = sha256_hex(&canonical(&Value::Object(projection)).unwrap());
    unsigned.insert(
        "acknowledgement".to_owned(),
        json!({
            "bundleHash": "bundle-hash",
            "bundleVersion": "7",
            "extensionAuthorityRevision": revision,
            "catalogDigest": catalog_digest,
            "effectiveProjectionDigest": projection_digest,
        }),
    );
    let activation = object(json!({ "activation": Value::Object(unsigned.clone()) }));
    let (record, digest, mac) =
        authenticated_record(&activation, &KEY, "managed-controls.activation").unwrap();
    unsigned.insert(
        "authentication".to_owned(),
        json!({ "record": record, "digest": digest, "mac": mac }),
    );
    Value::Object(unsigned)
}

#[test]
fn managed_ops_verify_their_state() {
    let home = Home::new();
    let revision = ExtensionControlAuthorityRequestV1 {
        state: Some(revision_state(4)),
        ..home.request("managed_revision", &catalog('a'))
    };
    assert_eq!(run(&revision)["revision"], json!(4));

    let activation = ExtensionControlAuthorityRequestV1 {
        state: Some(activation_state(&catalog('a'), 2)),
        catalog_digest: None,
        ..home.request("managed_activation", &catalog('a'))
    };
    let result = run(&activation);
    assert_eq!(result["revision"], json!(2));
    assert_eq!(result["layers"][0]["kind"], json!("signed-cloud"));

    let mut forged = activation_state(&catalog('a'), 2);
    forged["bundleVersion"] = json!("8");
    let forged = ExtensionControlAuthorityRequestV1 {
        state: Some(forged),
        ..activation
    };
    assert_eq!(
        run(&forged)["reason"],
        json!("managed controls activation payload mismatch")
    );
}

#[test]
fn compose_managed_adds_the_signed_layer() {
    let home = Home::new();
    let anchor = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    let view = run(&read_request(&home, &catalog('a'), Some(anchor)))["view"].clone();
    let compose = ExtensionControlAuthorityRequestV1 {
        view: Some(view),
        ..home.request("compose_managed", &catalog('a'))
    };
    assert_eq!(run(&compose)["view"]["layers"].as_array().unwrap().len(), 1);

    home.set_state(
        "managed_controls_active",
        &activation_state(&catalog('a'), 2),
    );
    assert_eq!(
        run(&compose)["reason"],
        json!("managed controls revision state is missing")
    );

    home.set_state("managed_controls_revision", &revision_state(2));
    let result = run(&compose);
    assert_eq!(result["view"]["managed_revision"], json!(2));
    assert_eq!(result["view"]["layers"][1]["kind"], json!("signed-cloud"));

    home.set_state("managed_controls_revision", &revision_state(3));
    assert_eq!(
        run(&compose)["reason"],
        json!("managed controls activation revision mismatch")
    );
}

#[test]
fn compose_managed_disables_stale_managed_allows_after_a_catalog_change() {
    let home = Home::new();
    let anchor = home.commit(1, &catalog('b'), &[local(&catalog('b'))], "committed");
    let view = run(&read_request(&home, &catalog('b'), Some(anchor)))["view"].clone();
    home.set_state(
        "managed_controls_active",
        &activation_state(&catalog('a'), 1),
    );
    home.set_state("managed_controls_revision", &revision_state(1));
    let compose = ExtensionControlAuthorityRequestV1 {
        view: Some(view),
        ..home.request("compose_managed", &catalog('b'))
    };
    assert_eq!(
        run(&compose)["reason"],
        json!("managed controls current catalog manifest is missing")
    );

    let with_manifest = ExtensionControlAuthorityRequestV1 {
        current_manifest: Some(manifest("fp1")),
        ..compose
    };
    let managed = &run(&with_manifest)["view"]["layers"][1];
    assert_eq!(managed["catalog_digest"], json!(catalog('b')));
    assert_eq!(managed["controls"][0]["state"], json!("disabled"));
}
