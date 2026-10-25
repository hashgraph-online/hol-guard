use guard_contracts::{ExtensionControlAuthorityRequestV1, ExtensionControlManagedActivationV1};
use serde_json::{json, Value};

use super::tests::{catalog, run, Home};

fn refusal(result: &Value) -> &str {
    assert_eq!(result["fault"], json!("tampered"), "{result}");
    result["reason"].as_str().unwrap()
}

fn input() -> ExtensionControlManagedActivationV1 {
    ExtensionControlManagedActivationV1 {
        bundle: json!({
            "bundleHash": "bundle-hash",
            "bundleVersion": 7,
            "workspaceId": "ws-1",
            "payloadHash": "payload-hash",
            "issuedAt": "  2026-10-21T00:00:00Z\u{1f} ",
            "expiresAt": "   ",
            "payload": {
                "metadata": {
                    "revision": 3.0,
                    "id": format!("\u{1c} control-set \u{e9}{}", "x".repeat(200)),
                    "name": "  Name  ",
                }
            },
        }),
        authority_mode: Some("cloud-managed".to_owned()),
        signed_cloud_layers: json!([{
            "schema_version": "1.0.0",
            "kind": "signed-cloud",
            "catalog_digest": catalog('a'),
            "global_lockdown": false,
            "controls": [{
                "target_kind": "extension",
                "target_id": "command.npm.install",
                "state": "enabled",
            }],
        }]),
        rule_targets: json!([{
            "ruleId": "r1",
            "extensionIds": ["e1", "e2"],
            "permissionIds": ["p1"],
        }]),
        delegated_targets: json!([{
            "targetKind": "extension",
            "targetId": "command.npm.install",
            "enforcementOwner": "hol",
        }]),
        base_revision: 4,
        base_snapshot_digest: catalog('b'),
        managed_revision: 5,
        negotiated_capabilities: vec!["z-cap".to_owned(), "a-cap".to_owned()],
    }
}

fn seal(home: &Home, input: ExtensionControlManagedActivationV1) -> Value {
    run(&ExtensionControlAuthorityRequestV1 {
        managed_activation: Some(input),
        ..home.request("seal_managed_activation", &catalog('a'))
    })
}

#[test]
fn sealed_managed_records_match_the_python_writer_byte_for_byte() {
    let home = Home::new();
    // The MACs the Python builders produced for the same inputs and key.
    let activation = &seal(&home, input())["activation"];
    assert_eq!(
        activation["authentication"]["mac"],
        json!("e480cbaf97b019e86c81367099496fc47c8d07cf06f41d4c39418c636b15d9c8")
    );
    assert_eq!(
        activation["authentication"]["digest"],
        json!("d4e01cb16d563233f9a0809b4defe1a2f7b10a31cb147cf231d83d69170d3fd7")
    );
    assert_eq!(
        activation["acknowledgement"]["effectiveProjectionDigest"],
        json!("d78b7d57d8f3c740c1448fbcbac342b860b95e7254dc86b807006eef9436d260")
    );
    assert_eq!(activation["issuedAt"], json!("2026-10-21T00:00:00Z"));
    assert_eq!(activation.get("expiresAt"), None);
    assert_eq!(activation["provenance"]["policyRevision"], json!(7));
    assert_eq!(activation["controlSetName"], json!("Name"));
    assert_eq!(
        activation["controlSetId"].as_str().unwrap().chars().count(),
        160
    );
    assert_eq!(
        activation["negotiatedCapabilities"],
        json!(["a-cap", "z-cap"])
    );
    let revision = run(&ExtensionControlAuthorityRequestV1 {
        revision: Some(5),
        ..home.request("seal_managed_revision", &catalog('a'))
    });
    assert_eq!(
        revision["state"]["authentication"]["mac"],
        json!("ba953e3cc8905dc12d41bdb924ba12063694e20963c9a4e7c85a844f06022636")
    );
}

#[test]
fn sealed_managed_records_verify_through_the_readers() {
    let home = Home::new();
    let activation = seal(&home, input())["activation"].clone();
    let verified = run(&ExtensionControlAuthorityRequestV1 {
        state: Some(activation),
        ..home.request("managed_activation", &catalog('a'))
    });
    assert_eq!(verified["revision"], json!(5));
    assert_eq!(verified["layers"][0]["kind"], json!("signed-cloud"));
    let state = run(&ExtensionControlAuthorityRequestV1 {
        revision: Some(5),
        ..home.request("seal_managed_revision", &catalog('a'))
    })["state"]
        .clone();
    let verified = run(&ExtensionControlAuthorityRequestV1 {
        state: Some(state),
        ..home.request("managed_revision", &catalog('a'))
    });
    assert_eq!(verified["revision"], json!(5));
}

#[test]
fn incomplete_managed_inputs_are_refused_by_name() {
    let home = Home::new();
    for (revision, reason) in [
        (0, "managed controls revision must be positive"),
        (-1, "managed controls revision must be positive"),
    ] {
        let result = run(&ExtensionControlAuthorityRequestV1 {
            revision: Some(revision),
            ..home.request("seal_managed_revision", &catalog('a'))
        });
        assert_eq!(refusal(&result), reason);
    }
    let with_bundle = |field: &str, value: Value| {
        let mut input = input();
        input.bundle[field] = value;
        input
    };
    for (input, reason) in [
        (
            ExtensionControlManagedActivationV1 {
                managed_revision: 0,
                ..input()
            },
            "managed_revision must be positive",
        ),
        (
            with_bundle("bundleHash", json!("")),
            "managed bundle hash is required",
        ),
        (
            with_bundle("bundleVersion", json!(true)),
            "managed bundle version is required",
        ),
        (
            with_bundle("bundleVersion", json!(7.0)),
            "managed bundle version is required",
        ),
        (
            with_bundle("workspaceId", Value::Null),
            "managed workspace binding is required",
        ),
        (
            with_bundle("payload", json!("text")),
            "managed policy payload is required",
        ),
        (
            ExtensionControlManagedActivationV1 {
                rule_targets: json!({}),
                ..input()
            },
            "invalid managed controls activation targets",
        ),
    ] {
        assert_eq!(refusal(&seal(&home, input)), reason);
    }
    let unkeyed = run(&ExtensionControlAuthorityRequestV1 {
        key_b64: None,
        managed_activation: Some(input()),
        ..home.request("seal_managed_activation", &catalog('a'))
    });
    assert_eq!(
        refusal(&unkeyed),
        "extension control authentication key missing"
    );
}
