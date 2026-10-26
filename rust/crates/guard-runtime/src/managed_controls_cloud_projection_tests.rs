use super::*;

fn parsed() -> Value {
    let document = json!({"x-hol-extension-controls":{"schemaVersion":CONTROLS_SCHEMA,
        "authorityMode":"managed-restrictive","controls":[{"targetKind":"extension",
        "targetId":"command.git","state":"disabled"}]},"spec":{"rules":[]}});
    let catalog =
        json!({"extensions":{"command.git":{"required":false,"delegated":false}},"permissions":{}});
    super::super::evaluate(&json!({"document":document,"catalog":catalog,
        "capabilities":[LAYER_CAP,TARGETS_CAP,ATOMIC_CAP]}))
    .unwrap()["ok"]
        .clone()
}

fn metadata() -> Vec<Value> {
    vec![
        json!({"id":"command.git","version":"1.0.0","name":"Git protection",
        "source":"built-in","executables":["git"],"ecosystemIds":["git"],
        "riskClasses":["source-control"],"delegatedProtection":null,"deprecated":false,
        "replacementId":null,"permissions":[{"id":"command.git.permission.force-push",
        "name":"Force push","configurable":true,"required":false,
        "riskClasses":["destructive"],"typedCapabilities":["git.push.force"]}]}),
    ]
}

#[test]
fn synthetic_server_v1_v2_bytes_and_digests() {
    // Synthetic protocol vectors; no private observation or workspace data.
    let parsed = parsed();
    let legacy = proof(
        &parsed,
        "c4b0c22d97418dfa85745f77c3f3b14e951f14a514ac74c237e6977388334035",
        None,
    )
    .unwrap();
    assert_eq!(
        legacy["digest"],
        "sha256:2a4ce5e603e81f3f5c77a88875e9354e097a3265ba80dbbf43433944bfad90b5"
    );
    let v2 = proof(&parsed, &"a".repeat(64), Some(&metadata())).unwrap();
    assert_eq!(
        v2["digest"],
        "sha256:49aea52b8f60997028ed6889889c395152436a580138871f42f7453976d2b20d"
    );
    let expected = concat!(
        r#"{"authorityMode":"managed-restrictive","delegatedTargets":[],"enforcementCatalogDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ruleTargets":[],"schemaVersion":"guard.signed-cloud-extension-projection.v2","signedCloudLayersJson":"[{\"catalog_digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"controls\":[{\"state\":\"disabled\",\"target_id\":\"command.git\",\"target_kind\":\"extension\"}],\"global_lockdown\":false,\"kind\":\"signed-cloud\",\"schema_version\":\"1.0.0\"}]","targetMetadata":["#,
        r#"{"delegatedProtection":null,"deprecated":false,"ecosystemIds":["git"],"executables":["git"],"id":"command.git","name":"Git protection","permissions":[{"configurable":true,"id":"command.git.permission.force-push","name":"Force push","required":false,"riskClasses":["destructive"],"typedCapabilities":["git.push.force"]}],"replacementId":null,"riskClasses":["source-control"],"source":"built-in","version":"1.0.0"}]}"#
    );
    assert_eq!(v2["canonical_json"], expected);
    let mut changed = metadata();
    changed[0]["permissions"][0]["configurable"] = json!(false);
    assert_ne!(
        proof(&parsed, &"a".repeat(64), Some(&changed)).unwrap()["digest"],
        v2["digest"]
    );
    assert_ne!(
        proof(&parsed, &"b".repeat(64), Some(&metadata())).unwrap()["digest"],
        v2["digest"]
    );
}

#[test]
fn v2_uses_utf8_and_legacy_keeps_ascii() {
    let mut parsed = parsed();
    parsed["rule_targets"] = json!([{"rule_id":"r🌱","extension_ids":[],"permission_ids":[]}]);
    let v1 = proof(&parsed, &"a".repeat(64), None).unwrap();
    let v2 = proof(&parsed, &"a".repeat(64), Some(&metadata())).unwrap();
    assert!(v1["canonical_json"]
        .as_str()
        .unwrap()
        .contains("\\ud83c\\udf31"));
    assert!(v2["canonical_json"].as_str().unwrap().contains('🌱'));
}

fn put(directory: &Path, value: &Value) -> Value {
    let bytes = serde_json::to_vec(value).unwrap();
    let sha = format!("{:x}", Sha256::digest(&bytes));
    std::fs::write(directory.join(format!("{sha}.json")), &bytes).unwrap();
    json!({"sha256":sha,"length":bytes.len(),"expanded_length":bytes.len(),"kind":"data"})
}

fn prepared(home: &Path, count: usize, name: &str) -> Value {
    use guard_command::cloud_catalog::{Builder, Observation};
    let mut observation = Observation {
        guard_home: home.into(),
        discovery_root: "b".repeat(64),
        discovery_authority: "c".repeat(64),
        enforcement_catalog_digest: "a".repeat(64),
        guard_version: "1.0.0".into(),
        generated_at: "2026-10-18T00:00:00Z".into(),
    };
    // Initialize private cache directories before the synthetic discovery CAS.
    drop(Builder::new(observation.clone()).unwrap());
    let directory = home.join("native-runtime/catalog-discovery/objects");
    std::fs::create_dir_all(&directory).unwrap();
    let raw = |i: usize| {
        let target = i == count - 1;
        let id = if target {
            "command.zzz-policy".into()
        } else {
            format!("command.scale-{i:06}")
        };
        let permissions = if target {
            json!([{"extension_id":id,
            "permission_id":"command.zzz-policy.permission.write","label":"Write",
            "configurable":true,"risk_tier":"high","typed_capabilities":["test.write"]}])
        } else {
            json!([])
        };
        json!({"extension_id":id,"name":if target {name} else {"Disabled discovery"},
            "version":"1.0.0","source":"built-in","executables":[],"ecosystem_ids":[],
            "risk_classes":[],"delegated_protection":null,"permissions":permissions})
    };
    let mut next = Value::Null;
    for start in (0..count.div_ceil(64)).rev().map(|i| i * 64) {
        let entries: Vec<_> = (start..(start + 64).min(count))
            .map(|i| {
                let value = raw(i);
                json!([value["extension_id"], put(&directory, &value)])
            })
            .collect();
        next = put(
            &directory,
            &json!({"schema":"guard.catalog-discovery-page.v1","entries":entries,"next":next}),
        );
    }
    let root = put(
        &directory,
        &json!({"schema":"guard.catalog-discovery.v1",
        "authority":observation.discovery_authority,"count":count,"first":next}),
    );
    observation.discovery_root = root["sha256"].as_str().unwrap().into();
    let view = Builder::new(observation.clone()).unwrap().finish().unwrap();
    let identity = json!({"ownerUserId":"fixture-owner", "workspaceId":"fixture-workspace",
        "deviceId":"fixture-device","runtimeId":"fixture-runtime"});
    let mut local = json!({"guard_home":home,"token":view["token"],"observation":observation,
        "identity":identity,"origin":"https://example.test/api/guard/runtime/extension-catalog/sync-v2",
        "credential_binding":"d".repeat(64),"action":"completion_begin"});
    let begun = guard_command::cloud_catalog::evaluate(&local);
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64;
    let observed = crate::policy_bundle_time::micros_to_utc_isoformat(micros, "Z").unwrap();
    // Explicit synthetic authenticated-transport adapter, not HTTP evidence.
    let manifest = &view["manifest"];
    local["response"] = json!({"schemaVersion":"guard.extension-catalog-sync.v2","accepted":true,"complete":true,
        "catalogDigest":manifest["catalogDigest"],"observation":{"schemaVersion":"guard.catalog-observation.v2",
        "nonce":begun["payload"]["idempotencyKey"],"credentialBinding":local["credential_binding"],"identity":identity,
        "catalogDigest":manifest["catalogDigest"],"enforcementCatalogDigest":manifest["enforcementCatalogDigest"],
        "guardVersion":manifest["guardVersion"],"controlSchemaVersion":manifest["controlSchemaVersion"],"observedAt":observed}});
    local["action"] = json!("completion_accept");
    let accepted = guard_command::cloud_catalog::evaluate(&local);
    assert!(accepted.get("error").is_none(), "{accepted}");
    json!({"guard_home":home,"token":view["token"],"observation":observation,
        "view_digest":manifest["catalogDigest"],"observed_at":observed,"now":observed,"identity":identity})
}

fn request(local: Value) -> Value {
    json!({"cloud_view":local,"enforcement_catalog_digest":"a".repeat(64),
        "projection":{"version":2,"catalog_digest":"a".repeat(64)},
        "capabilities":[LAYER_CAP,TARGETS_CAP,ATOMIC_CAP],
        "catalog":{"extensions":{},"permissions":{}},
        "document":{"spec":{"rules":[{"id":"write-review",TARGETS_FIELD:{
            "schemaVersion":TARGETS_SCHEMA,"extensionIds":[],
            "permissionIds":["command.zzz-policy.permission.write"]}}]},
            CONTROLS_FIELD:{"schemaVersion":CONTROLS_SCHEMA,"authorityMode":"managed-restrictive",
                "controls":[{"targetKind":"permission","targetId":"command.zzz-policy.permission.write","state":"disabled"}]}}})
}

fn run(request: &Value) -> Value {
    super::super::evaluate(request).unwrap()
}

#[test]
fn native_complete_view_last_page_proof_growth_and_metadata_binding() {
    let mut prior = None;
    for count in [166, 1660, 16600] {
        let home = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let local = prepared(home.path(), count, "Selected protection");
        let request = request(local);
        let result = run(&request);
        assert!(result.get("error").is_none(), "{result}");
        let projection: Value =
            serde_json::from_str(result["projection"]["canonical_json"].as_str().unwrap()).unwrap();
        assert_eq!(projection["targetMetadata"].as_array().unwrap().len(), 1);
        assert_eq!(projection["targetMetadata"][0]["id"], "command.zzz-policy");
        assert_eq!(projection["enforcementCatalogDigest"], "a".repeat(64));
        if let Some(prior) = prior {
            assert_eq!(
                result["projection"], prior,
                "disabled discovery growth churned proof"
            );
        }
        prior = Some(result["projection"].clone());
        let local = &request["cloud_view"];
        let mut provenance = local["identity"].clone();
        provenance["viewDigest"] = local["view_digest"].clone();
        provenance["enforcementDigest"] = json!("a".repeat(64));
        provenance["observedAt"] = local["observed_at"].clone();
        let mut checked = request.clone();
        checked["target_metadata"] = json!({"kind":"policy-target-metadata.v2", "provenance":provenance,
            "extensions":projection["targetMetadata"]});
        assert_eq!(run(&checked), result);
        for field in [
            "ownerUserId",
            "workspaceId",
            "deviceId",
            "runtimeId",
            "viewDigest",
            "enforcementDigest",
            "observedAt",
        ] {
            let mut substituted = checked.clone();
            substituted["target_metadata"]["provenance"][field] = json!("substituted");
            assert_eq!(
                run(&substituted)["error"]["code"],
                "policy_target_metadata_mismatch",
                "{field}"
            );
        }
        checked["target_metadata"]["extensions"][0]["name"] = json!("Substituted metadata");
        assert_eq!(
            run(&checked)["error"]["code"],
            "policy_target_metadata_mismatch"
        );
        let mut stale = request.clone();
        stale["cloud_view"]["now"] = json!("2099-10-18T00:15:01Z");
        assert_eq!(run(&stale)["error"]["code"], "policy_observation_stale");
        let mut changed = request.clone();
        changed["cloud_view"] = prepared(home.path(), count, "Changed selected protection");
        assert_ne!(
            run(&changed)["projection"]["digest"],
            result["projection"]["digest"]
        );
        assert_eq!(
            run(&checked)["error"]["code"],
            "policy_completed_observation_invalid"
        );
    }
}

#[test]
fn native_delivery_catalog_digest_binds_the_enforcement_identity() {
    let home = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let request = request(prepared(home.path(), 166, "Selected protection"));
    let mut bound = request.clone();
    bound["delivery_catalog_digest"] = json!("a".repeat(64));
    assert!(
        run(&bound).get("error").is_none(),
        "a delivery envelope cut against this enforcement identity was refused"
    );
    for substituted in [json!("b".repeat(64)), Value::Null, json!(1)] {
        let mut mismatched = request.clone();
        mismatched["delivery_catalog_digest"] = substituted.clone();
        assert_eq!(
            run(&mismatched)["error"]["code"],
            "policy_enforcement_digest_mismatch",
            "{substituted}"
        );
    }
    // An absent key means no delivery envelope accompanied this document.
    assert!(run(&request).get("error").is_none());
}

#[test]
fn native_v2_delivery_and_ack_round_trip_binds_enforcement_identity() {
    use crate::policy_bundle_delivery::{ack_payload, validate_delivery, AckRequest};
    let projected = proof(&parsed(), &"a".repeat(64), Some(&metadata())).unwrap();
    let bundle = json!({"contractVersion":"guard-policy-bundle.v2","bundleHash":format!("sha256:{}","b".repeat(64)),
        "bundleVersion":1,"workspaceId":"fixture-workspace","payloadHash":format!("sha256:{}","c".repeat(64)),
        "payload":{"metadata":{"revision":1}},"rollback":{"lastGoodBundleHash":null}});
    let delivery = json!({"bundleId":"fixture-bundle","bundleHash":bundle["bundleHash"],
        "bundleVersion":1,"workspaceId":"fixture-workspace","deviceId":"fixture-device",
        "runtimeSessionId":"fixture-runtime","deliveryId":"12345678-1234-5234-8234-123456789abc",
        "policyRevision":1,"extensionAuthorityRevision":0,"catalogDigest":"a".repeat(64),
        "effectiveProjectionDigest":format!("sha256:{}","d".repeat(64)),"payloadHash":bundle["payloadHash"],
        "extensionProjectionDigest":projected["digest"],"lastKnownGoodBundleHash":null});
    let summary = json!({"runtime_device_id":"fixture-device","runtime_session_id":"fixture-runtime",
        "extensionCatalogDigest":"e".repeat(64),"extensionCatalogViewDigest":"f".repeat(64),
        "extensionCatalogEnforcementDigest":"a".repeat(64),"managedControlsCapabilities":["extension-catalog.v2"],
        "extensionAuthorityRevision":0,"effectiveProjectionDigest":delivery["effectiveProjectionDigest"]});
    let validate = |delivery: &Value, summary: &Value| {
        validate_delivery(
            delivery,
            bundle.as_object().unwrap(),
            Some("fixture-workspace"),
            "fixture-device",
            Some(summary),
        )
    };
    assert_eq!(validate(&delivery, &summary), Ok(()));
    for digest in ["e".repeat(64), "f".repeat(64)] {
        let mut bad = delivery.clone();
        bad["catalogDigest"] = json!(digest);
        assert!(validate(&bad, &summary).is_err());
    }
    let mut grown = summary.clone();
    grown["extensionCatalogViewDigest"] = json!("9".repeat(64));
    assert_eq!(validate(&delivery, &grown), Ok(()));
    let revision = json!(1);
    let effective = json!(format!("sha256:{}", "1".repeat(64)));
    let ack = ack_payload(&AckRequest {
        device_id: "fixture-device",
        device_name: "Fixture",
        bundle: bundle.as_object().unwrap(),
        synced_at: "2026-10-18T00:00:00Z",
        status: "applied",
        previous: None,
        delivery: delivery.as_object(),
        applied_revision: Some(&revision),
        applied_digest: Some(&effective),
    })
    .unwrap();
    assert_eq!(ack["status"], "applied");
    for field in ["catalogDigest", "extensionProjectionDigest", "deliveryId"] {
        assert_eq!(ack[field], delivery[field]);
    }
}
