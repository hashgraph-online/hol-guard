use super::*;

mod ancestry;
mod spilled_history;

fn installed() -> Identity {
    Identity {
        profile: "installed".into(),
        source: "a".repeat(40),
        engine: "1".repeat(64),
        root: "2".repeat(64),
        version: "3.16.3".into(),
        authority: 2,
        revocation: 4,
    }
}
fn floor() -> Floor {
    let i = installed();
    Floor {
        schema: "guard.command-pack-floor.v1".into(),
        source: i.source.clone(),
        authority: i.authority,
        revocation: i.revocation,
        installed: Some(i),
        remote: None,
    }
}

#[test]
fn separate_profiles_cross_engine_and_source_rollback() {
    let mut remote = installed();
    remote.profile = "remote".into();
    remote.version = "100.7".into();
    remote.root = "3".repeat(64);
    let remote_floor = transition(&floor(), &remote, &Value::Null).unwrap();
    let mut next = installed();
    next.version = "3.16.4".into();
    next.engine = "4".repeat(64);
    next.root = "5".repeat(64);
    next.source = "b".repeat(40);
    let evidence = json!({"status":"ahead","base_commit":{"sha":remote.source},"merge_base_commit":{"sha":remote.source},"head_commit":{"sha":next.source},"behind_by":0,"ahead_by":1});
    let next_floor = transition(&remote_floor, &next, &evidence).unwrap();
    assert_eq!(next_floor.source, remote_floor.source);
    assert_eq!(next_floor.remote.as_ref().unwrap().version, "100.7");
    assert!(transition(&next_floor.clone(), &installed(), &Value::Null).is_err());
}

#[test]
fn pep440_release_order_aliases_and_bounds() {
    let versions = [
        "3.50.0.dev1",
        "3.50.0a1",
        "3.50.0b1",
        "3.50.0rc1",
        "3.50.0",
        "3.50.0.post1",
        "3.51.0.dev0",
    ];
    for (index, old) in versions.iter().enumerate() {
        let mut f = floor();
        f.installed.as_mut().unwrap().version = old.to_string();
        for (other, new) in versions.iter().enumerate() {
            let mut candidate = installed();
            candidate.version = new.to_string();
            assert_eq!(
                transition(&f, &candidate, &Value::Null).is_ok(),
                other >= index
            );
        }
    }
    let mut f = floor();
    f.installed.as_mut().unwrap().version = "3.50.0a1".into();
    let mut alias = f.installed.clone().unwrap();
    alias.version = "v3.50.0alpha1".into();
    assert!(transition(&f, &alias, &Value::Null).is_ok());
    for field in ["root", "source", "engine"] {
        let mut changed = serde_json::to_value(&alias).unwrap();
        changed[field] = json!(if field == "source" {
            "b".repeat(40)
        } else {
            "9".repeat(64)
        });
        assert_eq!(
            transition(&f, &parse(&changed).unwrap(), &Value::Null).unwrap_err(),
            "pack_lifecycle_version_reused"
        );
    }
    for invalid in [
        "3.50",
        "3.50.0+private",
        "3.50.0a9999999999999999999999999999999999999999999999999999999999999999",
    ] {
        alias.version = invalid.into();
        assert!(alias.validate().is_err());
    }
    assert!(version::validate("remote", "3.50.0a1").is_err());
    assert!(version::validate("remote", "3.50").is_ok());
}

#[test]
fn offline_installed_source_upgrade_keeps_remote_ancestry_and_security() {
    let mut remote = installed();
    remote.profile = "remote".into();
    remote.version = "100.7".into();
    let f = transition(&floor(), &remote, &Value::Null).unwrap();
    let mut next = installed();
    next.version = "3.50.0a1".into();
    next.source = "b".repeat(40);
    next.engine = "8".repeat(64);
    let upgraded = transition(&f, &next, &Value::Null).unwrap();
    assert_eq!(upgraded.source, f.source);
    assert_eq!(upgraded.remote, f.remote);
    assert_eq!(
        (upgraded.authority, upgraded.revocation),
        (f.authority, f.revocation)
    );
    assert!(transition(&upgraded, &installed(), &Value::Null).is_err());
    remote.version = "100.6".into();
    assert!(transition(&upgraded, &remote, &Value::Null).is_err());
    remote.version = "100.8".into();
    remote.source = next.source;
    assert_eq!(
        transition(&upgraded, &remote, &Value::Null).unwrap_err(),
        "pack_lifecycle_source_ancestry_required"
    );
}

#[test]
fn roots_versions_epochs_cannot_be_reused_or_lowered() {
    let f = floor();
    for field in ["root", "engine", "source"] {
        let mut i = installed();
        match field {
            "root" => i.root = "9".repeat(64),
            "engine" => i.engine = "9".repeat(64),
            _ => i.source = "9".repeat(40),
        }
        assert!(transition(&f, &i, &json!([f.source, i.source])).is_err());
    }
    let mut i = installed();
    i.version = "3.16.2".into();
    assert!(transition(&f, &i, &Value::Null).is_err());
    for epoch in ["authority", "revocation"] {
        let mut i = installed();
        i.profile = "remote".into();
        i.version = "999.1".into();
        if epoch == "authority" {
            i.authority = 1;
        } else {
            i.revocation = 0;
        }
        assert!(transition(&f, &i, &Value::Null).is_err());
    }
}

#[test]
fn protected_record_rejects_corruption_missing_and_wrong_key() {
    let key = [7u8; 32];
    let encoded = encode(&floor(), &key).unwrap();
    assert_eq!(decode(&encoded, &key).unwrap().source, "a".repeat(40));
    assert!(decode(&encoded, &[8u8; 32]).is_err());
    assert!(decode(&encoded.replace("3.16.3", "3.16.2"), &key).is_err());
    assert!(decode("{}", &key).is_err());
    assert!(evaluate(&json!({"kind":"read","key":hex::encode(key),"floor":null})).is_err());
    assert!(
        evaluate(&json!({"kind":"enroll","key":hex::encode(key),"installed":installed()})).is_err()
    );
}

#[test]
fn migration_retains_authenticated_floor_and_never_repairs_stamped_loss() {
    let key = [7u8; 32];
    let record = encode(&floor(), &key).unwrap();
    let request = |floor: Value, stamp: Value| json!({"kind":"migrate","key":hex::encode(key),"floor":floor,"stamp":stamp});
    assert_eq!(
        evaluate(&request(json!(record), Value::Null)).unwrap()["record"],
        record
    );
    assert!(evaluate(&request(
        Value::Null,
        json!("guard.command-pack-enrolled.v1")
    ))
    .is_err());
    assert!(evaluate(&request(json!("corrupt"), Value::Null)).is_err());
    assert_eq!(
        evaluate(&request(Value::Null, Value::Null)).unwrap()["record"],
        Value::Null
    );
    let mut forged = request(Value::Null, Value::Null);
    forged["legacy_key"] = json!(hex::encode(key));
    forged["legacy_anchor"] = json!({"record":"{}","digest":"0".repeat(64),"mac":"0".repeat(64)});
    assert!(evaluate(&forged).is_err());
}

#[test]
fn migration_enrolls_an_install_that_never_received_a_floor() {
    // An install whose authority was enrolled before this record existed has
    // no legacy anchor or snapshot to admit, and nothing else ever creates a
    // floor for it. Returning no record left those installs failing the floor
    // gate on every discovery and publication refresh, for good. Startup now
    // derives the floor from the release evidence it already carries, through
    // the same enrollment the installed adapter performs -- so unbound
    // evidence is rejected here exactly as it is there, rather than silently
    // producing nothing at all.
    let key = [7u8; 32];
    let mut startup = json!({"kind":"migrate","key":hex::encode(key),"floor":null,"stamp":null,"release_data":"{}"});
    assert_eq!(
        evaluate(&startup).unwrap_err(),
        "pack_lifecycle_release_invalid"
    );
    startup["release_data"] = json!("not json");
    assert_eq!(
        evaluate(&startup).unwrap_err(),
        "pack_lifecycle_release_invalid"
    );
    // A retained-floor probe carries no release evidence and is not a startup,
    // so it still answers without creating or requiring anything.
    startup["release_data"] = Value::Null;
    assert_eq!(evaluate(&startup).unwrap()["record"], Value::Null);
}

fn legacy_envelope(mut value: Value, key: &[u8], purpose: &str) -> Value {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};
    value["authority_schema_version"] = json!(1);
    value["purpose"] = json!(purpose);
    let data = serde_json::to_string(&value).unwrap();
    let mut derive = Hmac::<Sha256>::new_from_slice(key).unwrap();
    derive.update(b"hol-guard.extension-control-authority.v1\0");
    derive.update(purpose.as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(&derive.finalize().into_bytes()).unwrap();
    mac.update(data.as_bytes());
    json!({"record":data,"digest":hex::encode(Sha256::digest(data.as_bytes())),"mac":hex::encode(mac.finalize().into_bytes())})
}

fn legacy_pending() -> Value {
    let key = [7u8; 32];
    let authority = [8u8; 32];
    let snapshot = legacy_envelope(
        json!({"revision":0,"catalog_digest":"c".repeat(64)}),
        &authority,
        "extension-control.snapshot",
    );
    let activation = legacy_envelope(
        json!({"schema":"guard.command-pack-activation.v1","revision":1,
        "previous_digest":null,"catalog_digest":"c".repeat(64),"source_sha":"a".repeat(40),
        "engine":"1".repeat(64),"root_digest":"6".repeat(64),"publication_id":"100.7",
        "authority_epoch":5,"revocation_epoch":8,"issued_at":1000,"expires_at":2000}),
        &key,
        "command-pack-activation.v1",
    );
    let next = legacy_envelope(
        json!({"revision":1,"previous_digest":snapshot["digest"],
        "catalog_digest":"c".repeat(64),"command_pack_record_digest":activation["digest"]}),
        &authority,
        "extension-control.snapshot",
    );
    let transition = legacy_envelope(
        json!({"revision":1,"previous_revision":0,"previous_digest":snapshot["digest"],
        "snapshot_digest":next["digest"],"catalog_digest":"c".repeat(64),"phase":"prepared",
        "command_pack_record_digest":activation["digest"]}),
        &authority,
        "extension-control.transition",
    );
    let link = legacy_envelope(
        json!({"control_revision":1,"snapshot_digest":next["digest"],
        "catalog_digest":"c".repeat(64),"pack_record_digest":activation["digest"],"admitted_at":1500}),
        &key,
        "command-pack-control-transition.v1",
    );
    json!({"key":hex::encode(key),"legacy_key":hex::encode(authority),"legacy_snapshot":snapshot,
        "legacy_anchor":legacy_envelope(json!({"revision":1,"snapshot_digest":next["digest"],"phase":"anchored"}), &authority, "extension-control.anchor"),
        "legacy_next_snapshot":next,"legacy_transition":transition,"legacy_pending":{"activation":activation,"link":link},
        "legacy_activation":null,"legacy_history":[]})
}

#[test]
fn previous_writer_pending_migrates_and_recovers_offline_without_lowering_floors() {
    let key = [7u8; 32];
    let mut request = legacy_pending();
    let migrated = migration::admit(&request, &key, installed()).unwrap();
    let floor = decode(migrated["record"].as_str().unwrap(), &key).unwrap();
    assert_eq!((floor.authority, floor.revocation), (5, 8));
    assert_eq!(floor.remote.as_ref().unwrap().version, "100.7");
    assert_eq!(floor.installed, Some(installed()));
    request["kind"] = json!("legacy-pending");
    request["floor"] = migrated["record"].clone();
    assert_eq!(
        evaluate(&request).unwrap()["lifecycle_after"],
        migrated["record"]
    );
    let mut higher = floor.clone();
    higher.remote.as_mut().unwrap().version = "100.8".into();
    request["floor"] = json!(encode(&higher, &key).unwrap());
    assert_eq!(
        evaluate(&request).unwrap_err(),
        "pack_lifecycle_legacy_below_floor"
    );
    request["floor"] = Value::Null;
    assert!(evaluate(&request)
        .unwrap_err()
        .contains("protected_floor_missing"));
}

#[test]
fn legacy_migration_rejects_tampered_unanchored_and_rebound_pending_evidence() {
    let key = [7u8; 32];
    for field in [
        "legacy_anchor",
        "legacy_snapshot",
        "legacy_transition",
        "legacy_next_snapshot",
    ] {
        let mut request = legacy_pending();
        request[field]["mac"] = json!("0".repeat(64));
        assert!(
            migration::admit(&request, &key, installed()).is_err(),
            "{field}"
        );
    }
    for field in ["activation", "link"] {
        let mut request = legacy_pending();
        request["legacy_pending"][field]["mac"] = json!("0".repeat(64));
        assert!(
            migration::admit(&request, &key, installed()).is_err(),
            "{field}"
        );
    }
    let mut request = legacy_pending();
    request["legacy_anchor"] = legacy_envelope(
        json!({"revision":0,
        "snapshot_digest":request["legacy_snapshot"]["digest"],"phase":"committed"}),
        &[8u8; 32],
        "extension-control.anchor",
    );
    assert!(migration::admit(&request, &key, installed()).is_err());
    let mut request = legacy_pending();
    request["legacy_pending"]["link"] = legacy_envelope(
        json!({"control_revision":1,
        "snapshot_digest":request["legacy_next_snapshot"]["digest"],"catalog_digest":"c".repeat(64),
        "pack_record_digest":request["legacy_pending"]["activation"]["digest"],"admitted_at":2500}),
        &key,
        "command-pack-control-transition.v1",
    );
    assert!(migration::admit(&request, &key, installed()).is_err());
}

#[test]
fn committed_legacy_activation_retains_floor_across_packless_controls() {
    let key = [7u8; 32];
    let mut request = legacy_pending();
    request["legacy_activation"] = request["legacy_pending"]["activation"].clone();
    request["legacy_pending"] = Value::Null;
    let committed = request["legacy_next_snapshot"].clone();
    let snapshot = legacy_envelope(
        json!({"revision":2,"previous_digest":committed["digest"]}),
        &[8u8; 32],
        "extension-control.snapshot",
    );
    request["legacy_snapshot"] = snapshot.clone();
    request["legacy_history"] = json!([committed]);
    request["legacy_anchor"] = legacy_envelope(
        json!({"revision":2,"snapshot_digest":snapshot["digest"],"phase":"committed"}),
        &[8u8; 32],
        "extension-control.anchor",
    );
    let result = migration::admit(&request, &key, installed()).unwrap();
    assert_eq!(
        decode(result["record"].as_str().unwrap(), &key)
            .unwrap()
            .remote
            .unwrap()
            .version,
        "100.7"
    );
    request["legacy_activation"] = Value::Null;
    assert!(migration::admit(&request, &key, installed()).is_err());
}

#[test]
fn an_admitted_installed_release_plans_without_the_network_after_the_source_moves() {
    let key = [5u8; 32];
    let mut moved = floor();
    // A remote publication, or the legacy migration, moves the floor's source
    // cursor while the installed release it already admitted stays put.
    moved.source = "b".repeat(40);
    let encoded = encode(&moved, &key).unwrap();
    let plan = |installed: Value| {
        evaluate(
            &json!({"kind":"plan","key":hex::encode(key),"floor":encoded,
            "selected":["command.external"],"retained":[],"active":Value::Null,
            "active_engine":Value::Null,"registry":[],"installed":installed}),
        )
    };
    let response = plan(serde_json::to_value(installed()).unwrap()).unwrap();
    // Before, this planned "remote", so every saved policy needed the network.
    assert_eq!(response["profile"], "installed");
    let admitted = decode(response["admission_floor"].as_str().unwrap(), &key).unwrap();
    assert_eq!(
        serde_json::to_value(&admitted).unwrap(),
        serde_json::to_value(&moved).unwrap()
    );
    // A release the floor has not admitted still has to earn its admission,
    // and one that reuses a version degrades to remote instead of failing.
    let mut reused = installed();
    reused.root = "9".repeat(64);
    assert_eq!(
        plan(serde_json::to_value(&reused).unwrap()).unwrap()["profile"],
        "remote"
    );
    // Once a remote publication raises an epoch past the admitted release,
    // reusing it would be an epoch rollback, so planning goes remote.
    for (authority, revocation) in [(1, 0), (0, 1)] {
        let mut raised = moved.clone();
        raised.authority += authority;
        raised.revocation += revocation;
        let encoded = encode(&raised, &key).unwrap();
        let response = evaluate(
            &json!({"kind":"plan","key":hex::encode(key),"floor":encoded,
            "selected":["command.external"],"retained":[],"active":Value::Null,
            "active_engine":Value::Null,"registry":[],
            "installed":serde_json::to_value(installed()).unwrap()}),
        )
        .unwrap();
        assert_eq!(response["profile"], "remote");
    }
}

#[test]
fn selection_uses_existing_composer_and_never_managed_opt_in() {
    let layer = |kind: &str, state: &str| {
        json!({"schema_version":"1.0.0", "catalog_digest":"1".repeat(64),
        "kind":kind,"global_lockdown":false,"controls":[{"target_kind":"extension","target_id":"command.external","state":state}]})
    };
    let request = |layers: Value| json!({"kind":"selection","layers":layers,"owners":{}});
    assert_eq!(
        evaluate(&request(json!([layer("signed-cloud", "enabled")]))).unwrap()["selected"],
        json!([])
    );
    assert_eq!(
        evaluate(&request(json!([
            layer("local-admin", "enabled"),
            layer("signed-cloud", "disabled")
        ])))
        .unwrap()["selected"],
        json!([])
    );
    assert_eq!(
        evaluate(&request(json!([layer("local-admin", "enabled")]))).unwrap()["selected"],
        json!(["command.external"])
    );
}

#[test]
fn fallback_to_remote_is_authorized_only_for_installed_typed_unavailability() {
    let request = |profile: &str, reason: &str| {
        evaluate(&json!({"kind":"fallback","profile":profile,"reason":reason}))
    };
    let code = crate::pack_preparation::UNAVAILABLE;
    for profile in ["installed", "committed-subset"] {
        assert_eq!(request(profile, code).unwrap(), json!({"profile":"remote"}));
    }
    for (profile, reason) in [
        ("remote", code),
        ("committed-subset", "unavailable-pack"),
        ("installed", "unavailable-pack"),
        ("installed", "pack_transfer_budget_exceeded"),
        ("installed", ""),
    ] {
        assert_eq!(
            request(profile, reason).unwrap_err(),
            "pack_lifecycle_fallback_not_authorized"
        );
    }
}
