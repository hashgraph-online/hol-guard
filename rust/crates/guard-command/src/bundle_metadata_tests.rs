use super::*;

pub(super) fn fixture() -> Value {
    let reference = json!({"sha256":"c".repeat(64),"length":2,"expanded_length":2,"kind":"data"});
    let mut located = reference.clone();
    located["location"] = json!({"tag":format!("extension-data-{}-0.0-000000", "a".repeat(40)),"asset":format!("object-{}.json", "c".repeat(64))});
    json!({"schema":"guard.command-pack-bundle.v1","source_sha":"a".repeat(40),"engine":"b".repeat(64),
        "authority_epoch":1,"publication_id":"0.0","policy":{
            "root":{"schema":"guard.command-pack-release.v1","kind":"root","authority":"requires-authenticated-release-binding",
                "engine":"b".repeat(64),"extensions":1,"index":reference,"index_fanout":64,"objects":1,"object_bytes":2,"object_bytes_limit":65536},
            "transport":located,"defaults":{"count":0,"index":null},"revocations":{"count":0,"index":null,"epoch":0}}})
}

fn validate(value: &Value) -> Result<Value> {
    root(
        &serde_json::to_string(value).unwrap(),
        &"a".repeat(40),
        &"b".repeat(64),
    )
}

fn installed_fixture() -> Value {
    let data = serde_json::to_string(&fixture()).unwrap();
    let digest = hex::encode(Sha256::digest(data.as_bytes()));
    let descriptor = json!({"schema":"guard.command-pack-bundle.v1",
        "path":"codex_plugin_scanner/guard/contracts/data/extensions/command-pack-bundle/command-pack-bundle.v1.json",
        "sha256":digest,"length":data.len(),"source_sha":"a".repeat(40),"engine":"b".repeat(64)});
    let common = json!({"protocol_version":1,"source_sha":"a".repeat(40),"package_version":"1.0",
        "target":"test","platform_tag":"test","command_pack_bundle":descriptor});
    let mut runtime = common.clone();
    runtime["schema"] = json!("hol-guard-native-runtime.v1");
    runtime["runtime_size"] = json!(18);
    runtime["runtime_sha256"] = json!("e".repeat(64));
    let mut compiler = common;
    compiler["schema"] = json!("hol-guard-native-source-compiler.v2");
    compiler["compiler_size"] = json!(18);
    compiler["compiler_sha256"] = json!("e".repeat(64));
    compiler["executable"] = json!("hol-guard-runtime");
    compiler["implementation_digest"] = json!("b".repeat(64));
    json!({"runtime_manifest":runtime,"compiler_manifest":compiler,"data":data,
        "binary_length":18,"binary_digest":"e".repeat(64)})
}

#[test]
fn authenticates_both_release_manifests_executable_and_exact_root_descriptor() {
    let evidence = installed_fixture();
    let identity = installed(&evidence).unwrap();
    assert_eq!(identity["source_sha"], "a".repeat(40));
    assert_eq!(identity["engine"], "b".repeat(64));
    for (pointer, bad) in [
        ("/runtime_manifest/protocol_version", json!(true)),
        ("/compiler_manifest/protocol_version", json!(1.0)),
        ("/compiler_manifest/source_sha", json!("d".repeat(40))),
        ("/compiler_manifest/package_version", json!("2.0")),
        ("/compiler_manifest/target", json!(null)),
        ("/compiler_manifest/platform_tag", json!("other")),
        (
            "/compiler_manifest/executable",
            json!("../hol-guard-runtime"),
        ),
        ("/compiler_manifest/compiler_size", json!(134217729)),
        ("/runtime_manifest/runtime_size", json!(17)),
        ("/binary_length", json!(17)),
        ("/binary_digest", json!("f".repeat(64))),
        ("/runtime_manifest/runtime_sha256", json!("f".repeat(64))),
        ("/compiler_manifest/compiler_sha256", json!("f".repeat(64))),
        (
            "/compiler_manifest/implementation_digest",
            json!("f".repeat(64)),
        ),
        (
            "/compiler_manifest/command_pack_bundle/sha256",
            json!("f".repeat(64)),
        ),
        (
            "/runtime_manifest/command_pack_bundle/path",
            json!("elsewhere.json"),
        ),
    ] {
        let mut invalid = evidence.clone();
        *invalid.pointer_mut(pointer).unwrap() = bad;
        assert!(installed(&invalid).is_err(), "{pointer}");
    }
}

#[test]
fn accepts_full_unsigned_epoch_range_and_long_root_transport_strings() {
    let mut value = fixture();
    value["authority_epoch"] = json!(u64::MAX);
    value["policy"]["revocations"]["epoch"] = json!(u64::MAX);
    assert!(validate(&value).is_ok());
    let mut evidence = installed_fixture();
    let data = format!("{}{}", " ".repeat(5000), evidence["data"].as_str().unwrap());
    let digest = hex::encode(Sha256::digest(data.as_bytes()));
    for manifest in ["runtime_manifest", "compiler_manifest"] {
        evidence[manifest]["command_pack_bundle"]["sha256"] = json!(digest);
        evidence[manifest]["command_pack_bundle"]["length"] = json!(data.len());
    }
    evidence["data"] = json!(data);
    evidence["operation"] = json!("installed");
    assert!(evaluate(&serde_json::to_vec(&evidence).unwrap()).is_ok());
}

#[test]
fn complete_root_and_compatibility_preserve_default_off_inventory() {
    let mut value = fixture();
    assert_eq!(validate(&value).unwrap(), value);
    let data = serde_json::to_string(&value).unwrap();
    let mut request = json!({"operation":"root","data":data,
        "source_sha":"a".repeat(40),"engine":"b".repeat(64)});
    assert_eq!(
        evaluate(&serde_json::to_vec(&request).unwrap()).unwrap(),
        value
    );
    request["operation"] = json!("descriptor");
    assert_eq!(
        evaluate(&serde_json::to_vec(&request).unwrap()).unwrap(),
        installed_fixture()["runtime_manifest"]["command_pack_bundle"]
    );
    value["compatibility"] = json!({"commands":{"count":1,"index":value["policy"]["transport"]},"mcp":{"count":0,"index":null}});
    assert_eq!(validate(&value).unwrap(), value);
    assert_eq!(value["policy"]["defaults"]["count"], 0);
    for pointer in [
        "/compatibility/commands/count",
        "/policy/root/extensions",
        "/authority_epoch",
        "/policy/revocations/epoch",
    ] {
        for bad in [
            json!(true),
            json!(-1),
            json!(1.0),
            json!("1"),
            json!(null),
            json!({"$serde_json::private::Number":"1"}),
        ] {
            let mut invalid = value.clone();
            *invalid.pointer_mut(pointer).unwrap() = bad;
            assert!(validate(&invalid).is_err(), "{pointer}");
        }
    }
}

#[test]
fn rejects_unknown_fields_identity_substitution_and_index_mismatch() {
    for (pointer, bad) in [
        ("/policy/root/index/length", json!(65537)),
        ("/policy/root/index/expanded_length", json!(3)),
        (
            "/policy/transport/location/tag",
            json!(format!("extension-data-{}-0.0-000000", "d".repeat(40))),
        ),
        ("/policy/defaults/count", json!(2)),
        ("/policy/revocations/index", json!({})),
        ("/engine", json!("d".repeat(64))),
    ] {
        let mut value = fixture();
        *value.pointer_mut(pointer).unwrap() = bad;
        assert!(validate(&value).is_err(), "{pointer}");
    }
    let mut value = fixture();
    value["expires_at"] = json!(9999999999u64);
    assert!(validate(&value).is_err());
    let data = serde_json::to_string(&fixture()).unwrap();
    let duplicate = format!("{},\"policy\":{{}}}}", &data[..data.len() - 1]);
    assert!(root(&duplicate, &"a".repeat(40), &"b".repeat(64)).is_err());
    assert!(root(&" ".repeat(65537), &"a".repeat(40), &"b".repeat(64)).is_err());
}

#[test]
fn compatibility_requires_complete_counted_inventory() {
    let located = fixture()["policy"]["transport"].clone();
    let good = json!({"commands":{"count":1,"index":located},"mcp":{"count":0,"index":null}});
    assert!(compatibility(&good, 1, None).is_ok());
    assert!(evaluate(
        &serde_json::to_vec(&json!({"operation":"compatibility",
        "value":good,"extensions":1}))
        .unwrap()
    )
    .is_ok());
    assert!(compatibility(&good, 2, None).is_err());
    let mut invalid = good.clone();
    invalid["mcp"]["index"] = located.clone();
    assert!(compatibility(&invalid, 1, None).is_err());
    invalid = good;
    invalid["commands"]["remote"] = json!("https://example.com/unsigned");
    assert!(compatibility(&invalid, 1, None).is_err());
}

#[test]
fn targets_require_exact_source_and_bounded_flat_container_names() {
    let source = "a".repeat(40);
    let mut location = fixture()["policy"]["transport"]["location"].clone();
    assert!(target(&location, Some(&source)).is_ok());
    location["member"] = location["asset"].clone();
    location["asset"] = json!("objects-000000.zip");
    assert!(target(&location, Some(&source)).is_ok());
    for asset in [
        "packs-000000.zip",
        "../objects-000000.zip",
        "objects-000000.zip\n",
    ] {
        location["asset"] = json!(asset);
        assert!(target(&location, Some(&source)).is_err());
    }
}
