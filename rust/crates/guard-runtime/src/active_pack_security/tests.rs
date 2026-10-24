use super::*;

fn state() -> Security {
    Security {
        schema: "guard.active-pack-security.v1".into(),
        authority: 1,
        epoch: 1,
        root: json!({}),
        publication: String::new(),
        security_root: "a".repeat(64),
        active: "b".repeat(64),
        program: "c".repeat(64),
        lineage_floor: String::new(),
        identity: Value::Null,
        pending: false,
        facts: BTreeMap::new(),
        applied: BTreeMap::new(),
        quarantine: BTreeSet::new(),
    }
}

pub(crate) fn fixture(program: &str, key: &[u8], pending: bool) -> (String, String) {
    let mut state = state();
    state.program = program.into();
    state.pending = pending;
    state.quarantine.insert("command.git".into());
    (
        state.encode(key).unwrap(),
        state.applicable_digest().unwrap().unwrap(),
    )
}

#[test]
fn protected_record_authenticates_and_inactive_epochs_do_not_change_identity() {
    let mut current = state();
    let key = [7; 32];
    let encoded = current.encode(&key).unwrap();
    assert!(Security::decode(&encoded, &[8; 32]).is_err());
    assert!(Security::decode(&encoded.replace("security.v1", "security.v0"), &key).is_err());
    assert_eq!(current.applicable_digest().unwrap(), None);
    current.epoch = 12;
    assert_eq!(current.applicable_digest().unwrap(), None);
    current.quarantine.insert("command.example".into());
    assert!(current.applicable_digest().unwrap().is_some());
    current.pending = true;
    assert_ne!(
        current.applicable_digest().unwrap(),
        state().applicable_digest().unwrap()
    );
    assert!(Security::decode(&current.encode(&key).unwrap(), &key)
        .unwrap()
        .pending());
}

#[test]
fn prior_closed_marker_upgrade_binds_authenticated_pack_program() {
    let key = [7; 32];
    let (record, applicable) = fixture(&"c".repeat(64), &key, true);
    let marker = json!({"schema":"guard.native-command-control-authority.v1",
        "phase":"closed", "effective_digest":null});
    let input = json!({"key":hex::encode(key), "record":record,
        "operation":"marker", "marker":marker});
    let upgraded = evaluate(&input).unwrap();
    assert_eq!(
        upgraded["schema"],
        "guard.native-command-control-authority.v3"
    );
    assert_eq!(upgraded["pack_program_digest"], "c".repeat(64));
    assert_eq!(upgraded["active_security_digest"], applicable);
    assert_eq!(upgraded["phase"], "closed");
    assert!(upgraded["effective_digest"].is_null());
    let mut wrong_key = input;
    wrong_key["key"] = hex::encode([8; 32]).into();
    assert!(evaluate(&wrong_key).is_err());
}

const SOURCE: &str = "1111111111111111111111111111111111111111";

/// The installed activation a release admits for `bundle`.
fn activation(key: &[u8], bundle: &(String, Value)) -> Value {
    let identity = &bundle.1;
    let bytes = serde_json::to_string(&json!({"purpose":"command-pack-activation.v1",
        "authority_schema_version":1, "schema":"guard.command-pack-activation.v2",
        "authority_profile":"installed", "program_digest":"d".repeat(64),
        "engine":identity["engine"], "source_sha":identity["source"],
        "root_digest":identity["root"], "authority_epoch":identity["authority"],
        "revocation_epoch":identity["revocation"]}))
    .unwrap();
    let purpose = hex::decode(mac(
        key,
        b"hol-guard.extension-control-authority.v1\0",
        b"command-pack-activation.v1",
    ))
    .unwrap();
    json!({"activation_mac":mac(&purpose, b"", bytes.as_bytes()),
        "activation_digest":hex::encode(Sha256::digest(bytes.as_bytes())), "activation":bytes})
}

/// The installed bundle a release ships: its publication and the identity the
/// installed capability reports for it.
fn installed(engine: char, version: &str, authority: u64) -> (String, Value) {
    let publication = serde_json::to_string(&json!({"authority_epoch":authority,
        "engine":engine.to_string().repeat(64), "source_sha":SOURCE,
        "policy":{"revocations":{"epoch":2, "revoked":[]}}}))
    .unwrap();
    let identity = json!({"profile":"installed", "source":SOURCE,
        "engine":engine.to_string().repeat(64),
        "root":hex::encode(Sha256::digest(publication.as_bytes())),
        "version":version, "authority":authority, "revocation":2});
    (publication, identity)
}

fn begin(key: &[u8], record: Option<&str>, floor: &str, bundle: &(String, Value)) -> Value {
    begin_under(key, record, floor, bundle, bundle)
}

/// `begin` for `bundle` while the release `active` is the admitted activation.
fn begin_under(
    key: &[u8],
    record: Option<&str>,
    floor: &str,
    bundle: &(String, Value),
    active: &(String, Value),
) -> Value {
    let mut input = activation(key, active);
    input["key"] = hex::encode(key).into();
    input["operation"] = "begin".into();
    input["profile"] = "installed".into();
    input["record"] = json!(record);
    input["lineage_floor"] = floor.into();
    input["publication"] = bundle.0.clone().into();
    input["installed_identity"] = bundle.1.clone();
    match evaluate(&input) {
        Ok(value) => value,
        Err(code) => json!({"error":code}),
    }
}

fn floor_version(key: &[u8], record: &Value) -> Value {
    let state = Security::decode(record["record"].as_str().unwrap(), key).unwrap();
    let floor = crate::pack_lifecycle::evaluate(&json!({"kind":"read",
        "key":hex::encode(key), "floor":state.lineage_floor()}))
    .unwrap();
    floor["installed"]["version"].clone()
}

#[test]
fn a_restored_release_replaces_the_upgrade_it_rolled_back_from() {
    let key = [7; 32];
    let previous = installed('a', "3.55.1", 3);
    let upgrade = installed('b', "3.56.0a3", 3);
    let floor = crate::pack_lifecycle::enrolled_floor(&previous.1, &key);
    let upgraded = begin(&key, None, &floor, &upgrade);
    let upgraded_record = upgraded["record"].as_str().unwrap();
    assert_eq!(floor_version(&key, &upgraded), "3.56.0a3");

    // Desktop put the previous runtime back. Its own bundle becomes the root
    // again, so the activation it runs is not quarantined against the newer
    // engine, and the lineage floor stays at the upgrade.
    let restored = begin(&key, Some(upgraded_record), &floor, &previous);
    assert_eq!(restored["pending"], true, "{restored}");
    let state = Security::decode(restored["record"].as_str().unwrap(), &key).unwrap();
    assert_eq!(state.root["engine"], "a".repeat(64));
    assert_eq!(state.identity, previous.1);
    assert_eq!(floor_version(&key, &restored), "3.56.0a3");

    // The upgrade can still come back over it.
    let again = begin(&key, restored["record"].as_str(), &floor, &upgrade);
    assert_eq!(again["pending"], true, "{again}");
    assert_eq!(floor_version(&key, &again), "3.56.0a3");
}

#[test]
fn only_a_release_under_the_same_authority_is_restored() {
    let key = [7; 32];
    let previous = installed('a', "3.55.1", 3);
    let floor = crate::pack_lifecycle::enrolled_floor(&previous.1, &key);

    // An upgrade that raised the authority keeps its newer observation.
    let raised = begin(&key, None, &floor, &installed('b', "3.56.0a3", 4));
    let restored = begin(&key, raised["record"].as_str(), &floor, &previous);
    assert_eq!(restored, json!({"ignored":true}));

    // An older release that claims a newer authority than the upgrade is
    // still a version rollback.
    let upgraded = begin(&key, None, &floor, &installed('b', "3.56.0a3", 3));
    let claimed = begin(
        &key,
        upgraded["record"].as_str(),
        &floor,
        &installed('a', "3.55.1", 4),
    );
    assert_eq!(claimed, json!({"error":"pack_lifecycle_version_rollback"}));
}

#[test]
fn only_the_release_the_activation_admits_is_restored() {
    let key = [7; 32];
    let previous = installed('a', "3.55.1", 3);
    let upgrade = installed('b', "3.56.0a3", 3);
    let floor = crate::pack_lifecycle::enrolled_floor(&previous.1, &key);
    let upgraded = begin(&key, None, &floor, &upgrade);
    let upgraded_record = upgraded["record"].as_str();

    // A still older release under the same authority and revocations is not
    // the one the running activation admitted, so it stays a rollback.
    let unrelated = installed('c', "3.40.0", 3);
    let replaced = begin_under(&key, upgraded_record, &floor, &unrelated, &previous);
    assert_eq!(replaced, json!({"error":"pack_lifecycle_version_rollback"}));

    // Nor does the restored release replace the root while the upgrade is
    // still the admitted activation.
    let early = begin_under(&key, upgraded_record, &floor, &previous, &upgrade);
    assert_eq!(early, json!({"error":"pack_lifecycle_version_rollback"}));
}
