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
