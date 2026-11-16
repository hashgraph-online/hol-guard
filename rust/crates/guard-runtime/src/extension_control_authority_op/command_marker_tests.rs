//! Pins the command-control marker writer to the bytes the Python encoder
//! produced, the shapes it refused, and the private file the native reader
//! opens.

use serde_json::{json, Value};

use super::command_marker::{publish, sign_marker, MARKER_FILE};

const KEY: [u8; 32] = [7; 32];

/// `encode_authority` output for these records under `KEY`.
const SECURITY_MARKER: &str = r#"{"active_security_digest":"1111111111111111111111111111111111111111111111111111111111111111","authority_key_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","effective_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","epoch":3,"mac":"f0a844f8a5bcedb1b91eae0ea5aa1ef5d4962f15dee3aa9d3f52479a9c443523","mutation_revision":9,"pack_program_digest":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","phase":"committed","recovery":{"nonce":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","previous_authority_key_id":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","previous_epoch":2,"previous_floor_digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","previous_mutation_revision":8,"schema":"guard.native-command-control-recovery.v1"},"schema":"guard.native-command-control-authority.v3"}"#;
const CLOSED_MARKER: &str = r#"{"authority_key_id":"0000000000000000000000000000000000000000000000000000000000000000","effective_digest":null,"epoch":1,"mac":"861237e46bc7e9f9c602bf994e7c6e606d2caeb2c6ed89b681e71765d732c582","mutation_revision":1,"phase":"closed","recovery":null,"schema":"guard.native-command-control-authority.v1"}"#;

fn security_record() -> Value {
    json!({
        "schema": "guard.native-command-control-authority.v3",
        "epoch": 3,
        "mutation_revision": 9,
        "authority_key_id": "a".repeat(64),
        "phase": "committed",
        "effective_digest": "b".repeat(64),
        "recovery": {
            "schema": "guard.native-command-control-recovery.v1",
            "previous_epoch": 2,
            "previous_mutation_revision": 8,
            "previous_authority_key_id": "c".repeat(64),
            "previous_floor_digest": "d".repeat(64),
            "nonce": "e".repeat(64),
        },
        "pack_program_digest": "f".repeat(64),
        "active_security_digest": "1".repeat(64),
    })
}

fn closed_record() -> Value {
    json!({
        "schema": "guard.native-command-control-authority.v1",
        "epoch": 1,
        "mutation_revision": 1,
        "authority_key_id": "0".repeat(64),
        "phase": "closed",
        "effective_digest": null,
        "recovery": null,
    })
}

#[test]
fn a_marker_is_signed_byte_for_byte_as_the_python_encoder_signed_it() {
    for (record, expected) in [
        (security_record(), SECURITY_MARKER),
        (closed_record(), CLOSED_MARKER),
    ] {
        let (signed, encoded) = sign_marker(&record, &KEY).unwrap();
        assert_eq!(String::from_utf8(encoded).unwrap(), expected);
        assert_eq!(signed, serde_json::from_str::<Value>(expected).unwrap());
    }
    // A stale MAC on the way in is replaced, not trusted.
    let mut stale = closed_record();
    stale["mac"] = json!("9".repeat(64));
    let (_, encoded) = sign_marker(&stale, &KEY).unwrap();
    assert_eq!(String::from_utf8(encoded).unwrap(), CLOSED_MARKER);
}

#[test]
fn a_record_the_python_encoder_refused_is_refused() {
    let mut cases = Vec::new();
    let mut edit = |base: Value, change: &dyn Fn(&mut serde_json::Map<String, Value>)| {
        let mut record = base;
        change(record.as_object_mut().unwrap());
        cases.push(record);
    };
    edit(closed_record(), &|r| {
        r.insert("effective_digest".into(), json!("b".repeat(64)));
    });
    edit(closed_record(), &|r| {
        r.insert("phase".into(), json!("committed"));
    });
    edit(closed_record(), &|r| {
        r.insert("phase".into(), json!("open"));
    });
    edit(closed_record(), &|r| {
        r.insert(
            "schema".into(),
            json!("guard.native-command-control-authority.v4"),
        );
    });
    edit(closed_record(), &|r| {
        r.insert("epoch".into(), json!(0));
    });
    edit(closed_record(), &|r| {
        r.insert("epoch".into(), json!(true));
    });
    edit(closed_record(), &|r| {
        r.insert("authority_key_id".into(), json!("A".repeat(64)));
    });
    edit(closed_record(), &|r| {
        r.insert("pack_program_digest".into(), json!("f".repeat(64)));
    });
    edit(closed_record(), &|r| {
        r.remove("recovery");
    });
    edit(security_record(), &|r| {
        r.remove("active_security_digest");
    });
    edit(security_record(), &|r| {
        r.insert("pack_program_digest".into(), json!(null));
    });
    edit(security_record(), &|r| {
        r["recovery"]["previous_epoch"] = json!(3);
    });
    edit(security_record(), &|r| {
        r["recovery"]
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), json!(1));
    });
    for record in cases {
        assert_eq!(
            sign_marker(&record, &KEY),
            Err("native_command_control_authority_invalid".to_owned()),
            "{record}"
        );
    }
    assert!(sign_marker(&json!([]), &KEY).is_err());
}

#[cfg(unix)]
#[test]
fn a_published_marker_lands_private_in_the_native_runtime_directory() {
    use std::os::unix::fs::PermissionsExt;

    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    publish(home.path(), CLOSED_MARKER.as_bytes()).unwrap();
    publish(home.path(), SECURITY_MARKER.as_bytes()).unwrap();
    let path = home.path().join("native-runtime").join(MARKER_FILE);
    assert_eq!(std::fs::read(&path).unwrap(), SECURITY_MARKER.as_bytes());
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o077, 0);
    let entries = std::fs::read_dir(home.path().join("native-runtime"))
        .unwrap()
        .count();
    assert_eq!(entries, 1, "no temporary file is left behind");
}
