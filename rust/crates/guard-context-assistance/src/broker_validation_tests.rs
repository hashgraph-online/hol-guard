use super::*;

#[test]
fn source_revisions_remain_canonical_lossless_decimal_strings() {
    for version in ["0", "9007199254740993", "18446744073709551615"] {
        let value = BrokerRevision {
            epoch: "a".repeat(64),
            version: version.into(),
        };
        value.validate().unwrap();
        assert_eq!(serde_json::to_value(value).unwrap()["version"], version);
    }
    for version in ["", "00", "01", "-1", "1.0", "18446744073709551616", " 1"] {
        assert!(BrokerRevision {
            epoch: "a".repeat(64),
            version: version.into()
        }
        .validate()
        .is_err());
    }
    assert!(BrokerRevision {
        epoch: "A".repeat(64),
        version: "0".into()
    }
    .validate()
    .is_err());
}

#[test]
fn host_document_admission_refuses_unsafe_or_ambiguous_material() {
    assert!(documents(vec![document("note:a", "plain project guidance")], 16384).is_ok());
    for values in [
        vec![document("note:a", "bad\0content")],
        vec![document("", "empty identifier")],
        vec![document("note:a", "one"), document("note:a", "two")],
        vec![document("note:a", &"a".repeat(16385))],
    ] {
        assert!(documents(values, 16384).is_err());
    }
    assert!(matches!(
        documents(
            vec![document(
                "note:a",
                "-----BEGIN PRIVATE KEY-----\nsynthetic test material\n-----END PRIVATE KEY-----"
            )],
            16384
        ),
        Err(RuntimeError::ScopeDenied)
    ));
}
