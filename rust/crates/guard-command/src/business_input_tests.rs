use super::*;
use serde_json::{json, Value};

fn facts(primary: &[u8], attachments: &[Vec<u8>]) -> Value {
    let total = primary.len() + attachments.iter().map(Vec::len).sum::<usize>();
    json!({
        "schema": "guard.business-action.v1", "version": 1,
        "provider": {
            "service": "google_gmail", "identity_state": "known",
            "account_binding": "a".repeat(64), "tenant_binding": "b".repeat(64),
            "tool_identity_digest": "c".repeat(64), "tool_schema_digest": "d".repeat(64)
        },
        "operation": "mail_send",
        "audience": {"kind":"named", "expansion_state":"known", "recipients":[
            {"identity_binding":"e".repeat(64), "domain":"example.test", "kind":"to"}
        ]},
        "content": {
            "snapshot_digest":business_input_snapshot_digest(primary,attachments).unwrap(),
            "attachment_digests":attachments.iter().map(|bytes| digest_bytes(bytes)).collect::<Vec<_>>(),
            "inspection_state":"known", "inspected_bytes":total,
            "sensitivity_labels":["confidential"]
        },
        "target": {
            "resource_binding":"1".repeat(64), "revision_binding":"2".repeat(64),
            "field_diff_digest":"3".repeat(64), "batch_manifest_digest":"4".repeat(64)
        },
        "volume":{"recipient_count":1,"record_count":1,"byte_count":total},
        "completeness":"known"
    })
}

fn prepare(
    value: &Value,
    primary: Vec<u8>,
    attachments: Vec<Vec<u8>>,
) -> Result<PreparedBusinessInputV1, PreparedBusinessInputErrorV1> {
    PreparedBusinessInputV1::prepare(&serde_json::to_vec(value).unwrap(), primary, attachments)
}

#[test]
fn frozen_input_owns_exact_bytes_and_retains_ordered_commitments() {
    let mut source = b"private synthetic body".to_vec();
    let mut attachments = vec![b"first".to_vec(), b"second".to_vec()];
    let value = facts(&source, &attachments);
    let prepared = prepare(&value, source.clone(), attachments.clone()).unwrap();
    source.fill(b'x');
    attachments[0].fill(b'x');
    assert_eq!(prepared.primary_bytes(), b"private synthetic body");
    assert_eq!(
        prepared.attachments().collect::<Vec<_>>(),
        [b"first".as_slice(), b"second".as_slice()]
    );
    assert_eq!(serde_json::to_value(prepared.facts()).unwrap(), value);
    assert_eq!(prepared.binding().len(), 64);
}

#[test]
fn changed_body_attachment_order_count_or_bytes_cannot_prepare() {
    let body = b"body".to_vec();
    let original = vec![b"alpha".to_vec(), b"bravo".to_vec()];
    let value = facts(&body, &original);
    for (body, attachments) in [
        (b"Body".to_vec(), original.clone()),
        (body.clone(), vec![original[1].clone(), original[0].clone()]),
        (body.clone(), vec![original[0].clone()]),
        (body.clone(), vec![original[0].clone(), b"delta".to_vec()]),
    ] {
        assert!(matches!(
            prepare(&value, body, attachments),
            Err(PreparedBusinessInputErrorV1::ContentMismatch)
        ));
    }
}

#[test]
fn complete_snapshot_matches_independent_vector_and_unambiguous_partitions() {
    // Independently constructed with Python hashlib and struct.pack('>Q').
    assert_eq!(
        business_input_snapshot_digest(b"body", &[b"alpha".to_vec(), b"bravo".to_vec()]).unwrap(),
        "80b3f2b70c5b3bd3135eca5c031f5c9685d20257c66695969453cd2572e4fbef"
    );
    assert_ne!(
        business_input_snapshot_digest(b"ab", &[b"c".to_vec()]).unwrap(),
        business_input_snapshot_digest(b"a", &[b"bc".to_vec()]).unwrap()
    );
    assert_ne!(
        business_input_snapshot_digest(b"body", &[]).unwrap(),
        business_input_snapshot_digest(b"body", &[vec![]]).unwrap()
    );
    let body = b"body".to_vec();
    let attachments = vec![b"alpha".to_vec()];
    let mut value = facts(&body, &attachments);
    value["content"]["snapshot_digest"] = json!(digest_bytes(&body));
    assert!(matches!(
        prepare(&value, body, attachments),
        Err(PreparedBusinessInputErrorV1::ContentMismatch)
    ));
}

#[test]
fn known_inspection_claim_does_not_substitute_for_owned_byte_count() {
    let body = b"body".to_vec();
    let attachments = vec![];
    let mut value = facts(&body, &attachments);
    value["volume"]["byte_count"] = json!(5);
    value["content"]["inspected_bytes"] = json!(5);
    assert!(matches!(
        prepare(&value, body, attachments),
        Err(PreparedBusinessInputErrorV1::ContentMismatch)
    ));
}

#[test]
fn uncertain_facts_and_unknown_fields_never_prepare() {
    let body = b"body".to_vec();
    let value = facts(&body, &[]);
    for (section, key) in [
        ("provider", "identity_state"),
        ("audience", "expansion_state"),
        ("content", "inspection_state"),
    ] {
        let mut changed = value.clone();
        changed[section][key] = json!("unknown");
        assert!(matches!(
            prepare(&changed, body.clone(), vec![]),
            Err(PreparedBusinessInputErrorV1::InvalidFacts)
        ));
    }
    let mut changed = value.clone();
    changed["unchecked_send_override"] = json!(true);
    assert!(matches!(
        prepare(&changed, body, vec![]),
        Err(PreparedBusinessInputErrorV1::InvalidFacts)
    ));
}

#[test]
fn aggregate_byte_and_attachment_limits_apply_before_commitments() {
    let value = facts(b"", &[]);
    for (body, attachments) in [
        (vec![0; MAX_BUSINESS_INLINE_BYTES as usize + 1], vec![]),
        (vec![0; MAX_BUSINESS_INLINE_BYTES as usize], vec![vec![0]]),
        (vec![], vec![vec![]; MAX_BUSINESS_ACTION_ITEMS + 1]),
    ] {
        assert!(matches!(
            prepare(&value, body, attachments),
            Err(PreparedBusinessInputErrorV1::BoundsExceeded)
        ));
    }
    let limit = vec![0; MAX_BUSINESS_INLINE_BYTES as usize];
    let value = facts(&limit, &[]);
    assert_eq!(
        prepare(&value, limit, vec![])
            .unwrap()
            .primary_bytes()
            .len(),
        MAX_BUSINESS_INLINE_BYTES as usize
    );
}

#[test]
fn commitment_is_canonical_and_changes_with_every_fact_dimension() {
    let body = b"body".to_vec();
    let value = facts(&body, &[]);
    let original = prepare(&value, body.clone(), vec![]).unwrap();
    let pretty = serde_json::to_vec_pretty(&value).unwrap();
    let same = PreparedBusinessInputV1::prepare(&pretty, body.clone(), vec![]).unwrap();
    assert_eq!(same.binding(), original.binding());
    fn reordered(value: &Value) -> String {
        match value {
            Value::Object(object) => format!(
                "{{{}}}",
                object
                    .iter()
                    .rev()
                    .map(|(key, value)| format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap(),
                        reordered(value)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Value::Array(items) => format!(
                "[{}]",
                items.iter().map(reordered).collect::<Vec<_>>().join(",")
            ),
            value => serde_json::to_string(value).unwrap(),
        }
    }
    let reversed = reordered(&value);
    assert_ne!(reversed.as_bytes(), serde_json::to_vec(&value).unwrap());
    let same = PreparedBusinessInputV1::prepare(reversed.as_bytes(), body.clone(), vec![]).unwrap();
    assert_eq!(same.binding(), original.binding());
    for (section, key) in [
        ("provider", "account_binding"),
        ("provider", "tenant_binding"),
        ("provider", "tool_identity_digest"),
        ("provider", "tool_schema_digest"),
        ("target", "resource_binding"),
        ("target", "revision_binding"),
        ("target", "field_diff_digest"),
        ("target", "batch_manifest_digest"),
    ] {
        let mut changed = value.clone();
        changed[section][key] = json!("9".repeat(64));
        assert_ne!(
            prepare(&changed, body.clone(), vec![]).unwrap().binding(),
            original.binding()
        );
    }
    let mut changed = value.clone();
    changed["audience"]["recipients"][0]["identity_binding"] = json!("9".repeat(64));
    assert_ne!(
        prepare(&changed, body.clone(), vec![]).unwrap().binding(),
        original.binding()
    );
    let mut changed = value;
    changed["content"]["sensitivity_labels"] = json!(["secret"]);
    assert_ne!(
        prepare(&changed, body, vec![]).unwrap().binding(),
        original.binding()
    );
}
