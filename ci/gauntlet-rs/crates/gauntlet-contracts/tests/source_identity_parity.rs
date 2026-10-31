use gauntlet_contracts::{validate_source_identity, IdentityError};
use serde_json::{json, Value};

fn merge_report() -> Value {
    json!({
        "source_dirty": false,
        "candidate_sha": "a".repeat(40),
        "tested_source_sha": "c".repeat(40),
        "installed_source_sha": "c".repeat(40),
        "source_parents": ["b".repeat(40), "a".repeat(40)],
        "tested_base_sha": "b".repeat(40),
    })
}

#[test]
fn exact_candidate_or_two_parent_test_merge_matches_python() {
    let candidate = "a".repeat(40);
    let base = "b".repeat(40);
    let mut report = merge_report();
    assert!(validate_source_identity(&report, &candidate, Some(&base)).is_ok());
    assert_eq!(
        validate_source_identity(&report, &candidate, Some(&"d".repeat(40))),
        Err(IdentityError::StaleBase)
    );
    report["source_parents"] = json!([base]);
    assert_eq!(
        validate_source_identity(&report, &candidate, None),
        Err(IdentityError::InvalidTestMerge)
    );

    let direct = json!({
        "source_dirty": false,
        "candidate_sha": candidate,
        "tested_source_sha": candidate,
        "installed_source_sha": candidate,
        "source_parents": [base],
        "tested_base_sha": null,
    });
    assert!(validate_source_identity(&direct, &candidate, None).is_ok());
}

#[test]
fn dirty_missing_and_forged_bindings_fail_closed() {
    let candidate = "a".repeat(40);
    let base = "b".repeat(40);
    for dirty in [json!(true), Value::Null] {
        let mut report = merge_report();
        report["source_dirty"] = dirty;
        assert_eq!(
            validate_source_identity(&report, &candidate, Some(&base)),
            Err(IdentityError::DirtyOrUnrecorded)
        );
    }
    for (field, value) in [
        ("candidate_sha", json!("d".repeat(40))),
        ("installed_source_sha", json!("d".repeat(40))),
        ("source_parents", json!([base, "INVALID"])),
    ] {
        let mut report = merge_report();
        report[field] = value;
        assert!(validate_source_identity(&report, &candidate, Some(&base)).is_err());
    }
    let mut report = merge_report();
    report["tested_base_sha"] = json!("d".repeat(40));
    assert_eq!(
        validate_source_identity(&report, &candidate, Some(&base)),
        Err(IdentityError::StaleBase)
    );
}
