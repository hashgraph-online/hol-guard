use super::*;
use crate::business_policy::BusinessPolicyBindingV1;
use serde_json::{json, Value};

fn value() -> Value {
    json!({"schema":BUSINESS_BUDGET_SCHEMA,"version":1,"id":"mail.daily","scope":"account",
      "match":{"schema":"guard.business-policy-match.v1","version":1,"services":["google_gmail"],"operations":["mail_send"]},
      "windowMs":86400000,"maximumActions":10,"maximumRecipients":20,"maximumRecords":10,"maximumBytes":1048576})
}

#[test]
fn every_scope_zero_allowance_and_safe_integer_bounds_validate() {
    for scope in ["account", "user", "workflow"] {
        let mut v = value();
        v["scope"] = json!(scope);
        for field in [
            "maximumActions",
            "maximumRecipients",
            "maximumRecords",
            "maximumBytes",
        ] {
            v[field] = json!(0);
        }
        let budget: BusinessBudgetV1 = serde_json::from_value(v).unwrap();
        assert!(budget.validate().is_ok());
    }
    for (field, patch) in [
        ("windowMs", json!(0)),
        ("windowMs", json!(BUSINESS_BUDGET_MAX_WINDOW_MS + 1)),
        ("maximumActions", json!(MAX_BUSINESS_WIRE_COUNT + 1)),
        ("version", json!(2)),
        ("id", json!("../bad")),
    ] {
        let mut v = value();
        v[field] = patch;
        assert!(serde_json::from_value::<BusinessBudgetV1>(v)
            .unwrap()
            .validate()
            .is_err());
    }
}

#[test]
fn malformed_missing_null_duplicate_and_unknown_values_cannot_widen_limits() {
    for field in ["minRecipientCount", "minRecordCount", "minByteCount"] {
        let mut v = value();
        v["match"][field] = json!(10);
        assert!(serde_json::from_value::<BusinessBudgetV1>(v)
            .unwrap()
            .validate()
            .is_err());
    }
    for field in ["maximumActions", "scope", "windowMs", "match"] {
        let mut v = value();
        v.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<BusinessBudgetV1>(v).is_err());
        let mut v = value();
        v[field] = Value::Null;
        assert!(serde_json::from_value::<BusinessBudgetV1>(v).is_err());
    }
    let mut v = value();
    v["maximumActions"] = json!(-1);
    assert!(serde_json::from_value::<BusinessBudgetV1>(v).is_err());
    let mut v = value();
    v["scope"] = json!("global_unlimited");
    assert!(serde_json::from_value::<BusinessBudgetV1>(v).is_err());
    let mut v = value();
    v["unknown"] = json!(true);
    assert!(serde_json::from_value::<BusinessBudgetV1>(v).is_err());
    let encoded = serde_json::to_string(&value()).unwrap();
    let duplicate = encoded.replacen("{", "{\"maximumActions\":999,", 1);
    assert!(serde_json::from_str::<BusinessBudgetV1>(&duplicate).is_err());
}

#[test]
fn policy_budget_presence_is_strict_and_bound_into_snapshot_integrity() {
    let base = json!({"schema":"guard.native-business-policy.v1","version":1,"defaultAction":"allow","rules":[]});
    let binding: BusinessPolicyBindingV1 = serde_json::from_value(base.clone()).unwrap();
    assert!(!serde_json::to_value(binding)
        .unwrap()
        .as_object()
        .unwrap()
        .contains_key("budgets"));
    for budgets in [json!([]), json!([value(), value()])] {
        let mut v = base.clone();
        v["budgets"] = budgets;
        assert!(serde_json::from_value::<BusinessPolicyBindingV1>(v)
            .unwrap()
            .validate()
            .is_err());
    }
    let mut v = base.clone();
    v["budgets"] = Value::Null;
    assert!(serde_json::from_value::<BusinessPolicyBindingV1>(v).is_err());
    let mut v = base;
    v["budgets"] = json!([value()]);
    let mut snapshot = crate::tests::snapshot(1, &[7; 32]);
    snapshot.business_policy = Some(serde_json::from_value(v).unwrap());
    snapshot.policy_digest = crate::policy_digest(&snapshot).unwrap();
    snapshot.integrity.mac = crate::integrity_mac(&snapshot, &[7; 32]).unwrap();
    let old_digest = snapshot.policy_digest.clone();
    snapshot
        .business_policy
        .as_mut()
        .unwrap()
        .budgets
        .as_mut()
        .unwrap()[0]
        .maximum_actions += 1;
    assert_ne!(crate::policy_digest(&snapshot).unwrap(), old_digest);
    assert_ne!(
        crate::integrity_mac(&snapshot, &[7; 32]).unwrap(),
        snapshot.integrity.mac
    );
}
