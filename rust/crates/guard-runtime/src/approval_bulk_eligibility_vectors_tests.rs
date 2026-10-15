//! Parity vectors recorded from the retired Python `is_bulk_allow_once_eligible`
//! helpers: every case carries the stored request fields and the verdict the
//! Python produced.

use guard_contracts::{
    ApprovalBulkEligibilityItemV1, ApprovalBulkEligibilityRequestV1,
    APPROVAL_BULK_ELIGIBILITY_REQUEST_SCHEMA,
};
use serde_json::Value;

use super::evaluate;
use crate::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] =
    include_bytes!("../tests/fixtures/approval_bulk_eligibility_vectors.json.gz");

/// Basenames the resident's secret path classifier blocks but the retired
/// Python classifier did not. Bulk approval is deliberately stricter for them.
const STRICTER_BASENAMES: [&str; 5] = ["id_rsa", "id_ed25519", "id_ecdsa", ".wallet", "wallet.dat"];

fn targets_a_stricter_basename(request: &Value) -> bool {
    request["action_envelope_json"]["target_paths"]
        .as_array()
        .is_some_and(|paths| {
            paths.iter().filter_map(Value::as_str).any(|path| {
                let trimmed = path
                    .trim()
                    .trim_matches('\'')
                    .trim_matches('"')
                    .to_lowercase();
                let basename = trimmed.rsplit('/').next().unwrap_or("");
                STRICTER_BASENAMES.contains(&basename)
            })
        })
}

#[test]
fn verdicts_match_the_retired_python() {
    let vectors = gunzip_json(VECTORS);
    let home = vectors["home_dir"].as_str().expect("home_dir").to_owned();
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(cases.len() > 5000);
    let mut eligible = 0;
    let mut stricter = 0;
    for (index, case) in cases.iter().enumerate() {
        let expected = &case["expected"];
        let item: ApprovalBulkEligibilityItemV1 = serde_json::from_value(case["request"].clone())
            .unwrap_or_else(|error| panic!("case {index}: {error}"));
        let request = ApprovalBulkEligibilityRequestV1 {
            schema: APPROVAL_BULK_ELIGIBILITY_REQUEST_SCHEMA.to_owned(),
            request_id: "vector".to_owned(),
            home_dir: Some(home.clone()),
            items: vec![item],
        };
        let actual = evaluate(&request).unwrap_or_else(|code| panic!("case {index}: {code}"));
        let verdict = &actual["items"][0]["eligible"];
        match expected.get("ok") {
            Some(Value::Bool(flag)) => {
                if *flag {
                    eligible += 1;
                }
                if verdict != &Value::Bool(*flag) {
                    assert!(
                        *flag && targets_a_stricter_basename(&case["request"]),
                        "case {index}: {}",
                        case["request"]
                    );
                    stricter += 1;
                }
            }
            _ => assert_eq!(
                verdict,
                &Value::Bool(false),
                "case {index} raised {expected}: {}",
                case["request"]
            ),
        }
    }
    assert!(eligible > 100, "vector set must cover eligible requests");
    assert!(
        stricter < 400,
        "stricter classifier verdicts must stay rare: {stricter}"
    );
}
