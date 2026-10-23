use gauntlet_evidence::verify_staging_control_opening_ineligible;
use serde_json::Value;

#[test]
fn tail_only_fixture_cannot_be_promoted_to_a_staging_opening() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_control_reported_tail_v1.json")).unwrap();
    let base = &fixture["bases"]["success"];
    let raw = serde_json::to_vec(&base["control"]).unwrap();
    let key = base["public_key_hex"].as_str().unwrap();
    let error = verify_staging_control_opening_ineligible(&raw, "success", key, &base["expected"])
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "native output review incomplete or unavailable"
    );

    assert!(verify_staging_control_opening_ineligible(
        &raw,
        "success",
        &"0".repeat(64),
        &base["expected"]
    )
    .is_err());
    assert!(
        verify_staging_control_opening_ineligible(&raw, "all", key, &base["expected"]).is_err()
    );
}
