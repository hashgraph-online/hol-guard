use super::*;

#[test]
fn network_status_reports_no_protection_without_a_backend() {
    let (status, body) = status().unwrap();
    assert_eq!(status, 200);
    assert_eq!(body["schema"], "guard.network-status.v1");
    assert_eq!(body["protection_active"], false);
    assert_eq!(body["effective_grade"], "unavailable");
    assert_eq!(body["backends"].as_array().unwrap().len(), 4);
}
