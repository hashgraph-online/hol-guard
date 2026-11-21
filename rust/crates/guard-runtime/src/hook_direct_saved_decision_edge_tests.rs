use super::*;

#[test]
fn truthy_follows_python() {
    for value in [
        json!(true),
        json!(1),
        json!(-0.5),
        json!("x"),
        json!([0]),
        json!({"a": 0}),
    ] {
        assert!(truthy(Some(&value)), "{value}");
    }
    for value in [
        json!(null),
        json!(false),
        json!(0),
        json!(0.0),
        json!(""),
        json!([]),
        json!({}),
    ] {
        assert!(!truthy(Some(&value)), "{value}");
    }
    assert!(!truthy(None));
}
