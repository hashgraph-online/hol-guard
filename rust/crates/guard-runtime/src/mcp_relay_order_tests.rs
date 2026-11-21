use super::argument_order;

fn order(line: &str) -> Option<Vec<String>> {
    argument_order(line.as_bytes())
}

#[test]
fn keeps_the_host_key_order() {
    assert_eq!(
        order(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"z":1,"a":{"q":2,"b":3},"m":[1]}}}"#
        ),
        Some(vec!["z".to_owned(), "a".to_owned(), "m".to_owned()])
    );
    assert_eq!(
        order("{\"params\":{\"arguments\":{\"\\u00e9\":1,\"e\":2}}}\n"),
        Some(vec!["\u{e9}".to_owned(), "e".to_owned()])
    );
}

#[test]
fn has_no_order_without_an_arguments_object() {
    assert_eq!(order(r#"{"params":{"name":"x"}}"#), None);
    assert_eq!(order(r#"{"params":{"arguments":"{}"}}"#), None);
    assert_eq!(order(r#"{"params":[1]}"#), None);
    assert_eq!(order(r#"[1]"#), None);
    assert_eq!(order(r#"{"params":{"arguments":{"a":1}}} x"#), None);
}

#[test]
fn refuses_a_repeated_key_on_the_path() {
    assert_eq!(
        order(r#"{"params":{"arguments":{"a":1,"b":2,"a":3}}}"#),
        None
    );
    assert_eq!(
        order(r#"{"params":{"arguments":{"a":1}},"params":{"arguments":{"b":1}}}"#),
        None
    );
    assert_eq!(
        order(r#"{"params":{"arguments":{"a":1},"arguments":{"b":1}}}"#),
        None
    );
    assert_eq!(
        order(r#"{"params":{"arguments":{"a":{"x":1,"x":2},"b":1}}}"#),
        Some(vec!["a".to_owned(), "b".to_owned()])
    );
}
