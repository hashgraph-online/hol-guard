use super::*;

#[test]
fn relay_command_and_feature_names_are_stable() {
    assert_eq!(RELAY_COMMAND, "mcp-relay");
    assert_eq!(RELAY_FEATURE, "mcp-stdio-relay-v1");
}

#[test]
fn the_relay_is_advertised() {
    assert!(crate::resident_protocol::capabilities()
        .features
        .iter()
        .any(|feature| feature == RELAY_FEATURE));
}

#[test]
fn an_unparseable_proxy_argv_exits_with_a_usage_status() {
    let argv: Vec<String> = ["python", "guard", "codex-mcp-proxy", "--surprise=1"]
        .iter()
        .map(|token| (*token).to_owned())
        .collect();
    assert_eq!(run(&argv), 2);
    assert_eq!(run(&["python".to_owned(), "guard".to_owned()]), 2);
}
