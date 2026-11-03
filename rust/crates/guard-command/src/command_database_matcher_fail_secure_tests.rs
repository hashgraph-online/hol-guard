use super::DatabaseMatcher;
use crate::{CanonicalCommandV1, CommandSegmentV1, CommandSpanV1};
use serde_json::json;

fn command(arguments: &[&str]) -> CanonicalCommandV1 {
    CanonicalCommandV1 {
        exact_raw_text: true,
        normalized_text: String::new(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "test".into(),
        wrapper_chain: Vec::new(),
        segments: vec![CommandSegmentV1 {
            text: String::new(),
            tokens: Vec::new(),
            executable: Some("givi".into()),
            arguments: arguments.iter().map(|value| (*value).to_owned()).collect(),
            environment_names: Vec::new(),
            wrapper_chain: Vec::new(),
            path_overridden: false,
            execution_context: "root".into(),
            pipeline_index: 0,
            span: CommandSpanV1 {
                source: "normalized".into(),
                start: 0,
                end: 0,
            },
        }],
        confidence: "exact".into(),
        uncertainty_reason: None,
        path_overridden: false,
        parser_profile: "test".into(),
        security_identity: String::new(),
    }
}

fn matched(fail_secure: Option<bool>, arguments: &[&str]) -> bool {
    let mut config = json!({
        "executables": ["givi"],
        "subcommands": ["auto-review", "enable"],
        "options_with_values": ["--repo", "-f"],
        "forbidden_flags": ["--help", "-h"],
        "interleaved_options_with_values": ["--repo", "-f"]
    });
    if let Some(value) = fail_secure {
        config["fail_secure_unknown_options"] = json!(value);
    }
    DatabaseMatcher::from_config("leading-subcommand.v1", config)
        .unwrap()
        .match_segments(&command(arguments))
        .unwrap()
        == vec![0]
}

#[test]
fn fail_secure_unknown_options_rejects_only_unnamed_options() {
    let dry = &["auto-review", "enable", "--dry-run"][..];
    assert!(matched(None, dry));
    assert!(matched(Some(false), dry));
    assert!(!matched(Some(true), dry));
    assert!(matched(
        Some(true),
        &["auto-review", "enable", "--repo", "demo"]
    ));
    assert!(matched(
        Some(true),
        &["auto-review", "enable", "--repo", "-n"]
    ));
    assert!(matched(Some(true), &["auto-review", "enable", "-fdemo"]));
    assert!(matched(
        Some(true),
        &["auto-review", "enable", "--", "--dry-run"]
    ));
    assert!(!matched(
        Some(true),
        &["--dry-run", "auto-review", "enable"]
    ));
    assert!(!matched(Some(true), &["auto-review", "enable", "-x"]));
    assert!(!matched(Some(true), &["auto-review", "enable", "-h:bogus"]));
    assert!(matched(Some(true), &["auto-review", "enable", "-f:demo"]));
    let required = json!({
        "executables": ["givi"],
        "subcommands": ["auto-review", "enable"],
        "required_flags_anywhere": ["-X"],
        "fail_secure_unknown_options": true
    });
    let require = |arguments: &[&str]| {
        DatabaseMatcher::from_config("leading-subcommand.v1", required.clone())
            .unwrap()
            .match_segments(&command(arguments))
            .unwrap()
            == vec![0]
    };
    assert!(require(&["auto-review", "enable", "-X"]));
    assert!(!require(&["auto-review", "enable", "-Y"]));
}
