use serde_json::{json, Value};

use super::{restorations, restore_paths};

#[test]
fn restores_config_paths_metadata_found_paths_and_warning_text() {
    let args = json!({"restore": [["/w/.codex/config.toml", ".codex/config.toml"]]});
    let restore = restorations(args.as_object().unwrap()).unwrap();
    let mut artifacts = vec![json!({
        "config_path": "/w/.codex/config.toml",
        "metadata": {"source": ["/w/.codex/config.toml", "/other"], "/w/.codex/config.toml": 1},
    })];
    let mut found = vec![
        "/w/.codex/config.toml".to_owned(),
        "/h/hooks.json".to_owned(),
    ];
    let mut warnings = vec!["bad hook in /w/.codex/config.toml".to_owned()];
    restore_paths(&restore, &mut artifacts, &mut found, &mut warnings);
    assert_eq!(artifacts[0]["config_path"], ".codex/config.toml");
    assert_eq!(
        artifacts[0]["metadata"],
        json!({"source": [".codex/config.toml", "/other"], "/w/.codex/config.toml": 1})
    );
    assert_eq!(found, [".codex/config.toml", "/h/hooks.json"]);
    assert_eq!(warnings, ["bad hook in .codex/config.toml"]);
}

#[test]
fn a_missing_restore_is_empty_and_a_malformed_one_is_refused() {
    assert!(restorations(json!({}).as_object().unwrap())
        .unwrap()
        .is_empty());
    for bad in [
        json!("x"),
        json!([["a"]]),
        json!([["a", 1]]),
        json!({"a": "b"}),
    ] {
        let args: Value = json!({ "restore": bad });
        assert!(restorations(args.as_object().unwrap()).is_err());
    }
}
