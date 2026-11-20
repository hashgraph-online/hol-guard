use serde_json::{json, Value};

use super::{expand, restorations, restore_paths};

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

fn expanded(args: Value) -> Result<Value, &'static str> {
    expand(args.as_object().unwrap()).map(|map| Value::Object(map.into_owned()))
}

#[cfg(unix)]
#[test]
fn pairs_become_anchored_sources_with_their_restorations() {
    let args = json!({
        "harness": "codex",
        "cwd": "/w",
        "authenticated_config": "/h/.codex/config.toml",
        "pairs": [
            {"config": "/h/.codex/config.toml", "hooks": "/h/.codex/hooks.json", "scope": "global"},
            {"config": ".codex/config.toml", "hooks": ".codex/hooks.json", "scope": "workspace"},
        ],
        "contents": {".codex/config.toml": "ab", "/h/.codex/hooks.json": null},
    });
    let out = expanded(args).unwrap();
    assert!(out.get("pairs").is_none());
    assert_eq!(out["harness"], "codex");
    assert_eq!(
        out["sources"],
        json!([
            {
                "config_path": "/h/.codex/config.toml", "hooks_path": "/h/.codex/hooks.json",
                "config_scope": "global", "hooks_scope": "global", "authenticated": true,
            },
            {
                "config_path": "/w/.codex/config.toml", "hooks_path": "/w/.codex/hooks.json",
                "config_scope": "workspace", "hooks_scope": "workspace", "authenticated": false,
            },
        ])
    );
    assert_eq!(
        out["restore"],
        json!([
            ["/w/.codex/config.toml", ".codex/config.toml"],
            ["/w/.codex/hooks.json", ".codex/hooks.json"],
        ])
    );
    assert_eq!(
        out["contents"],
        json!({"/w/.codex/config.toml": "ab", "/h/.codex/hooks.json": null})
    );
}

#[test]
fn a_request_without_pairs_passes_through_and_a_malformed_one_is_refused() {
    let plain = json!({"sources": [], "restore": []});
    assert_eq!(expanded(plain.clone()).unwrap(), plain);
    let base = json!({"cwd": "/w", "authenticated_config": "/c"});
    for bad in [
        json!({"pairs": [], "authenticated_config": "/c"}),
        json!({"pairs": [], "cwd": "/w"}),
        json!({"pairs": "x", "cwd": "/w", "authenticated_config": "/c"}),
        json!({"pairs": [{"config": "/c", "hooks": "/h"}], "cwd": "/w", "authenticated_config": "/c"}),
        json!({"pairs": [], "cwd": "/w", "authenticated_config": "/c", "contents": 3}),
    ] {
        assert!(expanded(bad).is_err());
    }
    assert!(expanded(json!({"pairs": [], "cwd": base["cwd"], "authenticated_config": base["authenticated_config"]})).is_ok());
}
