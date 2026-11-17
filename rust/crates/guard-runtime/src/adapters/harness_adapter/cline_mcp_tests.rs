use std::fs;

use serde_json::json;

use super::super::Ctx;
use super::{applied, scan};
use crate::pyjson::PyVal;

#[test]
fn a_changed_settings_file_is_not_rewritten_from_a_stale_scan() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let settings = home.join(".cline/data/settings/cline_mcp_settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(
        &settings,
        r#"{"mcpServers": {"local": {"command": "node", "args": []}}}"#,
    )
    .unwrap();
    let ctx = Ctx::parse(Some(&json!({
        "home": home,
        "workspace": null,
        "guard_home": root.path().join("guard"),
        "home_override_explicit": false,
        "cwd": root.path(),
        "user_home": home,
        "env": {"PATH": ""},
    })))
    .unwrap();
    let scanned = scan(&ctx).unwrap();
    let found = scanned["candidates"][0].clone();
    fs::write(&settings, r#"{"mcpServers": {}}"#).unwrap();
    let replacement = vec![(
        "local".to_owned(),
        PyVal::Dict(vec![("command".to_owned(), PyVal::Str("/py".into()))]),
    )];
    assert!(applied(&ctx, vec![(found, replacement)]).is_err());
    assert_eq!(
        fs::read_to_string(&settings).unwrap(),
        r#"{"mcpServers": {}}"#
    );
}
