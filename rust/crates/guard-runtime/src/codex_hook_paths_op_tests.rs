use std::fs;

use serde_json::{json, Value};

use super::*;

fn ask(request: Value) -> Result<Value, String> {
    let bytes = run_command(request.to_string().as_bytes())?;
    Ok(serde_json::from_slice(&bytes).expect("json"))
}

fn sha24(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))[..24].to_owned()
}

#[test]
fn a_target_owns_a_manifest_and_a_receipt_named_by_its_hash() {
    let answer = ask(json!({"guard_home": "/guard", "config_path": "/nowhere/cfg/config.toml"}))
        .expect("an answer");
    let hash = sha24("/nowhere/cfg/config.toml");
    assert_eq!(
        answer["manifest_path"],
        json!(format!("/guard/managed/codex/hooks-{hash}.manifest.json"))
    );
    assert_eq!(
        answer["receipt_path"],
        json!(format!(
            "/guard/managed/codex/hooks-{hash}.authority-receipt.json"
        ))
    );
    assert_eq!(
        answer["key_path"],
        json!("/guard/managed/codex/hook-manifest.key")
    );
}

#[test]
fn the_key_answers_without_a_config_and_the_target_files_do_not() {
    let answer = ask(json!({"guard_home": "/guard"})).expect("an answer");
    assert_eq!(answer["manifest_path"], Value::Null);
    assert_eq!(answer["receipt_path"], Value::Null);
    assert_eq!(
        answer["key_path"],
        json!("/guard/managed/codex/hook-manifest.key")
    );
}

#[test]
fn a_guard_home_is_joined_as_the_caller_spells_it() {
    let answer = ask(json!({"guard_home": "relative/home"})).expect("an answer");
    assert_eq!(
        answer["key_path"],
        json!("relative/home/managed/codex/hook-manifest.key")
    );
}

#[cfg(unix)]
#[test]
fn a_link_to_the_config_names_the_same_manifest_as_the_config() {
    let root = std::env::temp_dir().join(format!("guard-hook-paths-{}", std::process::id()));
    let real = root.join("real");
    fs::create_dir_all(&real).expect("dir");
    let link = root.join("link");
    std::os::unix::fs::symlink(&real, &link).expect("link");
    let config = real.join("config.toml");
    let home = Path::new("/guard");
    assert_eq!(
        manifest_path(home, &config),
        manifest_path(home, &link.join("config.toml"))
    );
    assert_ne!(
        manifest_path(home, &config),
        manifest_path(home, &real.join("other.toml"))
    );
    assert_ne!(
        manifest_path(home, &config),
        receipt_path(home, &config),
        "the receipt is its own file"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_request_that_cannot_name_files_is_refused() {
    for request in [
        json!({"guard_home": ""}),
        json!({"guard_home": "/guard", "config_path": ""}),
        json!({"guard_home": "/guard", "config_path": "config.toml"}),
        json!({"guard_home": "/guard", "config_path": "/a\u{0}b"}),
        json!({"guard_home": "/gu\u{0}ard"}),
        json!({"config_path": "/a"}),
        json!([]),
    ] {
        assert_eq!(
            ask(request).unwrap_err(),
            "codex_hook_paths_request_invalid"
        );
    }
}

#[test]
fn an_oversized_request_is_refused() {
    let big = "a".repeat(20_000);
    let error = run_command(json!({"guard_home": big}).to_string().as_bytes()).unwrap_err();
    assert_eq!(error, "codex_hook_paths_request_too_large");
}

#[test]
fn the_pending_publication_journal_is_one_per_home_with_or_without_a_config() {
    let journal = json!("/guard/managed/codex/pending-hook-publication.json");
    let bare = ask(json!({"guard_home": "/guard"})).expect("an answer");
    let owned = ask(json!({"guard_home": "/guard", "config_path": "/nowhere/cfg/config.toml"}))
        .expect("an answer");
    assert_eq!(bare["record_path"], journal);
    assert_eq!(owned["record_path"], journal);
}
