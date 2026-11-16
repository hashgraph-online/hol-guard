use serde_json::{json, Value};

use super::{decision_row, generation_lock, scoped_family_supported, LOCK_FILE};

#[test]
fn harness_and_global_rules_name_only_a_scoped_family() {
    assert!(scoped_family_supported("harness", Some("family:mcp")));
    assert!(scoped_family_supported(
        "global",
        Some("family: Prompt-File ")
    ));
    assert!(!scoped_family_supported("harness", Some("family:shell")));
    assert!(!scoped_family_supported("global", Some("family:")));
    // Other scopes, empty ids and non-family ids are left to the store.
    assert!(scoped_family_supported("artifact", Some("family:shell")));
    assert!(scoped_family_supported("harness", Some("  ")));
    assert!(scoped_family_supported("harness", None));
    assert!(scoped_family_supported(
        "harness",
        Some("codex:project:tool")
    ));
}

fn fields(scope: &str) -> Value {
    json!({
        "harness": "codex",
        "scope": scope,
        "action": "allow",
        "artifact_id": "codex:project:mcp-tool:server",
        "workspace": "/work/repo",
        "publisher": "acme",
        "reason": "trusted",
    })
}

#[test]
fn the_row_keeps_only_the_keys_its_scope_owns() {
    let harness = decision_row(&fields("harness")).expect("row");
    assert_eq!(harness["artifact_id"], json!("family:mcp-tool"));
    assert_eq!(harness["workspace"], Value::Null);
    assert_eq!(harness["publisher"], Value::Null);

    let artifact = decision_row(&fields("artifact")).expect("row");
    assert_eq!(
        artifact["artifact_id"],
        json!("codex:project:mcp-tool:server")
    );
    assert_eq!(artifact["workspace"], Value::Null);

    let workspace = decision_row(&fields("workspace")).expect("row");
    let key = workspace["workspace"].as_str().expect("keyed");
    assert!(key.starts_with("workspace:"), "{key}");

    let publisher = decision_row(&fields("publisher")).expect("row");
    assert_eq!(publisher["artifact_id"], Value::Null);
    assert_eq!(publisher["publisher"], json!("acme"));

    for row in [harness, artifact, workspace, publisher] {
        assert_eq!(row["source"], json!("local"));
        assert_eq!(row["artifact_hash"], Value::Null);
        assert_eq!(row["owner"], Value::Null);
        assert_eq!(row["expires_at"], Value::Null);
        assert_eq!(row["reason"], json!("trusted"));
    }
}

#[test]
fn the_generation_lock_excludes_a_second_holder_and_refuses_a_link() {
    let home = tempfile::tempdir().expect("home");
    let held = generation_lock(home.path()).expect("lock");
    let second = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .open(home.path().join(LOCK_FILE))
        .expect("open");
    assert!(fs2::FileExt::try_lock_exclusive(&second).is_err());
    drop(held);
    assert!(fs2::FileExt::try_lock_exclusive(&second).is_ok());

    let linked = tempfile::tempdir().expect("home");
    std::os::unix::fs::symlink(home.path().join(LOCK_FILE), linked.path().join(LOCK_FILE))
        .expect("link");
    assert!(generation_lock(linked.path()).is_none());
}
