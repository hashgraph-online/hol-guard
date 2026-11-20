use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Map, Value};

use super::super::{Ctx, Failure};
use super::publish_hooks;

const ORIGINAL: &[u8] = b"model = \"fixture\"\n";
const RENDERED: &[u8] = b"model = \"fixture\"\n\n[features]\nhooks = true\n";

fn root() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    fs::create_dir_all(root.join("home/.codex")).unwrap();
    fs::write(root.join("home/.codex/config.toml"), ORIGINAL).unwrap();
    (dir, root)
}

fn ctx(root: &Path) -> Ctx {
    Ctx::parse(Some(&json!({
        "home": root.join("home"),
        "guard_home": root.join("guard"),
        "cwd": root,
        "user_home": root.join("home"),
        "env": {},
    })))
    .unwrap()
}

fn change(path: &Path, before: Option<&[u8]>, after: &[u8]) -> Value {
    json!({
        "path": path,
        "before": before.map(|bytes| STANDARD.encode(bytes)),
        "after": STANDARD.encode(after),
        "before_mode": null,
        "after_mode": 384,
        "kind": "file",
        "no_follow": true,
    })
}

/// A publication of the rendered config; `config_before` is what the plan
/// read, `manifest_before` what it found at the manifest.
fn fields(root: &Path, config_before: &[u8], manifest_before: Option<&[u8]>) -> Map<String, Value> {
    let config = root.join("home/.codex/config.toml");
    let manifest = root.join("guard/managed/codex/hooks.manifest.json");
    let receipt = root.join("guard/managed/codex/hooks.receipt.json");
    let mut fields = Map::new();
    fields.insert("home".into(), json!(root.join("guard")));
    fields.insert("config".into(), json!(config));
    fields.insert("operation_id".into(), json!("fixture-operation"));
    fields.insert("original".into(), json!(STANDARD.encode(ORIGINAL)));
    fields.insert("original_identity".into(), Value::Null);
    fields.insert("key_present".into(), json!(true));
    fields.insert(
        "files".into(),
        json!([
            change(&manifest, manifest_before, b"{}\n"),
            change(&receipt, None, b"{}\n"),
            change(&config, Some(config_before), RENDERED),
        ]),
    );
    fields.insert("manifest_index".into(), json!(0));
    fields.insert("receipt_index".into(), json!(1));
    fields.insert("config_index".into(), json!(2));
    fields
}

#[test]
fn a_config_other_than_codexs_own_is_refused() {
    let (_dir, root) = root();
    let mut fields = fields(&root, ORIGINAL, None);
    fields.insert("config".into(), json!(root.join("elsewhere.toml")));
    assert!(matches!(
        publish_hooks(&ctx(&root), &fields),
        Err(Failure::Runtime(message)) if message.contains("canonical config target")
    ));
}

#[test]
fn a_plan_read_from_another_config_writes_nothing() {
    let (_dir, root) = root();
    let answer = publish_hooks(&ctx(&root), &fields(&root, b"stale = 1\n", None))
        .ok()
        .unwrap();
    assert_eq!(
        answer["error"],
        json!({ "transition": "adapter_preparation_generation_conflict" })
    );
    assert_eq!(answer["events"], json!([]));
    assert!(answer.get("state").is_none());
    let config = root.join("home/.codex/config.toml");
    assert_eq!(fs::read(config).unwrap(), ORIGINAL);
    assert!(!root
        .join("guard/managed/codex/hooks.manifest.json")
        .exists());
}

#[test]
fn a_manifest_that_moved_since_the_plan_is_not_prepared() {
    let (_dir, root) = root();
    let stale = fields(&root, ORIGINAL, Some(b"{\"old\": true}\n"));
    let answer = publish_hooks(&ctx(&root), &stale).ok().unwrap();
    assert!(answer["error"].is_object(), "{answer}");
    assert!(answer.get("rollback_error").is_none(), "{answer}");
    let config = root.join("home/.codex/config.toml");
    assert_eq!(fs::read(config).unwrap(), ORIGINAL);
    assert!(!root
        .join("guard/managed/codex/hooks.manifest.json")
        .exists());
}
