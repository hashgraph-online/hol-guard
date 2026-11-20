use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use super::dispatch;
use super::inspect::sha256_hex;
use super::publication::Call;

pub(super) struct Home(pub(super) PathBuf);

impl Home {
    pub(super) fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "publication-repair-plan-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        fs::create_dir_all(root.join("guard/managed/codex")).unwrap();
        fs::create_dir_all(root.join("home/.codex")).unwrap();
        Self(fs::canonicalize(root).unwrap())
    }

    pub(super) fn guard(&self) -> PathBuf {
        self.0.join("guard")
    }

    pub(super) fn config(&self) -> PathBuf {
        self.0.join("home/.codex/config.toml")
    }

    pub(super) fn change(&self) -> Value {
        let (manifest, _) = Call::targets(&self.guard(), &self.config().to_string_lossy());
        json!({
            "path": manifest.to_string_lossy(),
            "before": null,
            "after": STANDARD.encode(b"{}\n"),
            "before_mode": 0o600,
            "after_mode": 0o600,
            "kind": "binding",
            "no_follow": true,
        })
    }

    pub(super) fn files(&self) -> Vec<Value> {
        let (_, receipt) = Call::targets(&self.guard(), &self.config().to_string_lossy());
        let secret = self.guard().join("managed/codex/hook-manifest.key");
        let mut files = vec![self.change()];
        for path in [secret, receipt, self.config()] {
            files.push(dependency(&path));
        }
        files
    }

    fn ask(&self, operation: &str, files: Vec<Value>) -> Result<Value, String> {
        dispatch(&json!({
            "op": "publication_repair_plan",
            "home": self.guard().to_string_lossy(),
            "config": self.config().to_string_lossy(),
            "operation_id": operation,
            "change": self.change(),
            "files": files,
            "native_runtime": null,
            "verification_workspace": null,
        }))
        .map_err(|error| format!("{error:?}"))
        .and_then(|answer| match answer.get("error") {
            Some(error) => Err(error.to_string()),
            None => Ok(answer["value"].clone()),
        })
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(super) fn dependency(path: &Path) -> Value {
    json!({
        "path": path.to_string_lossy(),
        "before": null,
        "after": null,
        "before_mode": 0o600,
        "after_mode": 0o600,
        "kind": "binding",
        "no_follow": true,
        "expected_digest": sha256_hex(path.to_string_lossy().as_bytes()),
    })
}

pub(super) const OPERATION: &str = "1b4e28ba-2fa1-41d2-883f-0016d3cca427";

#[test]
fn a_restore_of_the_missing_manifest_answers_its_subject() {
    let home = Home::new();
    let answer = home.ask(OPERATION, home.files()).unwrap();
    let payload = &answer["payload"];
    assert_eq!(
        payload["schema"],
        "hol-guard.codex-authority-repair-plan.v1"
    );
    assert_eq!(payload["action"], "apps.repair.codex-authority");
    assert_eq!(payload["operation_id"], OPERATION);
    assert_eq!(payload["files"].as_array().map(Vec::len), Some(4));
    assert!(payload.get("native_runtime").is_none());
    let subject = answer["subject"].as_str().unwrap();
    assert!(subject.starts_with(&format!("codex-authority-repair:{OPERATION}:")));
}

#[test]
fn a_noncanonical_operation_is_refused() {
    let home = Home::new();
    let error = home
        .ask(&OPERATION.to_uppercase(), home.files())
        .unwrap_err();
    assert!(error.contains("authority_repair_plan_invalid"), "{error}");
}

#[test]
fn a_plan_without_the_config_dependency_is_refused() {
    let home = Home::new();
    let mut files = home.files();
    files.pop();
    let error = home.ask(OPERATION, files).unwrap_err();
    assert!(error.contains("authority_repair_plan_invalid"), "{error}");
}

#[test]
fn a_dependency_that_writes_bytes_is_refused() {
    let home = Home::new();
    let mut files = home.files();
    files[1]["after"] = json!(STANDARD.encode(b"x"));
    let error = home.ask(OPERATION, files).unwrap_err();
    assert!(error.contains("authority_repair_plan_invalid"), "{error}");
}

fn merge(previous: &Value, change: &Value) -> Result<Value, String> {
    dispatch(&json!({
        "op": "publication_merge_dependency",
        "previous": previous,
        "change": change,
    }))
    .map_err(|error| format!("{error:?}"))
    .and_then(|answer| match answer.get("error") {
        Some(error) => Err(error.to_string()),
        None => Ok(answer["value"].clone()),
    })
}

fn artifact(role: &str, invocation: Option<Value>) -> Value {
    let mut item = dependency(Path::new("/opt/guard/bin/runtime"));
    item["artifact_identity"] = json!({ "size": 10, "owner_uid": 0, "role": role });
    if let Some(invocation) = invocation {
        item["invocation_identity"] = invocation;
    }
    item
}

#[test]
fn two_roles_of_one_artifact_merge_with_the_one_invocation_contract() {
    let contract = json!({ "path": "/usr/bin/runtime", "mode": 0o755 });
    let merged = merge(
        &artifact("bridge", None),
        &artifact("launch_runtime", Some(contract.clone())),
    )
    .unwrap();
    assert_eq!(merged["artifact_identity"]["role"], "artifact");
    assert_eq!(merged["invocation_identity"], contract);
    let same = artifact("bridge", None);
    assert_eq!(merge(&same, &same).unwrap()["same"], true);
}

#[test]
fn different_invocation_contracts_or_bytes_do_not_merge() {
    let one = artifact("bridge", Some(json!({ "path": "/a" })));
    let two = artifact("launch_runtime", Some(json!({ "path": "/b" })));
    assert!(merge(&one, &two)
        .unwrap_err()
        .contains("adapter_preparation_generation_conflict"));
    let mut written = artifact("bridge", None);
    written["after"] = json!(STANDARD.encode(b"x"));
    let error = merge(&artifact("bridge", None), &written).unwrap_err();
    assert!(error.contains("adapter_preparation_generation_conflict"));
}
