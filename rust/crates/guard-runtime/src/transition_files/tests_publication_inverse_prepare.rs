use std::fs;
use std::path::PathBuf;

use serde_json::{json, Value};

use crate::transition_files::dispatch;

const OPERATION: &str = "1b4e28ba-2fa1-41d2-883f-0016d3cca427";

struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "publication-inverse-prepare-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        fs::create_dir_all(root.join("guard")).unwrap();
        Self(fs::canonicalize(root).unwrap())
    }

    fn guard(&self) -> PathBuf {
        self.0.join("guard")
    }

    fn ask(&self, extra: Value) -> Value {
        let mut request = json!({
            "op": "publication_inverse_prepare",
            "home": self.guard().to_string_lossy(),
            "config": self.0.join("config.toml").to_string_lossy(),
            "operation_id": OPERATION,
            "spec": {},
            "context": {},
            "package_roots": [],
        });
        request
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().cloned().unwrap());
        dispatch(&request).unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn an_inverse_without_a_journal_is_refused() {
    let home = Home::new();
    let answer = home.ask(json!({}));
    assert_eq!(
        answer["error"]["transition"],
        "publication_inverse_journal_missing"
    );
}

#[test]
fn an_expired_hook_deadline_stops_the_preparation_first() {
    let home = Home::new();
    let answer = home.ask(json!({"budget": {"hook_ms": 0}}));
    assert_eq!(
        answer["error"]["integrity"],
        "codex_hook_validation_deadline_expired"
    );
}

#[cfg(unix)]
#[test]
fn a_journal_the_runtime_cannot_authenticate_is_not_trusted() {
    use std::os::unix::fs::PermissionsExt;
    let home = Home::new();
    let journal = crate::transition_files::publication::Call::record_path(&home.guard());
    let parent = journal.parent().unwrap();
    fs::create_dir_all(parent).unwrap();
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&journal, b"{\"phase\": \"prepared\"}").unwrap();
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
    let answer = home.ask(json!({}));
    assert!(answer["error"].is_object(), "{answer}");
    assert_ne!(
        answer["error"]["transition"],
        "publication_inverse_journal_missing"
    );
    assert!(journal.exists());
}
