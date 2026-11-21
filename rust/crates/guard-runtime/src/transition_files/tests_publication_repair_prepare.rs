use std::fs;
use std::path::PathBuf;

use serde_json::{json, Value};

use super::fault;
use crate::harness_adapter::Failure;
use crate::transition_files::publication::Call;
use crate::transition_files::{dispatch, Fault};

const OPERATION: &str = "1b4e28ba-2fa1-41d2-883f-0016d3cca427";

struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "publication-repair-prepare-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        fs::create_dir_all(root.join("guard/managed/codex")).unwrap();
        fs::create_dir_all(root.join("home/.codex")).unwrap();
        Self(fs::canonicalize(root).unwrap())
    }

    fn guard(&self) -> PathBuf {
        self.0.join("guard")
    }

    fn config(&self) -> PathBuf {
        self.0.join("home/.codex/config.toml")
    }

    fn ask(&self) -> Value {
        dispatch(&json!({
            "op": "publication_repair_prepare",
            "home": self.guard().to_string_lossy(),
            "config": self.config().to_string_lossy(),
            "operation_id": OPERATION,
            "spec": {},
            "context": {},
            "package_roots": [],
        }))
        .unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_manifest_that_is_present_is_not_restored() {
    let home = Home::new();
    let (manifest, _) = Call::targets(&home.guard(), &home.config().to_string_lossy());
    fs::write(manifest, b"{}").unwrap();
    let answer = home.ask();
    assert_eq!(
        answer["error"]["transition"],
        "authority_repair_manifest_present"
    );
}

#[test]
fn a_repair_without_a_receipt_is_refused() {
    let home = Home::new();
    let answer = home.ask();
    assert_eq!(
        answer["error"]["integrity"],
        "codex_hook_recovery_receipt_invalid"
    );
}

#[test]
fn a_failed_parse_reaches_the_caller_as_a_runtime_error() {
    let parse = Failure::Runtime("Failed to parse Codex config file".to_owned());
    assert_eq!(
        fault(parse).to_json(),
        json!({ "runtime": "Failed to parse Codex config file" })
    );
    assert!(matches!(
        fault(Failure::Invalid),
        Fault::Transition("native_transition_invalid")
    ));
}
