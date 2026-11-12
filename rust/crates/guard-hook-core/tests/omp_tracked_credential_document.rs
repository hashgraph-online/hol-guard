//! An Oh My Pi `edit` of a committed project document whose name carries a
//! credential word, as the extension reports it after the tool ran: the
//! envelope names the file and the result is the host's own inline text, with
//! no source reference. PreToolUse admits the edit once the file proves it is
//! a tracked, secret-free document, so the output recheck must accept the same
//! proof. Anything that fails it keeps the sensitive-target refusal.
#![cfg(unix)]

use guard_contracts::NativeHookRequestV1;
use guard_hook_core::review_post_tool;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

const CATALOG: &str = "contributions/extensions/command.kubernetes-secrets.json";
const CATALOG_TEXT: &str =
    "{\n  \"id\": \"command.kubernetes-secrets\",\n  \"title\": \"List cluster secrets\",\n  \"version\": \"1.1.0\"\n}\n";

struct Fixture(PathBuf);

impl Fixture {
    /// A home holding one repository, under the build tree like the
    /// guard-command fixtures for the same proof.
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
                "guard-omp-tracked-document-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("home/project/.git/info")).unwrap();
        Self(std::fs::canonicalize(root).unwrap())
    }

    fn home(&self) -> PathBuf {
        self.0.join("home")
    }

    fn project(&self) -> PathBuf {
        self.home().join("project")
    }

    fn write(&self, path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// A version 2 index listing `names`, as `git add` writes it.
    fn track(&self, names: &[&str]) {
        let mut bytes = b"DIRC".to_vec();
        bytes.extend_from_slice(&2_u32.to_be_bytes());
        bytes.extend_from_slice(&(names.len() as u32).to_be_bytes());
        for name in names {
            let entry = (62 + name.len() + 8) & !7;
            let start = bytes.len();
            bytes.resize(start + 60, 0);
            bytes.extend_from_slice(&(name.len() as u16).to_be_bytes());
            bytes.extend_from_slice(name.as_bytes());
            bytes.resize(start + entry, 0);
        }
        std::fs::write(self.project().join(".git/index"), bytes).unwrap();
    }

    fn edit_result(&self, path: &str) -> NativeHookRequestV1 {
        NativeHookRequestV1 {
            protocol_version: 1,
            request_id: Some("omp-tracked-document".into()),
            harness: "omp".into(),
            event_name: "PostToolUse".into(),
            payload: json!({
                "tool_name": "edit",
                "tool_input": {"path": path},
                "tool_response": [{"type": "text", "text": "Successfully replaced 1 block."}]
            }),
            cwd: Some(self.project().to_string_lossy().into_owned()),
            home_dir: self.home().to_string_lossy().into_owned(),
            guard_home: self
                .home()
                .join(".hol-guard")
                .to_string_lossy()
                .into_owned(),
            source_ref_external_allowed: false,
            observe_mode: false,
            deadline_budget_ms: Some(750),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_tracked_catalog_named_for_secrets_keeps_its_edit_result() {
    let fixture = Fixture::new();
    let file = fixture.project().join(CATALOG);
    fixture.write(&file, CATALOG_TEXT);
    fixture.track(&[CATALOG]);
    for spelling in [file.to_string_lossy().into_owned(), CATALOG.to_owned()] {
        let response = review_post_tool(&fixture.edit_result(&spelling));
        assert_eq!(
            response.decision, "allow",
            "{spelling}: {}",
            response.reason_code
        );
        assert_eq!(response.reason_code, "output_scan_allow");
    }
}

#[test]
fn an_untracked_copy_keeps_the_sensitive_target_refusal() {
    let fixture = Fixture::new();
    let file = fixture.project().join(CATALOG);
    fixture.write(&file, CATALOG_TEXT);
    fixture.track(&["README.md"]);
    let response = review_post_tool(&fixture.edit_result(&file.to_string_lossy()));
    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "sensitive_path");
}

#[test]
fn a_tracked_kubernetes_secret_manifest_keeps_the_refusal() {
    let fixture = Fixture::new();
    let manifest = "deploy/app-secrets.yaml";
    let file = fixture.project().join(manifest);
    fixture.write(
        &file,
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\n",
    );
    fixture.track(&[manifest]);
    let response = review_post_tool(&fixture.edit_result(&file.to_string_lossy()));
    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "sensitive_path");
}

#[test]
fn a_tracked_name_linked_to_a_secret_outside_the_repository_keeps_the_refusal() {
    let fixture = Fixture::new();
    let secret = fixture.home().join("prod-secrets.json");
    fixture.write(&secret, "{\n  \"version\": \"1.0.0\"\n}\n");
    let link = fixture.project().join(CATALOG);
    std::fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&secret, &link).unwrap();
    fixture.track(&[CATALOG]);
    let response = review_post_tool(&fixture.edit_result(&link.to_string_lossy()));
    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "sensitive_path");
}
