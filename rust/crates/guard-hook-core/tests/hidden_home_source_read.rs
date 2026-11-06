//! An Oh My Pi `read` of a file below a hidden directory of the home directory,
//! as the extension sends it: a source reference to the requested path beside
//! the text the host presented. Hiddenness alone is not a reason to refuse the
//! result; the credential screen PreToolUse applies to the same read is.
#![cfg(unix)]

use guard_contracts::NativeHookRequestV1;
use guard_hook_core::review_post_tool;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

const MANIFEST: &str = ".nvm/versions/node/v25.2.1/lib/node_modules/inert-pkg/package.json";
const MANIFEST_TEXT: &str = "{\n  \"name\": \"inert-pkg\",\n  \"version\": \"3.1.0\"\n}\n";

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "guard-hidden-home-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        std::fs::create_dir(root.join("home")).unwrap();
        std::fs::create_dir(root.join("work")).unwrap();
        Self(root)
    }

    fn home(&self) -> PathBuf {
        self.0.join("home")
    }

    fn work(&self) -> PathBuf {
        self.0.join("work")
    }

    fn seed(&self, relative: &str, text: &str) -> PathBuf {
        let path = self.home().join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        path
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn read_result(root: &TestRoot, path: &Path, file_text: &str) -> NativeHookRequestV1 {
    // OMP's read tool drops the file's final newline.
    let output = file_text.strip_suffix('\n').unwrap_or(file_text);
    let target = path.to_string_lossy().into_owned();
    NativeHookRequestV1 {
        protocol_version: 1,
        request_id: Some("hidden-home-read".into()),
        harness: "omp".into(),
        event_name: "PostToolUse".into(),
        payload: json!({
            "tool_name": "read", "tool_input": {"path": target},
            "tool_response": output,
            "guard_source_ref": {"version": 1, "kind": "source_file",
                "path": target, "tool_input_path": target,
                "output_sha256": format!("{:x}", Sha256::digest(output.as_bytes())),
                "output_chars": output.chars().count()}
        }),
        cwd: Some(root.work().to_string_lossy().into()),
        home_dir: root.home().to_string_lossy().into(),
        guard_home: root.0.join("guard").to_string_lossy().into(),
        source_ref_external_allowed: true,
        observe_mode: false,
        deadline_budget_ms: Some(750),
    }
}

fn token() -> String {
    format!("{}{}", ["gh", "p_"].concat(), "b".repeat(30))
}

#[test]
fn a_toolchain_package_manifest_under_a_hidden_home_directory_keeps_its_output() {
    let root = TestRoot::new();
    let manifest = root.seed(MANIFEST, MANIFEST_TEXT);
    let result = review_post_tool(&read_result(&root, &manifest, MANIFEST_TEXT));
    assert_eq!(result.model_output_action, "allow_original", "{result:?}");
    assert_eq!(result.reason_code, "source_full_scan_allow", "{result:?}");
}

#[test]
fn a_hidden_home_read_is_still_scanned_for_secrets() {
    let root = TestRoot::new();
    let body = format!(
        "{{\n  \"name\": \"inert-pkg\",\n  \"note\": \"{}\"\n}}\n",
        token()
    );
    let manifest = root.seed(MANIFEST, &body);
    // The model is shown clean text, but the file on disk holds a secret.
    let shown = read_result(&root, &manifest, MANIFEST_TEXT);
    assert_eq!(review_post_tool(&shown).reason_code, "source_secret_match");
    // A file that shows its secret to the model is held back as well.
    let leaked = read_result(&root, &manifest, &body);
    assert_eq!(review_post_tool(&leaked).reason_code, "source_secret_match");
}

#[test]
fn credential_stores_and_tool_configuration_below_home_stay_unreviewable() {
    let root = TestRoot::new();
    for relative in [
        ".ssh/config",
        ".aws/credentials.txt",
        ".config/gh/hosts.yml",
        ".config/exampletool/config.yaml",
        ".npmrc",
        ".ngrok2/ngrok.yml",
        ".cargo/bin/helper",
        ".nvm/versions/node/v25.2.1/bin/node",
        ".nvm/.cache/state/package.json",
        ".nvm/versions/node/v25.2.1/lib/node_modules/inert-pkg/.env",
    ] {
        let file = root.seed(relative, MANIFEST_TEXT);
        let result = review_post_tool(&read_result(&root, &file, MANIFEST_TEXT));
        assert_ne!(
            result.model_output_action, "allow_original",
            "{relative}: {result:?}"
        );
    }
}

#[test]
fn a_skill_document_outside_a_supported_root_stays_unreviewable() {
    let root = TestRoot::new();
    for relative in [
        ".nvm/docs/SKILL.md",
        ".nvm/versions/node/v25.2.1/lib/node_modules/inert-pkg/SKILL.md",
    ] {
        let file = root.seed(relative, MANIFEST_TEXT);
        let result = review_post_tool(&read_result(&root, &file, MANIFEST_TEXT));
        assert_ne!(
            result.model_output_action, "allow_original",
            "{relative}: {result:?}"
        );
    }
}

#[test]
fn a_link_cannot_dress_a_credential_store_as_a_toolchain() {
    let root = TestRoot::new();
    let store = root.seed(".aws/inert-pkg/package.json", MANIFEST_TEXT);
    let toolchain = root
        .home()
        .join(".nvm/versions/node/v25.2.1/lib/node_modules");
    std::fs::create_dir_all(&toolchain).unwrap();
    std::os::unix::fs::symlink(store.parent().unwrap(), toolchain.join("inert-pkg")).unwrap();
    let linked = toolchain.join("inert-pkg/package.json");
    let result = review_post_tool(&read_result(&root, &linked, MANIFEST_TEXT));
    assert_ne!(result.model_output_action, "allow_original", "{result:?}");
}

#[test]
fn a_hidden_directory_outside_the_home_directory_stays_unreviewable() {
    let root = TestRoot::new();
    let outside = root.0.join(MANIFEST);
    std::fs::create_dir_all(outside.parent().unwrap()).unwrap();
    std::fs::write(&outside, MANIFEST_TEXT).unwrap();
    let result = review_post_tool(&read_result(&root, &outside, MANIFEST_TEXT));
    assert_ne!(result.model_output_action, "allow_original", "{result:?}");
}
