//! An Oh My Pi `read` of a committed page named for the key it documents,
//! such as `docs/auth-evidence/private-key-jwt-client-auth.md` for the OAuth
//! `private_key_jwt` method. PreToolUse admits the read once the page proves
//! it is tracked and holds no secret, so the output review must accept the
//! same proof instead of answering the page as a key file. The text is still
//! scanned, and anything that fails the proof keeps the sensitive-path
//! refusal.
#![cfg(unix)]

use guard_contracts::NativeHookRequestV1;
use guard_hook_core::review_post_tool;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

const PAGE: &str = "docs/auth-evidence/private-key-jwt-client-auth.md";
const PAGE_TEXT: &str =
    "# private_key_jwt\n\nThe client signs a JWT assertion with its own key and posts it\nto the token endpoint.\n";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
                "guard-omp-key-named-document-{}-{}",
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

    fn write(&self, name: &str, text: &str) -> PathBuf {
        let path = self.project().join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        path
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

    fn result(&self, tool: &str, path: &str, file_text: &str) -> NativeHookRequestV1 {
        // OMP's read tool drops the file's final newline.
        let output = file_text.strip_suffix('\n').unwrap_or(file_text);
        NativeHookRequestV1 {
            protocol_version: 1,
            request_id: Some("omp-key-named-document".into()),
            harness: "omp".into(),
            event_name: "PostToolUse".into(),
            payload: json!({
                "tool_name": tool, "tool_input": {"path": path},
                "tool_response": output,
                "guard_source_ref": {"version": 1, "kind": "source_file",
                    "path": path, "tool_input_path": path,
                    "output_sha256": format!("{:x}", Sha256::digest(output.as_bytes())),
                    "output_chars": output.chars().count()}
            }),
            cwd: Some(self.project().to_string_lossy().into_owned()),
            home_dir: self.home().to_string_lossy().into_owned(),
            guard_home: self
                .home()
                .join(".hol-guard")
                .to_string_lossy()
                .into_owned(),
            source_ref_external_allowed: true,
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

fn deny(fixture: &Fixture, tool: &str, path: &str, text: &str) {
    let response = review_post_tool(&fixture.result(tool, path, text));
    assert_eq!(response.decision, "deny", "{path}: {response:?}");
    assert_eq!(
        response.reason_code, "sensitive_path",
        "{path}: {response:?}"
    );
}

#[test]
fn a_committed_key_named_page_keeps_its_read_output() {
    let fixture = Fixture::new();
    let file = fixture.write(PAGE, PAGE_TEXT);
    fixture.track(&[PAGE]);
    for spelling in [file.to_string_lossy().into_owned(), PAGE.to_owned()] {
        let response = review_post_tool(&fixture.result("read", &spelling, PAGE_TEXT));
        assert_eq!(response.decision, "allow", "{spelling}: {response:?}");
    }
}

#[test]
fn an_untracked_key_named_page_keeps_the_sensitive_path_refusal() {
    let fixture = Fixture::new();
    let file = fixture.write(PAGE, PAGE_TEXT);
    fixture.track(&["README.md"]);
    deny(&fixture, "read", &file.to_string_lossy(), PAGE_TEXT);
}

#[test]
fn a_committed_key_file_keeps_the_sensitive_path_refusal() {
    let fixture = Fixture::new();
    // The key-name relief covers documents only: a key's own extension, a
    // name with no document extension, and a page inside a key container
    // keep the refusal even when the repository tracks them.
    for name in [
        "docs/private-key.pem",
        "docs/wallet-key",
        "secrets/private-key-notes.md",
    ] {
        let file = fixture.write(name, PAGE_TEXT);
        fixture.track(&[name]);
        deny(&fixture, "read", &file.to_string_lossy(), PAGE_TEXT);
    }
}

#[test]
fn a_committed_key_named_page_holding_a_key_is_still_withheld() {
    let fixture = Fixture::new();
    let text = format!(
        "# Signing key\n\n{}\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo\n",
        ["-----BEGIN RSA ", "PRIVATE KEY-----"].concat()
    );
    let file = fixture.write(PAGE, &text);
    fixture.track(&[PAGE]);
    let response = review_post_tool(&fixture.result("read", &file.to_string_lossy(), &text));
    assert_eq!(response.decision, "deny", "{response:?}");
}

#[test]
fn a_write_result_for_a_committed_key_named_page_keeps_the_refusal() {
    let fixture = Fixture::new();
    let file = fixture.write(PAGE, PAGE_TEXT);
    fixture.track(&[PAGE]);
    deny(&fixture, "write", &file.to_string_lossy(), PAGE_TEXT);
}

/// Each spelling and the file it lands on must pass the same proof. A link
/// named like a committed dotenv template that lands on a key-named page,
/// and a key-named link that lands on a template, keep the refusal.
#[test]
fn a_link_crossing_the_two_proofs_keeps_the_refusal() {
    let fixture = Fixture::new();
    let page = fixture.write(PAGE, PAGE_TEXT);
    let template_text = "API_BASE_URL=http://127.0.0.1:3000\n";
    let template = fixture.write(".env.example", template_text);
    let template_link = fixture.project().join("docs/.env.example");
    std::os::unix::fs::symlink(&page, &template_link).unwrap();
    let page_link = fixture.project().join("docs/private-key-jwt-notes.md");
    std::os::unix::fs::symlink(&template, &page_link).unwrap();
    fixture.track(&[
        PAGE,
        ".env.example",
        "docs/.env.example",
        "docs/private-key-jwt-notes.md",
    ]);
    deny(
        &fixture,
        "read",
        &template_link.to_string_lossy(),
        PAGE_TEXT,
    );
    deny(
        &fixture,
        "read",
        &page_link.to_string_lossy(),
        template_text,
    );
}

/// A key-named link to a committed page in a credential store keeps the
/// refusal: the name as written is screened as well as the file it reaches.
#[test]
fn a_key_named_link_inside_a_credential_store_keeps_the_refusal() {
    let fixture = Fixture::new();
    let page = fixture.write(PAGE, PAGE_TEXT);
    let store = fixture.home().join(".gnupg");
    std::fs::create_dir_all(&store).unwrap();
    let link = store.join("private-key-jwt-client-auth.md");
    std::os::unix::fs::symlink(&page, &link).unwrap();
    fixture.track(&[PAGE]);
    deny(&fixture, "read", &link.to_string_lossy(), PAGE_TEXT);
}
