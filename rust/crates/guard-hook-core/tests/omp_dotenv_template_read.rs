//! An Oh My Pi `read` of the dotenv template a repository commits beside its
//! code, such as `.env.example`. PreToolUse admits the read once the file
//! proves it is tracked and holds no secret, so the output review must accept
//! the same proof instead of answering the template as the local `.env`.
//! The file's text is still scanned, and anything that fails the proof keeps
//! the sensitive-path refusal.
#![cfg(unix)]

use guard_contracts::NativeHookRequestV1;
use guard_hook_core::review_post_tool;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

const TEMPLATE: &str = ".env.example";
const TEMPLATE_TEXT: &str = "API_BASE_URL=http://127.0.0.1:3000\nFEATURE_ROUTE_TIMEOUT_MS=2000\n";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
                "guard-omp-dotenv-template-{}-{}",
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
            request_id: Some("omp-dotenv-template".into()),
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

fn token() -> String {
    format!("{}{}", ["gh", "p_"].concat(), "b".repeat(30))
}

#[test]
fn a_committed_placeholder_template_keeps_its_read_output() {
    let fixture = Fixture::new();
    let file = fixture.write(TEMPLATE, TEMPLATE_TEXT);
    fixture.track(&[TEMPLATE]);
    for spelling in [file.to_string_lossy().into_owned(), TEMPLATE.to_owned()] {
        let response = review_post_tool(&fixture.result("read", &spelling, TEMPLATE_TEXT));
        assert_eq!(response.decision, "allow", "{spelling}: {response:?}");
    }
}

#[test]
fn an_untracked_template_keeps_the_sensitive_path_refusal() {
    let fixture = Fixture::new();
    let file = fixture.write(TEMPLATE, TEMPLATE_TEXT);
    fixture.track(&["README.md"]);
    let response =
        review_post_tool(&fixture.result("read", &file.to_string_lossy(), TEMPLATE_TEXT));
    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "sensitive_path");
}

#[test]
fn a_committed_local_dotenv_file_keeps_the_sensitive_path_refusal() {
    let fixture = Fixture::new();
    let file = fixture.write(".env", TEMPLATE_TEXT);
    fixture.track(&[".env"]);
    let response =
        review_post_tool(&fixture.result("read", &file.to_string_lossy(), TEMPLATE_TEXT));
    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "sensitive_path");
}

#[test]
fn a_committed_template_holding_a_secret_is_still_withheld() {
    let fixture = Fixture::new();
    let text = format!("GITHUB_TOKEN={}\n", token());
    let file = fixture.write(TEMPLATE, &text);
    fixture.track(&[TEMPLATE]);
    let response = review_post_tool(&fixture.result("read", &file.to_string_lossy(), &text));
    assert_eq!(response.decision, "deny", "{response:?}");
}

#[test]
fn a_template_link_to_the_local_dotenv_file_keeps_the_refusal() {
    let fixture = Fixture::new();
    let local = fixture.write(".env", TEMPLATE_TEXT);
    let link = fixture.project().join(TEMPLATE);
    std::os::unix::fs::symlink(&local, &link).unwrap();
    fixture.track(&[TEMPLATE]);
    let response =
        review_post_tool(&fixture.result("read", &link.to_string_lossy(), TEMPLATE_TEXT));
    assert_eq!(response.decision, "deny");
}

#[test]
fn a_write_result_for_a_committed_template_keeps_the_refusal() {
    let fixture = Fixture::new();
    let file = fixture.write(TEMPLATE, TEMPLATE_TEXT);
    fixture.track(&[TEMPLATE]);
    let response =
        review_post_tool(&fixture.result("write", &file.to_string_lossy(), TEMPLATE_TEXT));
    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "sensitive_path");
}
