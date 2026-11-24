//! A shell read of a page the repository commits whose name carries a key
//! word, such as `docs/auth-evidence/private-key-jwt-client-auth.md`. The
//! name alone matches the key-file family; the committed-document proof is
//! what clears it, for `cat` and `head` as it already does for `grep`.

use super::tests::{fixture, write_index};
use std::path::Path;

const PAGE: &str = "docs/auth-evidence/private-key-jwt-client-auth.md";
const PAGE_TEXT: &str = "# private_key_jwt\n\nThe client signs a JWT assertion with its own key and posts it\nto the token endpoint.\n";

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

fn decide(harness: &str, command: &str, home: &Path, project: &Path) -> (String, String) {
    let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        home.to_str(),
        project.to_str(),
    );
    (result.decision, result.reason_code)
}

fn reads(name: &str) -> [String; 3] {
    [
        format!("cat {name}"),
        format!("head -5 {name}"),
        format!("head -n 20 ./{name}"),
    ]
}

#[test]
fn a_shell_read_of_a_committed_key_named_page_is_allowed() {
    let (home, project) = fixture();
    write(&project.join(PAGE), PAGE_TEXT);
    write_index(&project.join(".git"), &[PAGE]);
    let absolute = project.join(PAGE);
    for harness in ["omp", "claude-code", "codex"] {
        for command in reads(PAGE)
            .into_iter()
            .chain([format!("cat {}", absolute.display())])
        {
            let (decision, reason) = decide(harness, &command, &home, &project);
            assert_eq!(decision, "allow", "{harness} {command}: {reason}");
        }
    }
}

#[test]
fn an_untracked_key_named_page_keeps_its_review() {
    let (home, project) = fixture();
    write(&project.join(PAGE), PAGE_TEXT);
    write_index(&project.join(".git"), &["README.md"]);
    for command in reads(PAGE) {
        let (decision, reason) = decide("omp", &command, &home, &project);
        assert_ne!(decision, "allow", "{command}: {reason}");
    }
}

#[test]
fn a_committed_key_file_keeps_its_review() {
    let (home, project) = fixture();
    for name in [
        "docs/private-key.pem",
        "docs/wallet.key",
        "docs/private.key",
    ] {
        write(&project.join(name), PAGE_TEXT);
        write_index(&project.join(".git"), &[name]);
        for command in reads(name) {
            let (decision, reason) = decide("omp", &command, &home, &project);
            assert_ne!(decision, "allow", "{command}: {reason}");
        }
    }
}

#[test]
fn a_committed_key_named_page_holding_a_key_keeps_its_review() {
    let (home, project) = fixture();
    let header = ["-----BEGIN ", "RSA PRIVATE", " KEY-----"].concat();
    write(
        &project.join(PAGE),
        &format!("{PAGE_TEXT}\n{header}\nMIIEowIBAAKCAQEA\n"),
    );
    write_index(&project.join(".git"), &[PAGE]);
    for command in reads(PAGE) {
        let (decision, reason) = decide("omp", &command, &home, &project);
        assert_ne!(decision, "allow", "{command}: {reason}");
    }
}

#[test]
fn a_committed_key_named_page_in_a_credential_store_keeps_its_review() {
    let (home, project) = fixture();
    for name in [
        ".ssh/private-key-jwt-client-auth.md",
        ".gnupg/private-key-jwt-client-auth.md",
    ] {
        write(&project.join(name), PAGE_TEXT);
        write_index(&project.join(".git"), &[name]);
        for command in reads(name) {
            let (decision, reason) = decide("omp", &command, &home, &project);
            assert_ne!(decision, "allow", "{command}: {reason}");
        }
    }
}

#[cfg(unix)]
#[test]
fn a_key_named_link_to_a_key_file_keeps_its_review() {
    let (home, project) = fixture();
    write(&project.join("keys/private-key.pem"), PAGE_TEXT);
    let link = project.join(PAGE);
    std::fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(project.join("keys/private-key.pem"), &link).unwrap();
    write_index(&project.join(".git"), &[PAGE, "keys/private-key.pem"]);
    for command in reads(PAGE) {
        let (decision, reason) = decide("omp", &command, &home, &project);
        assert_ne!(decision, "allow", "{command}: {reason}");
    }
}
