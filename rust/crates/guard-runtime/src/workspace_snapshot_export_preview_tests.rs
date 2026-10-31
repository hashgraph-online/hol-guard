use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use guard_scanner::secret_detection::{scan_secret_text, SecretScanSummary};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::export_preview::{
    may_be_short_name, preview, preview_with, run_command, ExportPreviewRequest,
    MAX_FINDINGS_PER_FILE, MAX_PATHS, REDACTION_MARKER,
};

// The values are split so repository secret scanners do not read this file as
// holding a credential; they are joined into the planted fixtures below.
fn github_token() -> String {
    ["ghp_", "AbCdEfGhIjKlMnOpQrStUvWxYz", "012345"].concat()
}

fn request(root: &Path, paths: &[&str]) -> ExportPreviewRequest {
    ExportPreviewRequest {
        root: root.to_str().unwrap().to_owned(),
        paths: paths.iter().map(|path| (*path).to_owned()).collect(),
        max_file_bytes: 0,
        max_total_bytes: 0,
    }
}

fn run(root: &Path, paths: &[&str]) -> Value {
    preview(&request(root, paths)).unwrap()
}

fn write(root: &Path, relative: &str, content: &[u8]) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

fn sha256(content: &[u8]) -> String {
    hex::encode(Sha256::digest(content))
}

fn reasons(result: &Value) -> BTreeMap<String, String> {
    result["excluded"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["path"].as_str().unwrap().to_owned(),
                entry["reason"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// A detector a redaction can never satisfy: it reads the marker back as the
/// secret it replaced.
fn stubborn(text: &str, path: &str, max_findings: usize) -> SecretScanSummary {
    let restored = text.replace(REDACTION_MARKER, &github_token());
    scan_secret_text(&restored, path, "test", None, max_findings)
}

#[test]
fn clean_file_is_included_unchanged_with_a_stable_bundle_digest() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "src/main.rs", b"fn main() {}\n");

    let first = run(dir.path(), &["src/main.rs"]);
    let second = run(dir.path(), &["src/main.rs"]);
    assert_eq!(first["schema"], "guard.workspace-export-preview.v1");
    assert_eq!(first["status"], "ready");
    assert_eq!(first["file_count"], 1);
    assert_eq!(first["redactions"], 0);
    let file = &first["files"][0];
    assert_eq!(file["path"], "src/main.rs");
    assert_eq!(file["bytes"], 13);
    assert_eq!(file["source_sha256"], sha256(b"fn main() {}\n"));
    assert_eq!(file["export_sha256"], file["source_sha256"]);
    assert_eq!(first["bundle_digest"], second["bundle_digest"]);

    write(dir.path(), "src/main.rs", b"fn main() { run() }\n");
    let changed = run(dir.path(), &["src/main.rs"]);
    assert_ne!(changed["bundle_digest"], first["bundle_digest"]);
}

#[test]
fn secrets_are_replaced_and_never_reported() {
    let dir = tempfile::tempdir().unwrap();
    let source = format!("import os\nGH_TOKEN = {}\n", github_token());
    write(dir.path(), "app.py", source.as_bytes());

    let result = run(dir.path(), &["app.py"]);
    assert_eq!(result["status"], "ready");
    assert_eq!(result["redactions"], 1);
    let file = &result["files"][0];
    let exported = format!("import os\nGH_TOKEN = {REDACTION_MARKER}\n");
    assert_eq!(file["source_sha256"], sha256(source.as_bytes()));
    assert_eq!(file["export_sha256"], sha256(exported.as_bytes()));
    assert_eq!(file["export_bytes"], exported.len());
    assert!(!file["redaction_rules"].as_array().unwrap().is_empty());
    assert!(!result.to_string().contains(&github_token()));
}

#[test]
fn a_secret_the_rescan_still_finds_blocks_the_bundle() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "app.py",
        format!("GH_TOKEN = {}\n", github_token()).as_bytes(),
    );
    write(dir.path(), "README.md", b"# app\n");

    let result = preview_with(&request(dir.path(), &["README.md", "app.py"]), stubborn).unwrap();
    assert_eq!(result["status"], "blocked");
    assert_eq!(reasons(&result)["app.py"], "redaction_failed");
    assert_eq!(result["file_count"], 1);
    assert!(!result.to_string().contains(&github_token()));
}

#[test]
fn a_file_at_the_finding_cap_is_not_trusted_to_be_redacted() {
    let dir = tempfile::tempdir().unwrap();
    let mut source = String::new();
    for index in 0..MAX_FINDINGS_PER_FILE + 5 {
        source.push_str(&format!(
            "{}{:06}\n",
            ["ghp_", "AbCdEfGhIjKlMnOpQrStUvWxYz"].concat(),
            index
        ));
    }
    write(dir.path(), "tokens.txt", source.as_bytes());

    let result = run(dir.path(), &["tokens.txt"]);
    assert_eq!(result["status"], "blocked");
    assert_eq!(reasons(&result)["tokens.txt"], "redaction_failed");
}

#[test]
fn paths_that_could_leave_the_root_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "a/b", b"inside\n");

    let invalid = ["", "../x", "/etc/passwd", "a/./b", "a//b", "a\\b", "a/b/"];
    let result = run(dir.path(), &invalid);
    let reasons = reasons(&result);
    for path in invalid {
        assert_eq!(reasons[path], "invalid_path", "{path:?}");
    }
    assert_eq!(result["status"], "empty");
}

#[test]
fn credential_stores_and_policy_directories_stay_out_even_when_named() {
    let dir = tempfile::tempdir().unwrap();
    for path in [
        ".env",
        "config/.env.local",
        "deploy/server.pem",
        "node_modules/pkg/index.js",
        ".git/config",
    ] {
        write(dir.path(), path, b"value\n");
    }

    let result = run(
        dir.path(),
        &[
            ".env",
            "config/.env.local",
            "deploy/server.pem",
            "node_modules/pkg/index.js",
            ".git/config",
        ],
    );
    let reasons = reasons(&result);
    assert_eq!(reasons[".env"], "sensitive");
    assert_eq!(reasons["config/.env.local"], "sensitive");
    assert_eq!(reasons["deploy/server.pem"], "sensitive");
    assert_eq!(reasons["node_modules/pkg/index.js"], "policy_directory");
    assert_eq!(reasons[".git/config"], "policy_directory");
    assert_eq!(result["file_count"], 0);
}

#[test]
fn policy_directories_match_without_case() {
    let dir = tempfile::tempdir().unwrap();
    for path in [".GIT/config", "Node_Modules/pkg/index.js"] {
        write(dir.path(), path, b"value\n");
    }

    let result = run(dir.path(), &[".GIT/config", "Node_Modules/pkg/index.js"]);
    let reasons = reasons(&result);
    assert_eq!(reasons[".GIT/config"], "policy_directory");
    assert_eq!(reasons["Node_Modules/pkg/index.js"], "policy_directory");
    assert_eq!(result["file_count"], 0);
}

#[cfg(windows)]
#[test]
fn windows_names_with_a_trailing_dot_or_space_or_a_short_name_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), ".env", b"value\n");
    write(dir.path(), "node_modules/pkg/index.js", b"value\n");

    let named = [
        ".env.",
        ".env ",
        "node_modules./pkg/index.js",
        "ENV~1",
        "NODE_M~1/pkg/index.js",
    ];
    let result = run(dir.path(), &named);
    let reasons = reasons(&result);
    for path in named {
        assert_eq!(reasons[path], "invalid_path", "{path:?}");
    }
    assert_eq!(result["file_count"], 0);
}

#[test]
fn a_tilde_and_a_digit_mark_a_possible_short_name() {
    for short in ["ENV~1", "NODE_M~1", "PROGRA~12", "a~b~3.txt"] {
        assert!(may_be_short_name(short), "{short}");
    }
    for long in [".env", "notes~", "backup~old", "~", "file.txt~"] {
        assert!(!may_be_short_name(long), "{long}");
    }
}

#[test]
fn files_left_out_after_reading_still_spend_the_byte_budget() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "a.dat", b"\x00\x01\x02\x03bin");
    write(dir.path(), "b.txt", b"12345678");

    let mut limited = request(dir.path(), &["a.dat", "b.txt"]);
    limited.max_total_bytes = 10;
    let result = preview(&limited).unwrap();
    let reasons = reasons(&result);
    assert_eq!(reasons["a.dat"], "not_text");
    assert_eq!(reasons["b.txt"], "byte_budget");
    assert_eq!(result["status"], "empty");
}

#[test]
fn every_occurrence_of_a_secret_is_replaced_and_counted_once() {
    let dir = tempfile::tempdir().unwrap();
    let token = github_token();
    let source = format!("A = {token}\nB = {token}\n");
    write(dir.path(), "app.py", source.as_bytes());

    let result = run(dir.path(), &["app.py"]);
    assert_eq!(result["status"], "ready");
    assert_eq!(result["redactions"], 1);
    let exported = format!("A = {REDACTION_MARKER}\nB = {REDACTION_MARKER}\n");
    assert_eq!(
        result["files"][0]["export_sha256"],
        sha256(exported.as_bytes())
    );
    assert!(!result.to_string().contains(&token));
}

#[test]
fn size_limits_and_binary_content_exclude_files() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "a.txt", b"12345678");
    write(dir.path(), "b.txt", b"12345678");
    write(dir.path(), "big.txt", b"0123456789abcdef");
    write(dir.path(), "blob.dat", b"\x00\x01\x02binary");

    let mut limited = request(dir.path(), &["a.txt", "b.txt", "big.txt"]);
    limited.max_file_bytes = 10;
    limited.max_total_bytes = 10;
    let result = preview(&limited).unwrap();
    let reasons = reasons(&result);
    assert_eq!(result["files"][0]["path"], "a.txt");
    assert_eq!(reasons["b.txt"], "byte_budget");
    assert_eq!(reasons["big.txt"], "oversize");
    assert_eq!(result["limits"]["max_file_bytes"], 10);

    let binary = run(dir.path(), &["blob.dat"]);
    assert_eq!(self::reasons(&binary)["blob.dat"], "not_text");
}

#[test]
fn missing_entries_and_directories_are_reported() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "src/lib.rs", b"pub fn a() {}\n");

    let result = run(
        dir.path(),
        &["missing.txt", "missing/x.txt", "src", "src/lib.rs/x"],
    );
    let reasons = reasons(&result);
    assert_eq!(reasons["missing.txt"], "not_found");
    assert_eq!(reasons["missing/x.txt"], "not_found");
    assert_eq!(reasons["src"], "not_a_file");
    assert_eq!(reasons["src/lib.rs/x"], "not_found");
}

#[cfg(unix)]
#[test]
fn symlinks_are_never_followed() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    write(outside.path(), "secret.txt", b"outside\n");
    std::os::unix::fs::symlink(
        outside.path().join("secret.txt"),
        dir.path().join("leaf.txt"),
    )
    .unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("linked")).unwrap();

    let result = run(dir.path(), &["leaf.txt", "linked/secret.txt"]);
    let reasons = reasons(&result);
    assert_eq!(reasons["leaf.txt"], "symlink");
    assert_eq!(reasons["linked/secret.txt"], "symlink");
    assert_eq!(result["file_count"], 0);
}

#[test]
fn duplicate_paths_are_previewed_once_and_no_paths_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "a.txt", b"a\n");

    let result = run(dir.path(), &["a.txt", "a.txt"]);
    assert_eq!(result["file_count"], 1);
    assert_eq!(result["files"].as_array().unwrap().len(), 1);

    let empty = run(dir.path(), &[]);
    assert_eq!(empty["status"], "empty");
    assert_eq!(empty["file_count"], 0);
}

#[test]
fn request_errors_are_reported_without_a_preview() {
    let dir = tempfile::tempdir().unwrap();
    let many: Vec<String> = (0..=MAX_PATHS).map(|index| format!("f{index}")).collect();
    let mut too_many = request(dir.path(), &[]);
    too_many.paths = many;
    assert_eq!(
        preview(&too_many).unwrap_err(),
        "workspace_export_preview_too_many_paths"
    );

    let mut relative = request(dir.path(), &[]);
    relative.root = "relative/root".to_owned();
    assert_eq!(
        preview(&relative).unwrap_err(),
        "workspace_export_preview_root_not_absolute"
    );

    assert_eq!(
        run_command(br#"{"root": "/", "paths": [], "upload": true}"#).unwrap_err(),
        "workspace_export_preview_request_invalid"
    );
    let missing = serde_json::json!({
        "root": dir.path().join("gone").to_str().unwrap(),
        "paths": [],
    });
    let response = run_command(missing.to_string().as_bytes()).unwrap();
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"], "workspace_export_preview_root_missing");
}

/// The same bytes a base64 writer would produce: whole lines of an equal width,
/// with whatever is left over on the last.
fn base64_lines(plain: &str, column: usize) -> String {
    use base64ct::Encoding as _;

    let encoded = base64ct::Base64::encode_string(plain.as_bytes());
    let mut out = String::new();
    let mut rest = encoded.as_str();
    while !rest.is_empty() {
        let take = rest.len().min(column);
        out.push_str(&rest[..take]);
        out.push('\n');
        rest = &rest[take..];
    }
    out
}

#[test]
fn a_secret_carried_only_by_an_encoding_is_replaced_rather_than_blocking() {
    // The candidate of an encoded finding is the decoded credential, which has
    // no literal occurrence in the file, so replacing only literal occurrences
    // leaves the credential where it was: the second scan finds it again and
    // the whole bundle is blocked over a file that could have been exported.
    let dir = tempfile::tempdir().unwrap();
    let plain = format!("# deploy secrets\nGH_TOKEN={}\n", github_token());
    let source = base64_lines(&plain, 64);
    write(dir.path(), "env.b64", source.as_bytes());

    let result = run(dir.path(), &["env.b64"]);

    assert_eq!(result["status"], "ready", "{result}");
    assert!(reasons(&result).is_empty(), "{result}");
    assert!(result["redactions"].as_u64().unwrap() >= 1, "{result}");
    assert_eq!(
        result["files"][0]["source_sha256"],
        sha256(source.as_bytes())
    );
    assert_ne!(
        result["files"][0]["export_sha256"],
        sha256(source.as_bytes())
    );
}
