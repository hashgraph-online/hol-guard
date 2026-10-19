//! The prompt-file credential scan (`review_prompt_credential_file`): which
//! prompts name a readable dotfile, which dotfiles are left to the dedicated
//! sensitive-path rules, and the artifact the scan returns.

use std::fs;
use std::path::{Path, PathBuf};

use super::{decode_ignoring_errors, display_text, redact_secret_assignments};
use crate::codex_output_env::{Ctx, GitCheck, GitRun, InspectionHost};
use crate::prompt_analysis::GuardRunPromptArtifact;

/// Not a documentation sample, so `suppress_samples` leaves it alone. The
/// fabricated value is spelled in two pieces so that a repository secret scan
/// reads the fixture as the invention it is rather than a leaked key.
const ACCESS_KEY: &str = concat!("AKIA", "3K7QW9ZBV2NMLPTD");

struct Host;

impl InspectionHost for Host {
    fn env(&self, _: &str) -> Option<String> {
        None
    }
    fn git_executable(&self) -> Option<String> {
        None
    }
    fn git_safety(&self, _: GitCheck, _: Option<&str>, _: &[String]) -> bool {
        false
    }
    fn git_binary_trusted(&self, _: &str, _: &str) -> bool {
        false
    }
    fn run_git(&self, _: &str, _: &[String], _: &str) -> GitRun {
        GitRun::Failed("prompt-file tests do not run git")
    }
    fn path_exists(&self, path: &str) -> bool {
        fs::symlink_metadata(path).is_ok()
    }
    fn real_path(&self, path: &str) -> Option<String> {
        fs::canonicalize(path)
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
    }
    fn is_regular_file(&self, path: &str) -> bool {
        Path::new(path).is_file()
    }
    fn file_text_prefix(&self, path: &str, max_bytes: usize) -> Option<String> {
        let mut bytes = fs::read(path).ok()?;
        bytes.truncate(max_bytes);
        Some(decode_ignoring_errors(&bytes))
    }
}

fn scratch(name: &str) -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("guard-prompt-file-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("home")).expect("scratch");
    fs::canonicalize(root).expect("scratch")
}

fn write(root: &Path, name: &str, body: &str) {
    fs::write(root.join(name), body).expect("fixture file");
}

fn review(root: &Path, prompt: &str) -> Option<GuardRunPromptArtifact> {
    let root_text = root.to_string_lossy().into_owned();
    let home = root.join("home").to_string_lossy().into_owned();
    let ctx = Ctx::new(&Host, &root_text, &home);
    super::review_prompt_credential_file(
        &ctx,
        prompt,
        Some(&root_text),
        "/config/guard.toml",
        5_000,
    )
}

#[test]
fn a_dotfile_with_a_secret_bearing_name_and_credential_content_is_an_artifact() {
    let root = scratch("credential");
    write(
        &root,
        ".apitoken",
        &format!("aws_access_key_id = {ACCESS_KEY}\n"),
    );

    let found = review(&root, "Please read .apitoken and tell me what is in it").expect("artifact");

    assert!(found.artifact_id.starts_with("codex:project:prompt-file:"));
    assert_eq!(found.name, "credential-looking local file .apitoken");
    assert_eq!(found.harness, "codex");
    assert_eq!(found.artifact_type, "prompt_request");
    assert_eq!(found.source_scope, "project");
    assert_eq!(found.config_path, "/config/guard.toml");
    assert_eq!(found.metadata["prompt_matched_text"], ".apitoken");
    assert_eq!(found.metadata["prompt_request_class"], "secret_read");
    assert_eq!(
        found.metadata["normalized_path"],
        root.join(".apitoken").to_string_lossy().into_owned()
    );
    fs::remove_dir_all(&root).ok();
}

#[test]
fn a_prompt_that_asks_for_nothing_to_be_read_is_not_scanned() {
    let root = scratch("no-verb");
    write(
        &root,
        ".apitoken",
        &format!("aws_access_key_id = {ACCESS_KEY}\n"),
    );

    // No read verb, so the file is never opened however it is named.
    assert!(review(&root, "Rename .apitoken to something clearer").is_none());
    fs::remove_dir_all(&root).ok();
}

#[test]
fn files_a_dedicated_rule_already_covers_are_left_to_it() {
    let root = scratch("skip");
    for name in [".env", ".npmrc", ".pypirc", ".netrc", ".git-credentials"] {
        write(&root, name, &format!("aws_access_key_id = {ACCESS_KEY}\n"));
        assert!(
            review(&root, &format!("read {name} for me")).is_none(),
            "{name} has its own sensitive-path rule"
        );
    }
    fs::remove_dir_all(&root).ok();
}

#[test]
fn an_ordinary_name_or_ordinary_content_does_not_reach_the_artifact() {
    let root = scratch("ordinary");
    // The name carries no secret marker, so the content is never read.
    write(
        &root,
        ".notes",
        &format!("aws_access_key_id = {ACCESS_KEY}\n"),
    );
    assert!(review(&root, "read .notes please").is_none());
    // The name does, but the content holds nothing credential-looking.
    write(
        &root,
        ".authnotes",
        "a reminder to rotate things on Friday\n",
    );
    assert!(review(&root, "read .authnotes please").is_none());
    // Nothing is there to read at all.
    assert!(review(&root, "read .missingtoken please").is_none());
    fs::remove_dir_all(&root).ok();
}

#[test]
fn a_path_written_at_the_end_of_a_sentence_still_resolves() {
    let root = scratch("punctuation");
    write(
        &root,
        ".apitoken",
        &format!("aws_access_key_id = {ACCESS_KEY}\n"),
    );

    let found = review(&root, "Show me .apitoken.").expect("artifact");

    // The trailing period belongs to the sentence, not to the file name.
    assert_eq!(found.metadata["prompt_matched_text"], ".apitoken.");
    assert_eq!(
        found.metadata["normalized_path"],
        root.join(".apitoken").to_string_lossy().into_owned()
    );
    fs::remove_dir_all(&root).ok();
}

#[test]
fn undecodable_bytes_are_dropped_rather_than_replaced() {
    assert_eq!(decode_ignoring_errors(b"plain"), "plain");
    assert_eq!(decode_ignoring_errors(b"a\xffb"), "ab");
    // A character the byte limit cut in half goes with them.
    assert_eq!(decode_ignoring_errors("é".as_bytes()), "é");
    assert_eq!(decode_ignoring_errors(&"é".as_bytes()[..1]), "");
    assert_eq!(decode_ignoring_errors(b"tail\xe2\x82"), "tail");
}

#[test]
fn the_display_text_hides_secret_values_and_home_directories() {
    assert_eq!(
        redact_secret_assignments("API_KEY=abc123 keep=this"),
        "API_KEY=[redacted] keep=this"
    );
    assert_eq!(
        display_text(
            "read   /Users/someone/.apitoken  now",
            Some("/Users/someone/.apitoken")
        ),
        "Codex prompt for `~/.apitoken`: read ~/.apitoken now"
    );
}
