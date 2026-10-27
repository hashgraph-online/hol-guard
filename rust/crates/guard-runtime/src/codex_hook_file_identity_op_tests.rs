//! What `verify_regular_file_identity` refused in Python, the resident refuses.
//!
//! Each case below is a file the Python helper would have rejected, named by
//! the same reason code the Python raised, so a manifest that passed before the
//! cutover still passes and one that failed still fails for the same stated
//! reason.

use super::*;
use guard_contracts::CODEX_HOOK_FILE_IDENTITY_REQUEST_SCHEMA;
use serde_json::json;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

/// SHA-256 of `CONTENT`, the digest a manifest would have recorded.
const CONTENT: &[u8] = b"#!/usr/bin/env python3\nprint('hook')\n";
const CONTENT_SHA256: &str = "3a8f42dbd1a2f3f7e9f6a126c5b3f81a1a0a1e952be5828a9375a774306027c5";

struct Fixture {
    _root: tempfile::TempDir,
    path: PathBuf,
}

impl Fixture {
    /// A regular file holding `CONTENT`, at the permissions the caller names.
    fn new(mode: u32) -> Self {
        let root = tempfile::tempdir().expect("a temporary directory");
        let path = root.path().join("hook.py");
        let mut file = fs::File::create(&path).expect("the fixture file");
        file.write_all(CONTENT).expect("the fixture content");
        drop(file);
        set_mode(&path, mode);
        Self { _root: root, path }
    }

    /// The identity a manifest would carry for this file, as written.
    fn identity(&self) -> Value {
        json!({
            "role": "config_target",
            "path": self.path.to_str().expect("a printable fixture path"),
            "sha256": hash_of(&self.path).expect("the fixture hashes"),
            "mode": self.mode(),
            "size": CONTENT.len(),
            "owner_uid": self.uid(),
            "executable_required": false,
        })
    }

    fn mode(&self) -> u32 {
        let metadata = fs::symlink_metadata(&self.path).expect("the fixture metadata");
        file_mode(&self.path, &metadata) & 0o7777
    }

    fn uid(&self) -> u32 {
        let metadata = fs::symlink_metadata(&self.path).expect("the fixture metadata");
        file_uid(&metadata)
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))
        .expect("the fixture permissions");
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

/// The digest of a whole file. The operation hashes an open handle up to the
/// length it read from that same handle; a fixture has neither to hand, so it
/// opens the path and names its length.
fn hash_of(path: &Path) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let size = file.metadata().ok()?.len();
    sha256_file(file, size)
}

fn request(identity: Value, canonical: Option<&str>) -> CodexHookFileIdentityRequestV1 {
    CodexHookFileIdentityRequestV1 {
        schema: CODEX_HOOK_FILE_IDENTITY_REQUEST_SCHEMA.to_owned(),
        request_id: "codex-hook-file-identity-test".to_owned(),
        posix: cfg!(unix),
        current_uid: current_uid(),
        questions: vec![CodexHookFileIdentityQuestionV1 {
            canonical_path: canonical.map(str::to_owned).or_else(|| {
                identity
                    .get("path")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            }),
            identity,
            installed_python_package_file: false,
        }],
    }
}

#[cfg(unix)]
fn current_uid() -> Option<u32> {
    // The owner of a file this process just created is the user the resident
    // would compare a manifest entry against. `getuid` would answer directly,
    // but the crate forbids unsafe code, and the file's owner is the effective
    // user the identity check actually cares about.
    let root = tempfile::tempdir().ok()?;
    let path = root.path().join("owner-probe");
    fs::File::create(&path).ok()?;
    let metadata = fs::symlink_metadata(&path).ok()?;
    Some(file_uid(&metadata))
}

#[cfg(not(unix))]
fn current_uid() -> Option<u32> {
    None
}

/// The one answer a single-question request carries.
fn answer_to(request: &CodexHookFileIdentityRequestV1) -> Value {
    let payload = evaluate_request(request);
    payload["answers"][0].clone()
}

#[test]
fn the_fixture_hashes_to_the_digest_the_tests_name() {
    let fixture = Fixture::new(0o644);

    assert_eq!(
        hash_of(&fixture.path).as_deref(),
        Some(CONTENT_SHA256),
        "the recorded digest no longer describes the fixture content"
    );
}

#[test]
fn an_untouched_file_matches_its_own_identity() {
    let fixture = Fixture::new(0o644);

    let answer = answer_to(&request(fixture.identity(), None));

    assert_eq!(answer["outcome"], json!("verified"));
    assert_eq!(answer["role"], json!("config_target"));
    assert_eq!(answer.get("private_group_question"), None);
}

#[test]
fn an_identity_that_is_not_an_object_is_refused_under_the_fallback_role() {
    let answer = answer_to(&request(json!("not an identity"), Some("/absent")));

    assert_eq!(answer["outcome"], json!("failed"));
    assert_eq!(answer["kind"], json!("identity_invalid"));
    // `verify_regular_file_identity` names the same role for an identity that
    // is not an object as for one that states none.
    assert_eq!(answer["role"], json!("file"));
}

#[test]
fn a_relative_path_is_refused_before_the_file_is_read() {
    let mut identity = Fixture::new(0o644).identity();
    identity["path"] = json!("relative/hook.py");

    let answer = answer_to(&request(identity, Some("relative/hook.py")));

    assert_eq!(answer["kind"], json!("identity_invalid"));
    assert_eq!(answer["role"], json!("config_target"));
}

#[test]
fn a_boolean_mode_is_not_a_mode() {
    let fixture = Fixture::new(0o644);
    let mut identity = fixture.identity();
    identity["mode"] = json!(true);

    assert_eq!(
        answer_to(&request(identity, None))["kind"],
        json!("identity_invalid")
    );
}

#[test]
fn an_identity_without_a_role_is_answered_as_a_file() {
    let fixture = Fixture::new(0o644);
    let mut identity = fixture.identity();
    identity["role"] = json!("");

    let answer = answer_to(&request(identity, None));

    assert_eq!(answer["outcome"], json!("verified"));
    assert_eq!(answer["role"], json!("file"));
}

#[test]
fn a_file_that_is_gone_is_missing() {
    let fixture = Fixture::new(0o644);
    let identity = fixture.identity();
    fs::remove_file(&fixture.path).expect("the fixture is removable");

    assert_eq!(
        answer_to(&request(identity, None))["kind"],
        json!("missing")
    );
}

#[test]
fn a_path_the_caller_spells_differently_is_a_path_mismatch() {
    let fixture = Fixture::new(0o644);

    let answer = answer_to(&request(fixture.identity(), Some("/somewhere/else.py")));

    assert_eq!(answer["kind"], json!("path_mismatch"));
}

#[test]
fn a_caller_that_cannot_canonicalize_the_path_is_a_path_mismatch() {
    let fixture = Fixture::new(0o644);
    let mut request = request(fixture.identity(), None);
    request.questions[0].canonical_path = None;

    assert_eq!(answer_to(&request)["kind"], json!("path_mismatch"));
}

#[test]
fn a_changed_mode_is_a_mode_mismatch() {
    let fixture = Fixture::new(0o644);
    let mut identity = fixture.identity();
    identity["mode"] = json!(0o600);

    let answer = answer_to(&request(identity, None));

    // Off POSIX the mode a manifest records is the read-only attribute, which
    // this fixture does not set, so the recorded 0o600 disagrees there too.
    assert_eq!(answer["kind"], json!("mode_mismatch"));
}

#[test]
fn a_changed_size_is_a_hash_mismatch() {
    let fixture = Fixture::new(0o644);
    let mut identity = fixture.identity();
    identity["size"] = json!(CONTENT.len() + 1);

    assert_eq!(
        answer_to(&request(identity, None))["kind"],
        json!("hash_mismatch")
    );
}

#[test]
fn a_changed_digest_is_a_hash_mismatch() {
    let fixture = Fixture::new(0o644);
    let mut identity = fixture.identity();
    identity["sha256"] = json!("0".repeat(64));

    assert_eq!(
        answer_to(&request(identity, None))["kind"],
        json!("hash_mismatch")
    );
}

#[test]
fn a_negative_size_fails_the_comparison_rather_than_the_shape_check() {
    let fixture = Fixture::new(0o644);
    let mut identity = fixture.identity();
    identity["size"] = json!(-1);

    assert_eq!(
        answer_to(&request(identity, None))["kind"],
        json!("hash_mismatch")
    );
}

#[test]
fn a_directory_standing_where_a_file_belongs_is_not_regular() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let path = root.path().join("hook.py");
    fs::create_dir(&path).expect("the fixture directory");
    let identity = json!({
        "role": "config_target",
        "path": path.to_str().expect("a printable fixture path"),
        "sha256": CONTENT_SHA256,
        "mode": 0o755,
        "size": 0,
    });

    assert_eq!(
        answer_to(&request(identity, None))["kind"],
        json!("not_regular")
    );
}

/// The platform rules are carried in the request, so the Windows reading is
/// reachable from a POSIX host too - which is where CI runs most of the time.
#[test]
fn off_posix_no_owner_or_permission_rule_applies() {
    let fixture = Fixture::new(0o666);
    let mut identity = fixture.identity();
    identity["owner_uid"] = json!(4242);
    let mut request = request(identity, None);
    request.posix = false;
    request.current_uid = None;

    assert_eq!(answer_to(&request)["outcome"], json!("verified"));
}

#[test]
fn off_posix_an_executable_file_needs_no_execute_bit() {
    let fixture = Fixture::new(0o644);
    let mut identity = fixture.identity();
    identity["executable_required"] = json!(true);
    let mut request = request(identity, None);
    request.posix = false;

    assert_eq!(answer_to(&request)["outcome"], json!("verified"));
}

#[test]
fn a_request_naming_another_contract_is_refused() {
    let fixture = Fixture::new(0o644);
    let mut request = request(fixture.identity(), None);
    request.schema = "guard-something-else.v1".to_owned();

    let encoded = evaluate_codex_hook_file_identity_request(&request).expect("a response");
    let response: Value = serde_json::from_slice(&encoded).expect("a JSON response");

    assert_eq!(response["status"], json!("error"));
    assert_eq!(
        response["code"],
        json!("native_codex_hook_file_identity_schema_mismatch")
    );
    assert_eq!(response["payload"], Value::Null);
}

#[test]
fn a_request_above_the_batch_limit_is_refused() {
    let fixture = Fixture::new(0o644);
    let mut request = request(fixture.identity(), None);
    let question = request.questions[0].clone();
    request.questions = vec![question; CODEX_HOOK_FILE_IDENTITY_MAX_QUESTIONS + 1];

    let encoded = evaluate_codex_hook_file_identity_request(&request).expect("a response");
    let response: Value = serde_json::from_slice(&encoded).expect("a JSON response");

    assert_eq!(
        response["code"],
        json!("native_codex_hook_file_identity_too_many_questions")
    );
}

#[test]
fn a_posix_request_that_states_no_uid_is_refused() {
    let fixture = Fixture::new(0o644);
    let mut request = request(fixture.identity(), None);
    request.posix = true;
    request.current_uid = None;

    let encoded = evaluate_codex_hook_file_identity_request(&request).expect("a response");
    let response: Value = serde_json::from_slice(&encoded).expect("a JSON response");

    // Answering it would have skipped the owner check rather than failed it,
    // so a file another user owns could have verified.
    assert_eq!(response["status"], json!("error"));
    assert_eq!(
        response["code"],
        json!("native_codex_hook_file_identity_current_uid_missing")
    );
    assert_eq!(response["payload"], Value::Null);
}

#[test]
fn the_digest_reads_no_further_than_the_length_it_was_given() {
    let fixture = Fixture::new(0o644);
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&fixture.path)
        .expect("the fixture is appendable");
    file.write_all(b"print('appended by another writer')\n")
        .expect("the extra content");
    drop(file);
    let handle = fs::File::open(&fixture.path).expect("the fixture opens");

    let digest = sha256_file(handle, CONTENT.len() as u64).expect("the fixture hashes");

    // A writer extending the file underneath the read cannot lengthen the work
    // the comparison does, and the digest still describes the length that was
    // measured rather than whatever the file has grown to.
    assert_eq!(digest, CONTENT_SHA256);
}

#[test]
fn a_batch_answers_in_the_order_it_was_asked() {
    let present = Fixture::new(0o644);
    let absent = Fixture::new(0o644);
    let absent_identity = absent.identity();
    fs::remove_file(&absent.path).expect("the fixture is removable");
    let mut request = request(present.identity(), None);
    request.questions.push(CodexHookFileIdentityQuestionV1 {
        canonical_path: absent_identity
            .get("path")
            .and_then(Value::as_str)
            .map(str::to_owned),
        identity: absent_identity,
        installed_python_package_file: false,
    });

    let payload = evaluate_request(&request);

    assert_eq!(payload["answers"][0]["outcome"], json!("verified"));
    assert_eq!(payload["answers"][1]["kind"], json!("missing"));
}

#[test]
fn a_response_binds_itself_to_the_request_it_answers() {
    let fixture = Fixture::new(0o644);
    let request = request(fixture.identity(), None);

    let encoded = evaluate_codex_hook_file_identity_request(&request).expect("a response");
    let response: Value = serde_json::from_slice(&encoded).expect("a JSON response");

    assert_eq!(response["status"], json!("ok"));
    assert_eq!(
        response["request_id"],
        json!("codex-hook-file-identity-test")
    );
    assert_eq!(
        response["request_sha256"],
        json!(
            request_digest_with_limit(&request, CODEX_HOOK_FILE_IDENTITY_MAX_BYTES)
                .expect("the request digests")
        )
    );
}

#[test]
fn feature_is_advertised() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&guard_contracts::CODEX_HOOK_FILE_IDENTITY_FEATURE));
}

#[cfg(unix)]
#[path = "codex_hook_file_identity_op_posix_tests.rs"]
mod posix;
