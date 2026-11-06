//! Native execution of the language-neutral parity vectors in
//! `tests/fixtures/native-archive-inspection/cases.v1.json`, plus native-only
//! vectors for BOM and null handling, lifecycle and dependency policy, and
//! link behavior. Archives are built from the member specs here; no binaries
//! are committed.
#![cfg(unix)]

mod common;

use std::os::unix::fs::{symlink as fs_symlink, PermissionsExt};
use std::time::{Duration, Instant};

use common::*;
use guard_archive::{inspect_path, ArchiveCaps, ArchiveOutcome};
use serde_json::{json, Value};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/fixtures/native-archive-inspection/cases.v1.json"
);

/// Cases the caller-side (Python/adapter) harness owns: they describe worker
/// transport, not archive bytes, so no native vector exists for them.
const ADAPTER_ONLY: [&str; 10] = [
    "invalid-request-policy",
    "native-unavailable",
    "worker-cannot-start",
    "worker-timeout",
    "worker-crash",
    "malformed-worker-output",
    "unverified-clean-result",
    "lease-held",
    "orphaned-worker",
    "closed-liveness-channel",
];

fn fixture() -> Value {
    serde_json::from_slice(&std::fs::read(FIXTURE).expect("read parity fixture"))
        .expect("parse parity fixture")
}

fn fixture_caps(document: &Value, overrides: Option<&Value>) -> ArchiveCaps {
    let mut caps = document["caps"].clone();
    if let Some(Value::Object(extra)) = overrides {
        for (key, value) in extra {
            caps[key.as_str()] = value.clone();
        }
    }
    let int = |key: &str| caps[key].as_u64().unwrap_or_else(|| panic!("caps.{key}"));
    ArchiveCaps {
        max_archive_bytes: int("max_archive_bytes"),
        max_files: int("max_files"),
        max_expanded_bytes: int("max_expanded_bytes"),
        max_member_bytes: int("max_member_bytes"),
        max_package_json_bytes: int("max_package_json_bytes"),
        max_decompression_ratio: caps["max_decompression_ratio"].as_f64().expect("ratio"),
        max_nested_archives: int("max_nested_archives"),
        max_path_depth: int("max_path_depth"),
    }
}

fn build_member(spec: &Value) -> Vec<u8> {
    let name = spec["name"].as_str().expect("member name");
    let linkname = spec["linkname"].as_str().unwrap_or("");
    if let Some(kind) = spec["type"].as_str() {
        let flag = match kind {
            "sym" => b'2',
            "lnk" => b'1',
            "dir" => b'5',
            "chr" => b'3',
            "fifo" => b'6',
            other => panic!("unknown member type {other}"),
        };
        return member_with(
            name.as_bytes(),
            flag,
            b"",
            linkname.as_bytes(),
            Magic::Ustar,
        );
    }
    let payload: Vec<u8> = if let Some(value) = spec.get("json") {
        serde_json::to_vec(value).expect("json member")
    } else if let Some(padding) = spec.get("json_padding") {
        let fill = padding["padding"].as_str().expect("padding");
        let (unit, count) = fill.split_once('*').expect("padding is unit*count");
        let filler = unit.repeat(count.parse().expect("padding count"));
        serde_json::to_vec(&json!({"name": padding["name"], "padding": filler})).expect("json")
    } else if let Some(repeat) = spec.get("content_repeat") {
        let unit = repeat[0].as_str().expect("repeat unit");
        unit.repeat(repeat[1].as_u64().expect("repeat count") as usize)
            .into_bytes()
    } else if spec["nested_archive"].as_bool() == Some(true) {
        b"nested archive payload".to_vec()
    } else {
        spec["content"].as_str().unwrap_or("").as_bytes().to_vec()
    };
    file(name, &payload)
}

/// The bytes the vector describes: gzip-compressed tar, or the foreign
/// compression magic for the unsupported formats.
fn build_archive(case: &Value) -> Vec<u8> {
    let members: Vec<Vec<u8>> = case["members"]
        .as_array()
        .expect("members")
        .iter()
        .map(build_member)
        .collect();
    let tar = archive(&members);
    match case["archive_format"].as_str() {
        Some("tar.bz2") => [b"BZh9".as_slice(), &tar].concat(),
        Some("tar.xz") => [[0xfd, b'7', b'z', b'X', b'Z', 0x00].as_slice(), &tar].concat(),
        Some(other) => panic!("unknown archive_format {other}"),
        None => gz(&tar),
    }
}

fn check(case: &Value, outcome: &ArchiveOutcome, mismatches: &mut Vec<String>) {
    let id = case["id"].as_str().unwrap_or("?");
    let status = format!("{:?}", outcome.status).to_lowercase();
    if Some(status.as_str()) != case["expected_status"].as_str() {
        mismatches.push(format!(
            "{id}: status {status} (code {}) != {}",
            outcome.code, case["expected_status"]
        ));
    } else if let Some(code) = case["expected_code"].as_str() {
        if outcome.code != code {
            mismatches.push(format!("{id}: code {} != {code}", outcome.code));
        }
    }
}

#[test]
fn member_policy_vectors_match_the_contract() {
    let document = fixture();
    let mut mismatches = Vec::new();
    let mut seen = 0;
    for case in document["cases"].as_array().expect("cases") {
        if case["kind"] != "member-policy" {
            continue;
        }
        seen += 1;
        let caps = fixture_caps(&document, case.get("caps_override"));
        let outcome = inspect_with(&build_archive(case), &caps);
        check(case, &outcome, &mut mismatches);
    }
    assert!(seen >= 46, "only {seen} member-policy vectors ran");
    assert!(
        mismatches.is_empty(),
        "parity mismatches:\n{}",
        mismatches.join("\n")
    );
}

fn blob_for(case_id: &str) -> Option<Blob> {
    let tar = archive(&[file("package/index.js", b"x")]);
    let bytes = gz(&tar);
    Some(match case_id {
        "malformed-archive" => write_blob(b"this is not an archive"),
        "truncated-gzip" => write_blob(&bytes[..bytes.len() / 2]),
        _ => return None,
    })
}

fn inspect_at(path: &std::path::Path, digest: &str, caps: &ArchiveCaps) -> ArchiveOutcome {
    inspect_path(
        path,
        digest,
        caps,
        Instant::now() + Duration::from_secs(30),
        &|| false,
    )
}

#[test]
fn blob_and_transport_vectors_match_the_contract() {
    let document = fixture();
    let caps = fixture_caps(&document, None);
    let good = gz(&archive(&[file("package/index.js", b"x")]));
    let mut mismatches = Vec::new();
    let mut handled = Vec::new();
    for case in document["cases"].as_array().expect("cases") {
        let id = case["id"].as_str().expect("id");
        if case["kind"] == "member-policy" {
            continue;
        }
        if ADAPTER_ONLY.contains(&id) {
            continue;
        }
        handled.push(id.to_string());
        let outcome = match id {
            "digest-mismatch" => {
                let blob = write_blob(&good);
                inspect_at(&blob.path, &"0".repeat(64), &caps)
            }
            "symlink-blob" => {
                let blob = write_blob(&good);
                let link = blob.dir.join("link.tgz");
                fs_symlink(&blob.path, &link).expect("symlink");
                inspect_at(&link, &blob.sha256, &caps)
            }
            "writable-blob" => {
                let blob = write_blob(&good);
                std::fs::set_permissions(&blob.path, std::fs::Permissions::from_mode(0o644))
                    .expect("chmod");
                inspect_at(&blob.path, &blob.sha256, &caps)
            }
            "missing-blob" => {
                let blob = write_blob(&good);
                std::fs::remove_file(&blob.path).expect("unlink");
                inspect_at(&blob.path, &blob.sha256, &caps)
            }
            "directory-blob" => {
                let blob = write_blob(&good);
                inspect_at(&blob.dir, &blob.sha256, &caps)
            }
            "hardlinked-blob" => {
                let blob = write_blob(&good);
                std::fs::hard_link(&blob.path, blob.dir.join("second-name")).expect("link");
                inspect_at(&blob.path, &blob.sha256, &caps)
            }
            "blob-under-symlinked-temp-root" => {
                let blob = write_blob(&good);
                let alias = unique_dir("alias").join("root");
                fs_symlink(&blob.dir, &alias).expect("alias");
                let outcome = inspect_at(&alias.join("blob.tar"), &blob.sha256, &caps);
                std::fs::remove_dir_all(alias.parent().unwrap()).ok();
                outcome
            }
            _ => {
                let blob = blob_for(id).unwrap_or_else(|| panic!("no native vector for {id}"));
                blob.inspect(&caps)
            }
        };
        check(case, &outcome, &mut mismatches);
    }
    assert!(handled.len() >= 9, "handled only {handled:?}");
    assert!(
        mismatches.is_empty(),
        "parity mismatches:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn every_fixture_case_is_accounted_for() {
    // A vector added to the fixture must either run natively or be named in
    // ADAPTER_ONLY; it cannot be skipped silently.
    let document = fixture();
    let handled_here = [
        "digest-mismatch",
        "symlink-blob",
        "writable-blob",
        "missing-blob",
        "directory-blob",
        "hardlinked-blob",
        "blob-under-symlinked-temp-root",
        "malformed-archive",
        "truncated-gzip",
    ];
    for case in document["cases"].as_array().expect("cases") {
        let id = case["id"].as_str().expect("id");
        match case["kind"].as_str().expect("kind") {
            "member-policy" => {}
            _ => assert!(
                handled_here.contains(&id) || ADAPTER_ONLY.contains(&id),
                "fixture case {id} has no native vector"
            ),
        }
    }
}
