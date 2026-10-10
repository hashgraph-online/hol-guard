//! Parity vectors recorded from the legacy Python implementation plus the
//! request-binding and admission contract of the operation.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use guard_contracts::{
    SkillDirectoryCommandV1, SkillDirectoryIdentityRequestV1, SkillDirectoryLimitsV1,
    SKILL_DIRECTORY_IDENTITY_REQUEST_SCHEMA,
};
use serde_json::{json, Value};

use super::evaluate_skill_directory_identity_request;
use crate::skill_identity_canon::incomplete_state_hash_for_label;

const VECTORS: &str = include_str!("../tests/fixtures/skill_directory_identity_vectors.json");

struct TempBase(PathBuf);

impl TempBase {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "hol-guard-skill-identity-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
}

impl Drop for TempBase {
    fn drop(&mut self) {
        // Restore searchable modes so a failing test still cleans up.
        fn open_up(path: &Path) {
            let Ok(metadata) = fs::symlink_metadata(path) else {
                return;
            };
            if metadata.is_dir() {
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
                if let Ok(children) = fs::read_dir(path) {
                    for child in children.flatten() {
                        open_up(&child.path());
                    }
                }
            }
        }
        open_up(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn mode_of(entry: &Value) -> u32 {
    u32::from_str_radix(entry["mode"].as_str().unwrap_or("0644"), 8).unwrap()
}

fn build(base: &Path, spec: &Value) {
    let mut directory_modes: Vec<(PathBuf, u32)> = Vec::new();
    for entry in spec["entries"].as_array().unwrap() {
        let path = base.join(entry["path"].as_str().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        match entry["type"].as_str().unwrap() {
            "dir" => {
                fs::create_dir_all(&path).unwrap();
                directory_modes.push((path, mode_of(entry)));
            }
            "file" => {
                let data = match entry.get("content_hex") {
                    Some(hex_text) => hex::decode(hex_text.as_str().unwrap()).unwrap(),
                    None => entry["content"].as_str().unwrap().as_bytes().to_vec(),
                };
                fs::write(&path, data).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(mode_of(entry))).unwrap();
            }
            "symlink" => {
                let target = &entry["target"];
                let target = match target.get("base_relative") {
                    Some(relative) => base.join(relative.as_str().unwrap()),
                    None => PathBuf::from(target.as_str().unwrap()),
                };
                symlink(target, &path).unwrap();
            }
            "fifo" => {
                assert!(std::process::Command::new("mkfifo")
                    .arg(&path)
                    .status()
                    .unwrap()
                    .success());
            }
            other => panic!("unknown fixture entry {other}"),
        }
    }
    directory_modes.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    for (path, mode) in directory_modes {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    }
}

fn limits_of(spec: &Value) -> SkillDirectoryLimitsV1 {
    let get = |key: &str, default: u64| spec["limits"][key].as_u64().unwrap_or(default);
    SkillDirectoryLimitsV1 {
        max_depth: get("max_depth", 32),
        max_entries: get("max_entries", 4096),
        max_file_bytes: get("max_file_bytes", 128 * 1024 * 1024),
        max_total_bytes: get("max_total_bytes", 256 * 1024 * 1024),
    }
}

fn request(base: &Path, command: SkillDirectoryCommandV1) -> SkillDirectoryIdentityRequestV1 {
    SkillDirectoryIdentityRequestV1 {
        schema: SKILL_DIRECTORY_IDENTITY_REQUEST_SCHEMA.to_owned(),
        request_id: "skill-identity-test".to_owned(),
        guard_home: base.join("home").to_string_lossy().into_owned(),
        command,
    }
}

fn run(request: &SkillDirectoryIdentityRequestV1) -> Value {
    serde_json::from_slice(&evaluate_skill_directory_identity_request(request).unwrap()).unwrap()
}

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

#[test]
fn inspect_matches_legacy_python_vectors() {
    for spec in vectors()["inspect"].as_array().unwrap() {
        let name = spec["name"].as_str().unwrap();
        let base = TempBase::new(name);
        build(&base.0, spec);
        let scope = base.0.join(spec["scope"].as_str().unwrap_or(""));
        let command = SkillDirectoryCommandV1::Inspect {
            skill_document: base
                .0
                .join(spec["document"].as_str().unwrap())
                .to_string_lossy()
                .into_owned(),
            scope_root: scope.to_string_lossy().into_owned(),
            limits: limits_of(spec),
        };
        let reply = run(&request(&base.0, command));
        assert_eq!(reply["status"], "ok", "{name}");
        let payload = &reply["payload"];
        let expected = &spec["expected"];
        for (wire, legacy) in [
            ("status", "status"),
            ("directory_hash", "directory_hash"),
            ("primary_content_hash", "primary_content_hash"),
            ("entry_count", "entry_count"),
            ("total_bytes", "total_bytes"),
            ("failure_reason", "failure_reason"),
            ("incomplete_state_hash", "incomplete_state_hash"),
        ] {
            let mut want = &expected[legacy];
            // A symlink's own lstat mode is part of the hashed record and is
            // platform dependent (0755 on macOS, 0777 on Linux), so the
            // fixture carries Linux-specific hashes where they differ.
            if cfg!(target_os = "linux") {
                if let Some(over) = spec["expected_linux"].get(legacy) {
                    want = over;
                }
            }
            assert_eq!(&payload[wire], want, "{name}: {wire}");
        }
        assert_eq!(
            payload["schema_version"],
            "guard.skill-directory-identity.v1"
        );
    }
}

#[test]
fn discovery_matches_legacy_python_vectors() {
    for spec in vectors()["discover"].as_array().unwrap() {
        let name = spec["name"].as_str().unwrap();
        let base = TempBase::new(&format!("discover-{name}"));
        build(&base.0, spec);
        let root = base.0.join(spec["root"].as_str().unwrap());
        let command = SkillDirectoryCommandV1::Discover {
            skill_root: root.to_string_lossy().into_owned(),
            limits: limits_of(spec),
        };
        let reply = run(&request(&base.0, command));
        assert_eq!(reply["status"], "ok", "{name}");
        let decode = |value: &Value| {
            String::from_utf8(hex::decode(value.as_str().unwrap()).unwrap()).unwrap()
        };
        let documents: Vec<String> = reply["payload"]["documents_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(decode)
            .collect();
        let expected = &spec["expected"];
        assert_eq!(json!(documents), expected["documents"], "{name}: documents");
        let issues: Vec<Value> = reply["payload"]["issues"]
            .as_array()
            .unwrap()
            .iter()
            .map(|issue| {
                json!({
                    "relative_path": decode(&issue["relative_path_hex"]),
                    "failure_reason": issue["failure_reason"],
                    "issue_id": issue["issue_id"],
                })
            })
            .collect();
        assert_eq!(json!(issues), expected["issues"], "{name}: issues");
        for issue in reply["payload"]["issues"].as_array().unwrap() {
            let identity = &issue["identity"];
            assert_eq!(identity["status"], "incomplete", "{name}");
            assert_eq!(
                identity["failure_reason"], issue["failure_reason"],
                "{name}"
            );
        }
    }
}

#[test]
fn incomplete_state_hashes_match_legacy_table() {
    let vectors = vectors();
    let table = vectors["incomplete"].as_object().unwrap();
    assert_eq!(table.len(), 20);
    for (reason, expected) in table {
        assert_eq!(
            &json!(incomplete_state_hash_for_label(reason, None, 0, 0)),
            expected,
            "{reason}"
        );
    }
}

#[test]
fn transport_unavailable_constants_are_pinned() {
    // The Python transport reports these constants when no runtime answers;
    // they are the native material for its own reason label.
    assert_eq!(
        incomplete_state_hash_for_label("native_unavailable", None, 0, 0),
        "sha256:996f4946b4e5880a4f6760d4ea1ad25d81dfe288ed8a51394ce8cb30c980a49c"
    );
    assert_eq!(
        crate::skill_identity_discovery::issue_id_for_label(b".", "native_unavailable"),
        "a032a4986b3448cf"
    );
}

#[test]
fn reply_is_bound_to_the_canonical_request() {
    let base = TempBase::new("binding");
    let command = SkillDirectoryCommandV1::Discover {
        skill_root: base.0.join("skills").to_string_lossy().into_owned(),
        limits: limits_of(&json!({})),
    };
    let first = request(&base.0, command.clone());
    let mut second = first.clone();
    second.request_id = "another".to_owned();
    let (one, two) = (run(&first), run(&second));
    assert_eq!(one["request_id"], "skill-identity-test");
    assert_ne!(one["request_sha256"], two["request_sha256"]);
    let material = serde_json::to_value(&first).unwrap();
    let mut bytes = Vec::new();
    guard_contracts::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX, "x")
        .unwrap();
    assert_eq!(
        one["request_sha256"],
        json!(format!(
            "sha256:{}",
            guard_policy_snapshot::digest_bytes(&bytes)
        ))
    );
}

#[test]
fn admission_is_strict() {
    let base = TempBase::new("admission");
    let limits = limits_of(&json!({}));
    for (document, scope, home) in [
        ("relative/SKILL.md", "/tmp", "/tmp/home"),
        ("/tmp/x/SKILL.md", "relative", "/tmp/home"),
        ("/tmp/x/SKILL.md", "/tmp", "relative-home"),
        ("", "/tmp", "/tmp/home"),
    ] {
        let mut candidate = request(
            &base.0,
            SkillDirectoryCommandV1::Inspect {
                skill_document: document.to_owned(),
                scope_root: scope.to_owned(),
                limits,
            },
        );
        candidate.guard_home = home.to_owned();
        let reply = run(&candidate);
        assert_eq!(reply["status"], "error", "{document} {scope} {home}");
        assert_eq!(
            reply["code"],
            "native_skill_directory_identity_path_invalid"
        );
        assert!(reply.get("payload").is_none());
    }
    let mut wrong_schema = request(
        &base.0,
        SkillDirectoryCommandV1::Discover {
            skill_root: "/tmp".to_owned(),
            limits,
        },
    );
    wrong_schema.schema = "guard-skill-directory-identity-request.v0".to_owned();
    assert_eq!(
        evaluate_skill_directory_identity_request(&wrong_schema).unwrap_err(),
        "native_skill_directory_identity_schema_mismatch"
    );
}

#[test]
fn wire_decoding_rejects_unknown_fields_and_reasons() {
    let good = json!({
        "schema": SKILL_DIRECTORY_IDENTITY_REQUEST_SCHEMA,
        "request_id": "r",
        "guard_home": "/tmp/home",
        "command": {"kind": "discover", "skill_root": "/tmp/s", "limits": {
            "max_depth": 1, "max_entries": 1, "max_file_bytes": 1, "max_total_bytes": 1}},
    });
    assert!(serde_json::from_value::<SkillDirectoryIdentityRequestV1>(good.clone()).is_ok());
    let mut extra = good.clone();
    extra["command"]["extra"] = json!(true);
    assert!(serde_json::from_value::<SkillDirectoryIdentityRequestV1>(extra).is_err());
    let mut negative = good.clone();
    negative["command"]["limits"]["max_depth"] = json!(-1);
    assert!(serde_json::from_value::<SkillDirectoryIdentityRequestV1>(negative).is_err());
    let mut unknown_kind = good;
    unknown_kind["command"]["kind"] = json!("rewrite");
    assert!(serde_json::from_value::<SkillDirectoryIdentityRequestV1>(unknown_kind).is_err());
}

#[test]
fn unreadable_directory_is_incomplete() {
    // A privileged runner reads through mode 000, so the case cannot fail there.
    if running_as_root() {
        return;
    }
    let base = TempBase::new("unreadable");
    let spec = json!({"entries": [
        {"path": "skills/example/SKILL.md", "type": "file", "content": "x\n", "mode": "0644"},
        {"path": "skills/example/locked/inner.txt", "type": "file", "content": "y\n", "mode": "0644"},
        {"path": "skills/example/locked", "type": "dir", "mode": "0000"},
    ]});
    build(&base.0, &spec);
    let command = SkillDirectoryCommandV1::Inspect {
        skill_document: base
            .0
            .join("skills/example/SKILL.md")
            .to_string_lossy()
            .into_owned(),
        scope_root: base.0.to_string_lossy().into_owned(),
        limits: limits_of(&json!({})),
    };
    let reply = run(&request(&base.0, command));
    assert_eq!(reply["payload"]["status"], "incomplete");
    assert_eq!(reply["payload"]["failure_reason"], "unreadable_entry");
}

fn running_as_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|output| output.stdout.starts_with(b"0"))
        .unwrap_or(false)
}

#[test]
fn caller_limits_are_clamped_to_server_ceilings() {
    let huge = SkillDirectoryLimitsV1 {
        max_depth: u64::MAX,
        max_entries: u64::MAX,
        max_file_bytes: u64::MAX,
        max_total_bytes: u64::MAX,
    };
    let clamped = super::clamp_limits(&huge);
    assert_eq!(clamped, super::MAX_LIMITS);
    let lower = SkillDirectoryLimitsV1 {
        max_depth: 3,
        max_entries: 7,
        max_file_bytes: 11,
        max_total_bytes: 13,
    };
    assert_eq!(super::clamp_limits(&lower), lower);
}
