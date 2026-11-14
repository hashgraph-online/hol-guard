use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use super::dispatch;
use super::inspect::sha256_hex;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "transition-files-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        Self(fs::canonicalize(root).unwrap())
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn encoded(bytes: Option<&[u8]>) -> Value {
    bytes.map_or(Value::Null, |bytes| Value::String(STANDARD.encode(bytes)))
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

fn change(path: &Path, before: Option<&[u8]>, after: Option<&[u8]>, no_follow: bool) -> Value {
    json!({
        "kind": "binding",
        "path": path.to_string_lossy(),
        "before": encoded(before),
        "after": encoded(after),
        "before_mode": 0o600,
        "after_mode": 0o600,
        "no_follow": no_follow,
    })
}

fn ask(request: &Value) -> Value {
    dispatch(request).unwrap()
}

#[test]
fn compare_accepts_the_named_generation_and_refuses_another() {
    let fixture = Fixture::new();
    let target = fixture.path("config.toml");
    fs::write(&target, b"old").unwrap();
    set_mode(&target, 0o600);
    let files = json!([change(&target, Some(b"old"), Some(b"new"), false)]);
    let matched = ask(&json!({"op": "compare", "files": files, "generation": "before"}));
    assert_eq!(matched["ok"], true);
    let mismatched = ask(&json!({"op": "compare", "files": files, "generation": "after"}));
    assert_eq!(
        mismatched["error"],
        json!({"transition": "generation_changed"})
    );
    let inverse = ask(&json!({
        "op": "compare", "files": files, "generation": "after", "inverse": true,
    }));
    assert_eq!(inverse["ok"], true);
}

#[cfg(unix)]
#[test]
fn compare_refuses_a_linked_target() {
    let fixture = Fixture::new();
    let real = fixture.path("real.toml");
    fs::write(&real, b"old").unwrap();
    let link = fixture.path("config.toml");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let files = json!([change(&link, Some(b"old"), Some(b"new"), false)]);
    let answer = ask(&json!({"op": "compare", "files": files, "generation": "before"}));
    assert_eq!(
        answer["error"],
        json!({"transition": "file_target_changed"})
    );
}

#[test]
fn publish_writes_every_file_and_reports_each_in_order() {
    let fixture = Fixture::new();
    let first = fixture.path("one.json");
    let second = fixture.path("nested").join("two.json");
    fs::write(&first, b"a").unwrap();
    set_mode(&first, 0o600);
    let files = json!([
        change(&first, Some(b"a"), Some(b"b"), false),
        change(&second, None, Some(b"c"), true),
    ]);
    let answer = ask(&json!({"op": "publish", "files": files, "rollback": true}));
    assert_eq!(answer["ok"], true, "{answer}");
    assert_eq!(fs::read(&first).unwrap(), b"b");
    assert_eq!(fs::read(&second).unwrap(), b"c");
    let events = answer["events"].as_array().unwrap();
    assert_eq!(events.len(), 3);
    let mutation = &events[0]["mutation"];
    assert_eq!(mutation["operation"], "publish");
    assert_eq!(mutation["before_digest"], sha256_hex(b"a"));
    assert_eq!(mutation["after_digest"], sha256_hex(b"b"));
    assert_eq!(events[1], json!({"written": 0}));
    assert_eq!(events[2], json!({"written": 1}));
}

#[test]
fn publish_restores_what_it_wrote_when_a_later_file_changed() {
    let fixture = Fixture::new();
    let first = fixture.path("one.json");
    let second = fixture.path("two.json");
    fs::write(&first, b"a").unwrap();
    fs::write(&second, b"changed").unwrap();
    set_mode(&first, 0o600);
    set_mode(&second, 0o600);
    let files = json!([
        change(&first, Some(b"a"), Some(b"b"), false),
        change(&second, Some(b"x"), Some(b"y"), false),
    ]);
    let answer = ask(&json!({"op": "publish", "files": files, "rollback": true}));
    // The opening compare sees the second file changed before anything is written.
    assert_eq!(answer["error"], json!({"transition": "generation_changed"}));
    assert_eq!(fs::read(&first).unwrap(), b"a");
}

#[test]
fn publish_refuses_a_plan_that_removes_without_permission() {
    let fixture = Fixture::new();
    let target = fixture.path("one.json");
    fs::write(&target, b"a").unwrap();
    let files = json!([change(&target, Some(b"a"), None, false)]);
    let refused = ask(&json!({"op": "publish", "files": files}));
    assert_eq!(
        refused["error"],
        json!({"transition": "adapter_install_plan_invalid"})
    );
    assert_eq!(fs::read(&target).unwrap(), b"a");
}

#[test]
fn private_key_mutations_carry_no_digest() {
    let fixture = Fixture::new();
    let key = fixture.path("hook-manifest.key");
    let request = json!({
        "op": "write",
        "generation": "after",
        "change": change(&key, None, Some(b"secret-bytes"), false),
    });
    let answer = ask(&request);
    assert_eq!(answer["ok"], true, "{answer}");
    let mutation = &answer["events"][0]["mutation"];
    assert_eq!(mutation["after_present"], true);
    assert_eq!(mutation["after_digest"], Value::Null);
    assert_eq!(mutation["before_digest"], Value::Null);
}

#[test]
fn write_removes_through_the_managed_route() {
    let fixture = Fixture::new();
    let target = fixture.path("hooks.json");
    fs::write(&target, b"a").unwrap();
    let request = json!({
        "op": "write",
        "generation": "after",
        "change": change(&target, Some(b"a"), None, false),
    });
    let answer = ask(&request);
    assert_eq!(
        answer["events"][0]["mutation"]["operation"],
        "restore_absent"
    );
    assert!(!target.exists());
}

#[cfg(unix)]
#[test]
fn no_follow_write_refuses_a_linked_directory() {
    let fixture = Fixture::new();
    let real = fixture.path("real");
    fs::create_dir(&real).unwrap();
    let linked = fixture.path("linked");
    std::os::unix::fs::symlink(&real, &linked).unwrap();
    let error = super::output::write_no_follow(&linked.join("x.json"), b"x", 0o600).unwrap_err();
    assert!(
        error.to_string().contains("symlinked output directory"),
        "{error}"
    );
    assert!(!real.join("x.json").exists());
}

#[test]
fn digest_dependency_is_compared_and_shape_checked() {
    let fixture = Fixture::new();
    let target = fixture.path("authority.json");
    fs::write(&target, b"pinned").unwrap();
    set_mode(&target, 0o600);
    let mut dependency = change(&target, None, None, true);
    dependency["expected_digest"] = json!(sha256_hex(b"pinned"));
    let matched = ask(&json!({"op": "compare", "files": [dependency], "generation": "before"}));
    assert_eq!(matched["ok"], true, "{matched}");
    dependency["expected_digest"] = json!(sha256_hex(b"other"));
    let changed = ask(&json!({"op": "compare", "files": [dependency], "generation": "before"}));
    assert_eq!(
        changed["error"],
        json!({"transition": "generation_changed"})
    );
    dependency["expected_digest"] = json!("not-a-digest");
    let invalid = ask(&json!({"op": "compare", "files": [dependency], "generation": "before"}));
    assert_eq!(
        invalid["error"],
        json!({"transition": "authority_dependency_invalid"})
    );
}

#[test]
fn malformed_requests_are_rejected() {
    assert!(dispatch(&json!({"op": "compare", "generation": "before"})).is_err());
    assert!(dispatch(&json!({"op": "compare", "files": [], "generation": "middle"})).is_err());
    assert!(dispatch(&json!({"op": "unknown"})).is_err());
    assert!(
        dispatch(&json!({"op": "compare", "files": [], "generation": "before", "budget": 5}))
            .is_err()
    );
}

#[test]
fn an_expired_budget_stops_the_compare() {
    let fixture = Fixture::new();
    let target = fixture.path("config.toml");
    fs::write(&target, b"old").unwrap();
    let files = json!([change(&target, Some(b"old"), None, false)]);
    let answer = ask(&json!({
        "op": "compare", "files": files, "generation": "before",
        "budget": {"inverse_ms": 0},
    }));
    assert_eq!(answer["error"], json!({"transition": "deadline_exceeded"}));
}
