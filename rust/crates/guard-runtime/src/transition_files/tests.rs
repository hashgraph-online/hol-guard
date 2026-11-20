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
    // An inverse compare also accepts the file already at its "after" bytes.
    fs::write(&target, b"new").unwrap();
    let inverse = ask(&json!({
        "op": "compare", "files": files, "generation": "before", "inverse": true,
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

fn journal_request(home: &Path, dropped: u64, path: &Path) -> Value {
    json!({
        "op": "journal",
        "guard_home": home.to_string_lossy(),
        "owner": {
            "operation_id": "op", "config_target_id": "cfg", "actor": "install",
            "pid": 7, "process_identity": "proc", "dropped_events": dropped,
        },
        "mutations": [{
            "operation": "write", "path": path.to_string_lossy(),
            "before_present": false, "after_present": true,
            "before_digest": "aa", "after_digest": "bb",
        }],
    })
}

#[test]
fn journal_appends_rotates_and_withholds_key_digests() {
    let fixture = Fixture::new();
    let codex = fixture.path("managed/codex");
    fs::create_dir_all(&codex).unwrap();
    let journal = codex.join("authority-mutations.jsonl");
    let answer = dispatch(&journal_request(&fixture.0, 2, &fixture.path("hooks.json"))).unwrap();
    assert_eq!(answer, json!({ "ok": true, "dropped_events": 2 }));
    let line: Value = serde_json::from_str(fs::read_to_string(&journal).unwrap().trim()).unwrap();
    assert_eq!(line["schema"], "hol-guard.codex-authority-mutation.v1");
    assert_eq!(line["dropped_events"], 2);
    assert_eq!(line["before_digest"], Value::Null);
    assert_eq!(line["after_digest"], "bb");
    let target = fixture.path("hooks.json");
    assert_eq!(
        line["target_id"],
        sha256_hex(target.to_string_lossy().as_bytes())
    );
    let key = fixture.path("hook-manifest.key");
    dispatch(&journal_request(&fixture.0, 0, &key)).unwrap();
    let last = fs::read_to_string(&journal).unwrap();
    let last: Value = serde_json::from_str(last.lines().last().unwrap()).unwrap();
    assert_eq!(last["after_digest"], Value::Null);
    fs::write(&journal, vec![b'x'; 1024 * 1024]).unwrap();
    dispatch(&journal_request(&fixture.0, 0, &target)).unwrap();
    assert_eq!(
        fs::read(codex.join("authority-mutations.jsonl.1"))
            .unwrap()
            .len(),
        1024 * 1024
    );
    assert_eq!(fs::read_to_string(&journal).unwrap().lines().count(), 1);
}

#[cfg(unix)]
#[test]
fn journal_counts_an_unsafe_file_as_dropped() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let codex = fixture.path("managed/codex");
    fs::create_dir_all(&codex).unwrap();
    let journal = codex.join("authority-mutations.jsonl");
    fs::write(&journal, b"").unwrap();
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o644)).unwrap();
    let answer = dispatch(&journal_request(&fixture.0, 1, &fixture.path("a"))).unwrap();
    assert_eq!(answer["dropped_events"], 2);
    assert!(fs::read(&journal).unwrap().is_empty());
}

#[test]
fn install_lease_excludes_a_second_owner_until_released() {
    let fixture = Fixture::new();
    let acquire = json!({
        "op": "lease_acquire", "lock": "install",
        "guard_home": fixture.0.to_string_lossy(), "client_pid": std::process::id(),
    });
    let first = dispatch(&acquire).unwrap();
    let lease = first["lease"].as_str().unwrap().to_owned();
    assert_eq!(
        dispatch(&acquire).unwrap(),
        json!({ "ok": false, "busy": true })
    );
    let check = json!({ "op": "lease_check", "lease": lease });
    assert_eq!(dispatch(&check).unwrap()["held"], true);
    let release = json!({ "op": "lease_release", "lease": lease });
    assert_eq!(dispatch(&release).unwrap()["released"], true);
    assert_eq!(dispatch(&check).unwrap()["held"], false);
    let again = dispatch(&acquire).unwrap();
    assert_eq!(again["ok"], true);
    dispatch(&json!({ "op": "lease_release", "lease": again["lease"] })).unwrap();
    assert!(fixture.path("managed/codex/installation.lock").is_file());
}

#[test]
fn a_resident_stop_waits_out_an_install_lease_and_then_excludes_new_ones() {
    let fixture = Fixture::new();
    let acquire = json!({
        "op": "lease_acquire", "lock": "install",
        "guard_home": fixture.0.to_string_lossy(), "client_pid": std::process::id(),
    });
    let lease = dispatch(&acquire).unwrap()["lease"]
        .as_str()
        .unwrap()
        .to_owned();
    let wait = std::time::Duration::from_millis(50);
    assert_eq!(
        super::hold_install_lock(&fixture.0, wait).unwrap_err(),
        "native_resident_install_in_progress"
    );
    dispatch(&json!({ "op": "lease_release", "lease": lease })).unwrap();
    let held = super::hold_install_lock(&fixture.0, wait).unwrap();
    assert_eq!(
        dispatch(&acquire).unwrap(),
        json!({ "ok": false, "busy": true })
    );
    drop(held);
    let again = dispatch(&acquire).unwrap();
    assert_eq!(again["ok"], true);
    dispatch(&json!({ "op": "lease_release", "lease": again["lease"] })).unwrap();
}

#[cfg(unix)]
#[test]
fn install_lease_refuses_a_shared_lock_file() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let codex = fixture.path("managed/codex");
    fs::create_dir_all(&codex).unwrap();
    let lock = codex.join("installation.lock");
    fs::write(&lock, b"").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
    let answer = dispatch(&json!({
        "op": "lease_acquire", "lock": "install",
        "guard_home": fixture.0.to_string_lossy(), "client_pid": std::process::id(),
    }))
    .unwrap();
    assert_eq!(
        answer,
        json!({ "ok": false, "error": "codex_hook_transaction_lock_unsafe" })
    );
}
