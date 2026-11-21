//! The installation transaction: ownership, the journal it keeps, and the
//! refusals a mutation gets before it may start.

use std::fs;
use std::path::Path;

use serde_json::{json, Value};
use tempfile::TempDir;

use super::dispatch;
use super::inspect::{resolve_lenient, sha256_hex};

const THREAD: u64 = 11;

fn ask(request: &Value) -> Value {
    dispatch(request).unwrap()
}

fn begin_request(home: &Path, target: &Path, extra: Value) -> Value {
    let mut request = json!({
        "op": "owned_begin",
        "guard_home": home.to_string_lossy(),
        "target": target.to_string_lossy(),
        "actor": "test-actor",
        "process_identity": "test-process",
        "client_pid": std::process::id(),
        "thread": THREAD,
        "deadline_ms": 2000,
        "check_pending": true,
        "dirs": [],
    });
    for (key, value) in extra.as_object().unwrap() {
        request[key] = value.clone();
    }
    request
}

fn lines(home: &Path) -> Vec<Value> {
    let journal = home.join("managed/codex/authority-mutations.jsonl");
    fs::read_to_string(journal)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn operations(home: &Path) -> Vec<String> {
    lines(home)
        .iter()
        .map(|line| line["operation"].as_str().unwrap().to_owned())
        .collect()
}

fn install_lease(home: &Path) -> Value {
    ask(&json!({
        "op": "lease_acquire", "lock": "install",
        "guard_home": home.to_string_lossy(), "client_pid": std::process::id(),
    }))
}

fn release(lease: &Value) {
    ask(&json!({ "op": "lease_release", "lease": lease }));
}

fn end(owner: &Value, committed: bool) {
    let answer = ask(&json!({ "op": "owned_end", "owner": owner, "committed": committed }));
    assert_eq!(answer["ok"], true);
}

#[test]
fn owner_holds_the_installation_lock_and_journals_begin_to_committed() {
    let root = TempDir::new().unwrap();
    let home = root.path().join("guard");
    let target = root.path().join("home/.codex/config.toml");
    let started = ask(&begin_request(&home, &target, json!({})));
    assert_eq!(started["ok"], true, "{started}");
    let owner = started["owner"].clone();
    assert_eq!(
        started["config_target_id"],
        sha256_hex(resolve_lenient(&target).to_string_lossy().as_bytes())
    );
    assert_eq!(install_lease(&home), json!({ "ok": false, "busy": true }));
    let recorded = ask(&json!({
        "op": "owned_record", "owner": owner, "client_pid": std::process::id(), "thread": THREAD,
        "mutations": [{
            "operation": "write", "path": target.to_string_lossy(),
            "before_present": true, "after_present": true,
            "before_digest": "aa", "after_digest": "bb",
        }],
    }));
    assert_eq!(recorded["recorded"], true);
    assert_eq!(recorded["dropped_events"], 0);
    end(&owner, true);
    assert_eq!(operations(&home), ["begin", "write", "committed"]);
    for line in lines(&home) {
        assert_eq!(line["operation_id"], started["operation_id"]);
        assert_eq!(line["actor"], "test-actor");
        assert_eq!(line["process_identity"], "test-process");
        assert_eq!(line["pid"], std::process::id());
    }
    let freed = install_lease(&home);
    assert_eq!(freed["ok"], true);
    release(&freed["lease"]);
}

#[test]
fn a_failed_owner_journals_failed_and_releases_the_lock() {
    let root = TempDir::new().unwrap();
    let home = root.path().join("guard");
    let started = ask(&begin_request(
        &home,
        &root.path().join("config"),
        json!({}),
    ));
    end(&started["owner"], false);
    assert_eq!(operations(&home), ["begin", "failed"]);
    release(&install_lease(&home)["lease"]);
    // An owner that ended is gone; a later record is not journaled.
    let late = ask(&json!({
        "op": "owned_record", "owner": started["owner"], "client_pid": std::process::id(),
        "thread": THREAD, "mutations": [],
    }));
    assert_eq!(late["recorded"], false);
}

#[test]
fn a_pending_transition_refuses_the_owner_and_frees_its_locks() {
    let root = TempDir::new().unwrap();
    let home = root.path().join("guard");
    let target = root.path().join("home/.codex/config.toml");
    fs::create_dir_all(home.join("managed")).unwrap();
    fs::write(home.join("managed/runtime-transition.json"), b"{}").unwrap();
    let dir = root.path().join("home/.codex");
    let refused = ask(&begin_request(&home, &target, json!({ "dirs": [dir] })));
    assert_eq!(
        refused,
        json!({ "ok": false, "failure": { "kind": "transition", "reason": "pending_transition" } })
    );
    assert_eq!(operations(&home), ["begin", "failed"]);
    let freed = install_lease(&home);
    assert_eq!(freed["ok"], true);
    release(&freed["lease"]);
    let lifecycle = ask(&json!({
        "op": "owned_locks", "dirs": [dir], "client_pid": std::process::id(),
    }));
    assert_eq!(lifecycle["ok"], true, "{lifecycle}");
    for lease in lifecycle["leases"].as_array().unwrap() {
        release(lease);
    }
}

#[test]
fn a_check_that_is_not_asked_for_lets_a_pending_transition_pass() {
    let root = TempDir::new().unwrap();
    let home = root.path().join("guard");
    fs::create_dir_all(home.join("managed")).unwrap();
    fs::write(home.join("managed/runtime-transition.json"), b"{}").unwrap();
    let started = ask(&begin_request(
        &home,
        &root.path().join("config"),
        json!({ "check_pending": false }),
    ));
    assert_eq!(started["ok"], true, "{started}");
    end(&started["owner"], true);
}

#[cfg(unix)]
#[test]
fn a_linked_transition_record_is_pending_too() {
    let root = TempDir::new().unwrap();
    let home = root.path().join("guard");
    fs::create_dir_all(home.join("managed")).unwrap();
    std::os::unix::fs::symlink(
        root.path().join("nowhere"),
        home.join("managed/runtime-transition.json"),
    )
    .unwrap();
    let refused = ask(&begin_request(
        &home,
        &root.path().join("config"),
        json!({}),
    ));
    assert_eq!(refused["failure"]["reason"], "pending_transition");
}

#[test]
fn a_busy_installation_lock_refuses_at_the_deadline_and_releases_lifecycle_locks() {
    let root = TempDir::new().unwrap();
    let home = root.path().join("guard");
    let dir = root.path().join("home/.codex");
    let holder = install_lease(&home);
    assert_eq!(holder["ok"], true);
    let refused = ask(&begin_request(
        &home,
        &dir.join("config.toml"),
        json!({ "deadline_ms": 120, "dirs": [dir] }),
    ));
    assert_eq!(
        refused,
        json!({ "ok": false, "failure": {
            "kind": "timeout", "message": "Codex installation transaction deadline exceeded."
        } })
    );
    release(&holder["lease"]);
    let lifecycle = ask(&json!({
        "op": "owned_locks", "dirs": [dir], "client_pid": std::process::id(),
    }));
    assert_eq!(lifecycle["ok"], true, "{lifecycle}");
    for lease in lifecycle["leases"].as_array().unwrap() {
        release(lease);
    }
}

#[cfg(unix)]
#[test]
fn an_unsafe_installation_lock_refuses_with_its_integrity_code() {
    use std::os::unix::fs::PermissionsExt;
    let root = TempDir::new().unwrap();
    let home = root.path().join("guard");
    let codex = home.join("managed/codex");
    fs::create_dir_all(&codex).unwrap();
    let lock = codex.join("installation.lock");
    fs::write(&lock, b"").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
    let refused = ask(&begin_request(
        &home,
        &root.path().join("config"),
        json!({}),
    ));
    assert_eq!(refused["failure"]["kind"], "integrity");
    assert_eq!(
        refused["failure"]["code"],
        "codex_hook_transaction_lock_unsafe"
    );
    assert_eq!(
        refused["failure"]["message"],
        "Codex transaction ownership file is unsafe."
    );
}

#[cfg(unix)]
#[test]
fn a_linked_installation_lock_is_refused_and_its_target_kept() {
    let root = TempDir::new().unwrap();
    let home = root.path().join("guard");
    let codex = home.join("managed/codex");
    fs::create_dir_all(&codex).unwrap();
    let victim = root.path().join("victim");
    fs::write(&victim, b"preserve").unwrap();
    std::os::unix::fs::symlink(&victim, codex.join("installation.lock")).unwrap();
    let refused = ask(&begin_request(
        &home,
        &root.path().join("config"),
        json!({}),
    ));
    assert_eq!(refused["failure"]["kind"], "integrity", "{refused}");
    assert_eq!(fs::read(&victim).unwrap(), b"preserve");
}

#[test]
fn the_installation_lock_file_survives_every_owner() {
    let root = TempDir::new().unwrap();
    let home = root.path().join("guard");
    let lock = home.join("managed/codex/installation.lock");
    let first = ask(&begin_request(
        &home,
        &root.path().join("config"),
        json!({}),
    ));
    assert!(lock.is_file());
    end(&first["owner"], true);
    let second = ask(&begin_request(
        &home,
        &root.path().join("config"),
        json!({}),
    ));
    assert_ne!(second["operation_id"], first["operation_id"]);
    end(&second["owner"], true);
    assert!(lock.is_file());
}

#[test]
fn a_record_from_another_thread_or_process_is_not_journaled() {
    let root = TempDir::new().unwrap();
    let home = root.path().join("guard");
    let started = ask(&begin_request(
        &home,
        &root.path().join("config"),
        json!({}),
    ));
    let mutation = json!({
        "operation": "write", "path": root.path().join("x").to_string_lossy(),
        "before_present": false, "after_present": true,
        "before_digest": null, "after_digest": "bb",
    });
    for (pid, thread) in [
        (std::process::id(), THREAD + 1),
        (std::process::id() + 1, THREAD),
    ] {
        let answer = ask(&json!({
            "op": "owned_record", "owner": started["owner"], "client_pid": pid,
            "thread": thread, "mutations": [mutation],
        }));
        assert_eq!(answer["recorded"], false);
    }
    end(&started["owner"], true);
    assert_eq!(operations(&home), ["begin", "committed"]);
}

#[test]
fn recovery_that_cannot_proceed_fails_the_owner_before_any_work() {
    let root = TempDir::new().unwrap();
    let home = root.path().join("guard");
    let codex = home.join("managed/codex");
    fs::create_dir_all(&codex).unwrap();
    fs::write(codex.join("pending-hook-publication.json"), b"not json").unwrap();
    let refused = ask(&begin_request(
        &home,
        &root.path().join("config"),
        json!({ "recover": true }),
    ));
    assert_eq!(refused["ok"], false);
    assert_eq!(refused["failure"]["kind"], "fault", "{refused}");
    assert_eq!(operations(&home), ["begin", "failed"]);
    let freed = install_lease(&home);
    assert_eq!(freed["ok"], true);
    release(&freed["lease"]);
}

#[test]
fn recovery_with_nothing_pending_lets_the_owner_start() {
    let root = TempDir::new().unwrap();
    let home = root.path().join("guard");
    let started = ask(&begin_request(
        &home,
        &root.path().join("config"),
        json!({ "recover": true }),
    ));
    assert_eq!(started["ok"], true, "{started}");
    let again = ask(&json!({ "op": "owned_recover", "owner": started["owner"] }));
    assert_eq!(again["ok"], true, "{again}");
    end(&started["owner"], true);
    assert_eq!(operations(&home), ["begin", "committed"]);
}

#[test]
fn one_call_runs_as_the_owner_and_commits() {
    let root = TempDir::new().unwrap();
    let home = root.path().join("guard");
    let mut request = begin_request(&home, &root.path().join("config"), json!({}));
    request["op"] = "owned_call".into();
    request["call"] = json!({ "op": "publication_recover", "home": home.to_string_lossy() });
    let answer = ask(&request);
    assert_eq!(answer, json!({ "ok": true, "value": false }));
    assert_eq!(operations(&home), ["begin", "committed"]);
    let freed = install_lease(&home);
    assert_eq!(freed["ok"], true);
    release(&freed["lease"]);
}

#[test]
fn one_call_that_fails_journals_failed_and_reports_the_fault() {
    let root = TempDir::new().unwrap();
    let home = root.path().join("guard");
    let codex = home.join("managed/codex");
    fs::create_dir_all(&codex).unwrap();
    fs::write(codex.join("pending-hook-publication.json"), b"not json").unwrap();
    let mut request = begin_request(&home, &root.path().join("config"), json!({}));
    request["op"] = "owned_call".into();
    request["call"] = json!({ "op": "publication_recover", "home": home.to_string_lossy() });
    let answer = ask(&request);
    assert_eq!(answer["failure"]["kind"], "fault", "{answer}");
    assert_eq!(operations(&home), ["begin", "failed"]);
}

#[test]
fn a_request_without_its_fields_is_invalid() {
    assert!(dispatch(&json!({ "op": "owned_begin" })).is_err());
    assert!(dispatch(&json!({ "op": "owned_end" })).is_err());
    assert!(dispatch(&json!({ "op": "owned_nothing" })).is_err());
}

#[cfg(unix)]
#[test]
fn a_trailing_parent_after_a_missing_name_pops_it_like_path_resolve() {
    let root = TempDir::new().unwrap();
    let actual = fs::canonicalize(root.path()).unwrap().join("target");
    fs::create_dir(&actual).unwrap();
    let link = root.path().join("link");
    std::os::unix::fs::symlink(&actual, &link).unwrap();
    assert_eq!(resolve_lenient(&link.join("missing/..")), actual);
    assert_eq!(
        resolve_lenient(&link.join("missing/../other")),
        actual.join("other")
    );
    assert_eq!(
        resolve_lenient(&link.join("missing/.")),
        actual.join("missing")
    );
}
