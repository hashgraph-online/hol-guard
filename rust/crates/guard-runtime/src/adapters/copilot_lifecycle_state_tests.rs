//! Pins the Copilot lifecycle state verdicts `copilot_state_paths.py` gave
//! before they moved to the native runtime, and the argument refusals.

use serde_json::{json, Value};

use super::copilot_lifecycle_state::{dispatch, valid_backup_envelope};
use super::runner_authority_op::ERR_INVALID;

const TARGET: &str = "/home/dev/.copilot/mcp-config.json";
const BACKUP: &str = "/guard/managed/copilot/abc.backup.json";
const STATE: &str = "/guard/managed/copilot/abc.state.json";
const ENVELOPE: &str = "{\"existed\": true, \"content\": \"{}\\n\"}";

fn reuse(recorded: Value, backup: &std::path::Path) -> Value {
    let answer = dispatch(&json!({
        "action": "backup_reuse",
        "recorded": recorded,
        "expected": [TARGET, BACKUP],
        "backup": backup.to_str().expect("utf-8 path"),
    }))
    .expect("decision");
    answer["decision"].clone()
}

fn backup_holding(directory: &tempfile::TempDir, bytes: &[u8]) -> std::path::PathBuf {
    let backup = directory.path().join("abc.backup.json");
    std::fs::write(&backup, bytes).expect("write backup");
    backup
}

#[test]
fn a_bound_readable_backup_is_reused() {
    let directory = tempfile::tempdir().expect("tempdir");
    let absent = "{\"content\": null, \"existed\": false}";
    for envelope in [ENVELOPE, absent] {
        let backup = backup_holding(&directory, envelope.as_bytes());
        assert_eq!(
            reuse(json!([TARGET, BACKUP]), &backup),
            "reuse",
            "{envelope}"
        );
    }
}

#[test]
fn a_backup_larger_than_a_call_is_read_where_it_lies() {
    let directory = tempfile::tempdir().expect("tempdir");
    let content = "x".repeat(8 * 1024 * 1024);
    let envelope = json!({ "existed": true, "content": content }).to_string();
    let backup = backup_holding(&directory, envelope.as_bytes());
    assert_eq!(reuse(json!([TARGET, BACKUP]), &backup), "reuse");
}

#[test]
fn state_that_binds_another_pair_replaces_the_backup() {
    let directory = tempfile::tempdir().expect("tempdir");
    // An unusable backup never matters when the state binds another pair.
    let missing = directory.path().join("missing.backup.json");
    for recorded in [
        json!([null, null]),
        json!([TARGET, null]),
        json!([null, BACKUP]),
        json!(["/home/dev/other.json", BACKUP]),
        json!([TARGET, "/guard/managed/copilot/def.backup.json"]),
    ] {
        assert_eq!(reuse(recorded.clone(), &missing), "replace", "{recorded}");
    }
}

#[test]
fn a_bound_backup_that_cannot_be_restored_is_refused() {
    let directory = tempfile::tempdir().expect("tempdir");
    assert_eq!(
        reuse(json!([TARGET, BACKUP]), &directory.path().join("missing")),
        "refuse"
    );
    assert_eq!(reuse(json!([TARGET, BACKUP]), directory.path()), "refuse");
    for bytes in [
        &b""[..],
        b"not json",
        b"{\"existed\": false, \"content\": null}\xff",
    ] {
        let backup = backup_holding(&directory, bytes);
        assert_eq!(
            reuse(json!([TARGET, BACKUP]), &backup),
            "refuse",
            "{bytes:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_bound_backup_reached_through_a_link_is_refused() {
    let directory = tempfile::tempdir().expect("tempdir");
    let backup = backup_holding(&directory, ENVELOPE.as_bytes());
    let link = directory.path().join("link.backup.json");
    std::os::unix::fs::symlink(&backup, &link).expect("symlink");
    assert_eq!(reuse(json!([TARGET, BACKUP]), &link), "refuse");
}

#[test]
fn backup_envelopes_match_the_original_shape() {
    for (text, valid) in [
        (ENVELOPE, true),
        ("{\"existed\": false, \"content\": null}", true),
        ("  {\"existed\": true, \"content\": \"\"}\n", true),
        ("{\"existed\": true, \"content\": null}", false),
        ("{\"existed\": false, \"content\": \"{}\"}", false),
        ("{\"existed\": 1, \"content\": \"{}\"}", false),
        ("{\"existed\": \"true\", \"content\": \"{}\"}", false),
        ("{\"existed\": true}", false),
        (
            "{\"existed\": true, \"content\": \"{}\", \"extra\": 1}",
            false,
        ),
        ("{\"existed\": true, \"content\": {}}", false),
        ("[true, \"{}\"]", false),
        ("null", false),
        ("{\"existed\": true, \"content\": NaN}", false),
        ("\u{feff}{\"existed\": false, \"content\": null}", false),
    ] {
        assert_eq!(valid_backup_envelope(text), valid, "{text}");
    }
}

fn paths(state: &str) -> Value {
    json!({ "owned": true, "state": state, "backup": [BACKUP, BACKUP] })
}

fn global() -> Value {
    json!({
        "source": "global",
        "keys": [TARGET, "/private/home/dev/.copilot/mcp-config.json"],
        "contained": true,
        "paths": paths(STATE),
    })
}

fn workspace(source: &str, key: &str) -> Value {
    json!({
        "source": source,
        "keys": [key],
        "contained": true,
        "paths": paths("/guard/managed/copilot/ws.state.json"),
    })
}

fn state_entry(managed: Value, candidates: Value) -> Value {
    json!({
        "state": STATE,
        "fields": [managed, BACKUP],
        "candidates": candidates,
    })
}

fn verdicts(entries: Value) -> Value {
    dispatch(&json!({ "action": "state_entries", "entries": entries })).expect("entries")["entries"]
        .clone()
}

fn verdict(entry: Value) -> Value {
    verdicts(json!([entry]))[0].clone()
}

#[test]
fn an_authenticated_entry_names_its_config() {
    assert_eq!(verdict(state_entry(json!(TARGET), json!([global()]))), 0);
    let resolved = "/private/home/dev/.copilot/mcp-config.json";
    assert_eq!(verdict(state_entry(json!(resolved), json!([global()]))), 0);
}

#[test]
fn unusable_fields_name_nothing_guard_manages() {
    for managed in [
        json!(null),
        json!(1),
        json!([TARGET]),
        json!(""),
        json!("/home/dev/\u{0}x"),
    ] {
        assert_eq!(
            verdict(state_entry(managed.clone(), json!([global()]))),
            Value::Null,
            "{managed}"
        );
    }
    let mut no_backup = state_entry(json!(TARGET), json!([global()]));
    no_backup["fields"][1] = json!("");
    assert_eq!(verdict(no_backup), Value::Null);
}

#[test]
fn a_config_no_candidate_names_is_rejected() {
    let entry = state_entry(json!("/etc/passwd"), json!([global()]));
    assert_eq!(verdict(entry), Value::Null);
}

#[test]
fn a_recorded_workspace_replaces_the_current_one() {
    let current = "/work/now/.mcp.json";
    let recorded = "/work/then/.mcp.json";
    let both = json!([
        global(),
        workspace("recorded", recorded),
        workspace("current", current)
    ]);
    let mut entry = state_entry(json!(recorded), both);
    entry["state"] = json!("/guard/managed/copilot/ws.state.json");
    assert_eq!(verdict(entry.clone()), 1);
    entry["fields"][0] = json!(current);
    assert_eq!(verdict(entry.clone()), Value::Null);
    let only_current = json!([global(), workspace("current", current)]);
    entry["candidates"] = only_current;
    assert_eq!(verdict(entry), 1);
}

#[test]
fn a_later_candidate_with_the_same_spelling_wins() {
    let mut entry = state_entry(
        json!(TARGET),
        json!([global(), workspace("current", TARGET)]),
    );
    assert_eq!(verdict(entry.clone()), Value::Null);
    entry["state"] = json!("/guard/managed/copilot/ws.state.json");
    assert_eq!(verdict(entry), 1);
}

#[test]
fn an_escaping_config_or_foreign_paths_are_rejected() {
    let mut escaping = global();
    escaping["contained"] = json!(false);
    escaping["paths"] = Value::Null;
    // Containment is checked before the state and backup paths are named.
    assert_eq!(
        verdict(state_entry(json!(TARGET), json!([escaping]))),
        Value::Null
    );
    let mut foreign = global();
    foreign["paths"]["owned"] = json!(false);
    assert_eq!(
        verdict(state_entry(json!(TARGET), json!([foreign]))),
        Value::Null
    );
    let mut moved = state_entry(json!(TARGET), json!([global()]));
    moved["state"] = json!("/guard/managed/copilot/alias.state.json");
    assert_eq!(verdict(moved), Value::Null);
    let mut other_backup = state_entry(json!(TARGET), json!([global()]));
    other_backup["fields"][1] = json!("/guard/managed/copilot/def.backup.json");
    assert_eq!(verdict(other_backup), Value::Null);
}

#[test]
fn either_backup_spelling_is_accepted() {
    let mut candidate = global();
    candidate["paths"]["backup"] = json!([
        "/guard/managed/copilot/abc.backup.json",
        "/real/abc.backup.json"
    ]);
    let mut entry = state_entry(json!(TARGET), json!([candidate]));
    assert_eq!(verdict(entry.clone()), 0);
    entry["fields"][1] = json!("/real/abc.backup.json");
    assert_eq!(verdict(entry), 0);
}

#[test]
fn a_selected_config_whose_paths_raised_raises() {
    let mut broken = global();
    broken["paths"] = Value::Null;
    let answer = verdict(state_entry(json!(TARGET), json!([broken])));
    assert_eq!(answer, json!({ "raise": 0 }));
    // A candidate the entry does not name never raises.
    let mut other = workspace("current", "/work/.mcp.json");
    other["paths"] = Value::Null;
    let entry = state_entry(json!(TARGET), json!([global(), other]));
    assert_eq!(verdict(entry), 0);
}

#[test]
fn every_state_file_gets_one_verdict() {
    let unmanaged = state_entry(json!(TARGET), json!([]));
    let answer = verdicts(json!([
        unmanaged,
        state_entry(json!(TARGET), json!([global()]))
    ]));
    assert_eq!(answer, json!([null, 0]));
    assert_eq!(verdicts(json!([])), json!([]));
}

#[test]
fn malformed_arguments_are_refused() {
    let good_entry = state_entry(json!(TARGET), json!([global()]));
    let mut bad_source = global();
    bad_source["source"] = json!("elsewhere");
    let mut missing_state = good_entry.clone();
    missing_state["state"] = Value::Null;
    for args in [
        json!(null),
        json!({}),
        json!({ "action": "other" }),
        json!({ "action": "backup_reuse", "recorded": [null, null], "expected": [TARGET, BACKUP] }),
        json!({ "action": "backup_reuse", "recorded": [null], "expected": [TARGET, BACKUP], "backup": BACKUP }),
        json!({ "action": "backup_reuse", "recorded": [1, null], "expected": [TARGET, BACKUP], "backup": BACKUP }),
        json!({ "action": "backup_reuse", "recorded": [null, null], "expected": [TARGET, null], "backup": BACKUP }),
        json!({ "action": "backup_reuse", "recorded": [null, null], "expected": [TARGET, BACKUP], "backup": null }),
        json!({ "action": "backup_reuse", "recorded": [null, null], "expected": [TARGET, BACKUP], "backup": { "text": "{}" } }),
        json!({ "action": "state_entries", "entries": {} }),
        json!({ "action": "state_entries", "entries": [good_entry], "extra": 1 }),
        json!({ "action": "state_entries", "entries": [state_entry(json!(TARGET), json!([bad_source]))] }),
        json!({ "action": "state_entries", "entries": [missing_state] }),
    ] {
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{args}");
    }
}
