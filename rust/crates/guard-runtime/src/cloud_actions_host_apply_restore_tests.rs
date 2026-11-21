//! `restore`: what it puts back, and when it leaves the file alone.

use std::fs;

use serde_json::json;

use super::super::records::latest_backup;
use super::*;

const LOCAL_URL: &str = "http://127.0.0.1:3017/api/guard/gateway/mcp";

#[test]
fn restore_puts_back_the_file_from_before() {
    for tool in TOOLS {
        let home = tempfile::tempdir().expect("home");
        let guard_home = home.path().join("guard");
        let path = seed(home.path(), tool);
        let before = fs::read(&path).expect("read");
        let _ = configure(tool, &path, &guard_home, "/guard-home");

        let restored = restore_with(&Real, tool, &path, &guard_home).expect("restored");

        assert!(!restored.removed_file, "{tool}");
        assert_eq!(restored.scope, "file", "{tool}");
        assert_eq!(fs::read(&path).expect("read"), before, "{tool}");
        #[cfg(unix)]
        assert_eq!(mode_bits(&path), 0o640, "{tool}");
        assert!(kept_records(&guard_home, tool).is_empty(), "{tool}");
        assert!(
            restore_with(&Real, tool, &path, &guard_home).is_none(),
            "{tool}"
        );
        assert_eq!(fs::read(&path).expect("read"), before, "{tool}");
    }
}

#[test]
fn restore_after_later_edits_removes_only_guards_entry() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let path = seed(home.path(), "codex");
    let _ = configure("codex", &path, &guard_home, "/guard-home");
    let mut text = fs::read_to_string(&path).expect("read");
    text.push_str("\n[mcp_servers.notes]\ncommand = \"notes-mcp\"\n");
    fs::write(&path, text).expect("edit");

    let restored = restore_with(&Real, "codex", &path, &guard_home).expect("restored");

    assert_eq!(restored.scope, "entry");
    assert!(restored.entry_removed);
    let text = fs::read_to_string(&path).expect("read");
    assert!(text.starts_with(CODEX_SETTINGS));
    assert!(!text.contains(SERVER));
    assert!(text.contains("[mcp_servers.notes]\ncommand = \"notes-mcp\"\n"));
    assert!(kept_records(&guard_home, "codex").is_empty());
}

#[test]
fn restore_keeps_what_the_ai_tool_rewrote() {
    // Claude Code rewrites its settings file while it runs.
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let path = seed(home.path(), "claude-code");
    let _ = configure("claude-code", &path, &guard_home, "/guard-home");
    let rewritten = fs::read_to_string(&path)
        .expect("read")
        .replace("\"numStartups\": 3", "\"numStartups\": 4");
    fs::write(&path, rewritten).expect("edit");

    let restored = restore_with(&Real, "claude-code", &path, &guard_home).expect("restored");

    assert_eq!(restored.scope, "entry");
    assert_eq!(
        fs::read_to_string(&path).expect("read"),
        JSON_SETTINGS.replace("\"numStartups\": 3", "\"numStartups\": 4")
    );
}

#[test]
fn restore_after_later_edits_puts_back_the_earlier_address() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let path = settings_file(home.path(), "cursor");
    fs::create_dir_all(path.parent().expect("parent")).expect("folder");
    fs::write(
        &path,
        format!("{}\n", json!({"mcpServers": {SERVER: {"url": LOCAL_URL}}})),
    )
    .expect("seed");
    let plan = configure("cursor", &path, &guard_home, "/guard-home");
    assert_eq!(plan.action, "update");
    edit_json(&path, |document| {
        document["mcpServers"]["notes"] = json!({"command": "notes-mcp"});
    });

    let restored = restore_with(&Real, "cursor", &path, &guard_home).expect("restored");

    assert_eq!((restored.scope, restored.entry_removed), ("entry", false));
    assert_eq!(
        read_json(&path),
        json!({"mcpServers": {SERVER: {"url": LOCAL_URL}, "notes": {"command": "notes-mcp"}}})
    );
}

#[test]
fn restore_keeps_a_created_file_that_was_edited_since() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let path = settings_file(home.path(), "cursor");
    let plan = configure("cursor", &path, &guard_home, "/guard-home");
    assert_eq!(plan.action, "create_file");
    edit_json(&path, |document| {
        document["mcpServers"]["notes"] = json!({"command": "notes-mcp"});
    });

    let restored = restore_with(&Real, "cursor", &path, &guard_home).expect("restored");

    assert!(!restored.removed_file);
    assert_eq!(
        read_json(&path),
        json!({"mcpServers": {"notes": {"command": "notes-mcp"}}})
    );
}

#[test]
fn restore_leaves_guards_entry_alone_once_someone_changed_it() {
    for change in ["address", "removed", "file_removed"] {
        let home = tempfile::tempdir().expect("home");
        let guard_home = home.path().join("guard");
        let path = seed(home.path(), "cursor");
        let _ = configure("cursor", &path, &guard_home, "/guard-home");
        edit_json(&path, |document| {
            let servers = document["mcpServers"].as_object_mut().expect("servers");
            if change == "address" {
                let args = servers[SERVER]["args"].as_array_mut().expect("args");
                *args.last_mut().expect("last") = json!("/elsewhere");
            } else {
                servers.remove(SERVER);
            }
        });
        if change == "file_removed" {
            fs::remove_file(&path).expect("remove");
        }
        let edited = fs::read(&path).ok();

        let error = restore(&Real, "cursor", &path, &guard_home).expect_err("refused");

        assert_eq!(error.reason, "changed_since_apply", "{change}");
        assert_eq!(fs::read(&path).ok(), edited, "{change}");
        assert_eq!(kept_records(&guard_home, "cursor").len(), 1, "{change}");
    }
}

#[test]
fn restore_refuses_a_damaged_copy() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let path = seed(home.path(), "codex");
    let _ = configure("codex", &path, &guard_home, "/guard-home");
    let written = fs::read(&path).expect("read");
    let records = kept_records(&guard_home, "codex");
    fs::write(records[0].with_extension("before"), b"model = 'other'\n").expect("damage");

    let error = restore(&Real, "codex", &path, &guard_home).expect_err("refused");

    assert_eq!(error.reason, "backup_unreadable");
    assert_eq!(fs::read(&path).expect("read"), written);
}

#[test]
fn restore_reports_a_damaged_newer_record() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let path = seed(home.path(), "codex");
    let _ = configure("codex", &path, &guard_home, "/guard-home");
    let written = fs::read(&path).expect("read");
    fs::write(
        backups_dir(&guard_home, "codex").join(format!("{}-1.json", "9".repeat(20))),
        b"{\"format\": \"guard.cloud",
    )
    .expect("damage");

    let error = restore(&Real, "codex", &path, &guard_home).expect_err("refused");

    assert_eq!(error.reason, "backup_unreadable");
    assert_eq!(fs::read(&path).expect("read"), written);
}

#[test]
fn restore_finds_the_copy_through_another_spelling() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let path = seed(home.path(), "codex");
    let original = fs::read(&path).expect("read");
    let spelled = home
        .path()
        .join(".codex")
        .join("..")
        .join(".codex")
        .join("config.toml");

    let _ = configure("codex", &spelled, &guard_home, "/guard-home");

    assert!(restore_with(&Real, "codex", &path, &guard_home).is_some());
    assert_eq!(fs::read(&path).expect("read"), original);
}

#[test]
fn restore_steps_back_through_each_apply() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let path = seed(home.path(), "codex");
    let original = fs::read(&path).expect("read");
    let _ = configure("codex", &path, &guard_home, "/guard-home");
    let first = fs::read(&path).expect("read");
    let _ = configure("codex", &path, &guard_home, "/other-guard-home");

    assert!(restore_with(&Real, "codex", &path, &guard_home).is_some());
    assert_eq!(fs::read(&path).expect("read"), first);
    assert!(restore_with(&Real, "codex", &path, &guard_home).is_some());
    assert_eq!(fs::read(&path).expect("read"), original);
    assert!(restore_with(&Real, "codex", &path, &guard_home).is_none());
}

#[test]
fn only_the_latest_copies_are_kept() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let path = seed(home.path(), "codex");
    for index in 0..12 {
        let _ = configure(
            "codex",
            &path,
            &guard_home,
            &format!("/guard-home-{}", index % 2),
        );
    }

    let copies = fs::read_dir(backups_dir(&guard_home, "codex"))
        .expect("backups")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "before"))
        .count();
    assert_eq!(kept_records(&guard_home, "codex").len(), 10);
    assert_eq!(copies, 10);
}

#[test]
fn a_record_from_an_earlier_alpha_names_only_the_address() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let path = settings_file(home.path(), "cursor");
    let directory = backups_dir(&guard_home, "cursor");
    fs::create_dir_all(&directory).expect("folder");
    let record = json!({
        "format": "guard.cloud-actions.settings-backup.v1",
        "ai_tool": "cursor",
        "path": path.to_string_lossy(),
        "url": URL,
        "existed": false,
        "after_sha256": "0".repeat(64),
    });
    fs::write(
        directory.join("00000000000000000001-1.json"),
        record.to_string(),
    )
    .expect("record");

    let backup = latest_backup(&directory, &path)
        .expect("found")
        .expect("record");

    assert_eq!(backup.entry.get("url"), Some(&json!(URL)));
    assert!(!backup.replaced_entry);
}
