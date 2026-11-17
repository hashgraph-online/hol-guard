//! `apply`: the compare-and-swap write, and every way it can fail.

use super::*;

#[test]
fn apply_writes_the_previewed_file_and_keeps_a_copy() {
    for tool in TOOLS {
        let home = tempfile::tempdir().expect("home");
        let guard_home = home.path().join("guard");
        let path = seed(home.path(), tool);
        let before = fs::read(&path).expect("read");

        let plan = configure(tool, &path, &guard_home, "/guard-home");

        assert_eq!(plan.action, "add", "{tool}");
        assert_eq!(fs::read(&path).expect("read"), plan.after, "{tool}");
        assert!(strays(path.parent().expect("parent")).is_empty(), "{tool}");
        let records = kept_records(&guard_home, tool);
        assert_eq!(records.len(), 1, "{tool}");
        assert_eq!(
            fs::read(records[0].with_extension("before")).expect("copy"),
            before,
            "{tool}"
        );
        #[cfg(unix)]
        {
            assert_eq!(mode_bits(&path), 0o640, "{tool}");
            assert_eq!(mode_bits(&records[0]), 0o600, "{tool}");
            assert_eq!(mode_bits(&backups_dir(&guard_home, tool)), 0o700, "{tool}");
        }
    }
}

#[test]
fn applying_again_previews_no_change() {
    for tool in TOOLS {
        let home = tempfile::tempdir().expect("home");
        let guard_home = home.path().join("guard");
        let path = seed(home.path(), tool);
        let _ = configure(tool, &path, &guard_home, "/guard-home");
        let written = fs::read(&path).expect("read");

        let again = preview(tool, &path, "/guard-home");

        assert_eq!(again.action, "unchanged", "{tool}");
        assert_eq!(again.before_sha256, Some(sha256_hex(&written)), "{tool}");
        assert_eq!(kept_records(&guard_home, tool).len(), 1, "{tool}");
    }
}

#[test]
fn apply_creates_a_private_file_and_restore_removes_it() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let path = settings_file(home.path(), "cursor");

    let plan = configure("cursor", &path, &guard_home, "/guard-home");

    assert_eq!(plan.action, "create_file");
    assert_eq!(
        read_json(&path)["mcpServers"][SERVER],
        entry("cursor", "/guard-home")
    );
    #[cfg(unix)]
    assert_eq!(mode_bits(&path), 0o600);
    let copies = fs::read_dir(backups_dir(&guard_home, "cursor"))
        .expect("backups")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "before"))
        .count();
    assert_eq!(copies, 0);

    let restored = restore_with(&Real, "cursor", &path, &guard_home).expect("something to undo");

    assert!(restored.removed_file);
    assert!(!path.exists());
}

#[test]
fn a_change_after_the_preview_is_never_overwritten() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let path = seed(home.path(), "claude-code");
    let plan = preview("claude-code", &path, "/guard-home");
    let edited = JSON_SETTINGS.replace("\"numStartups\": 3", "\"numStartups\": 4");
    fs::write(&path, &edited).expect("edit");

    let error = apply_with(&Real, &plan, "claude-code", &path, &guard_home).expect_err("refused");

    assert_eq!(error.reason, "changed_since_preview");
    assert_eq!(fs::read_to_string(&path).expect("read"), edited);
    assert!(kept_records(&guard_home, "claude-code").is_empty());
}

#[test]
fn a_change_just_before_the_move_is_never_overwritten() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let path = seed(home.path(), "claude-code");
    let plan = preview("claude-code", &path, "/guard-home");
    let edited = JSON_SETTINGS.replace("\"numStartups\": 3", "\"numStartups\": 5");
    let mut rig = Rig::new();
    rig.temporary = Box::new(|target, payload, mode| {
        let temporary = Real.write_temporary(target, payload, mode)?;
        fs::write(target, &edited)?;
        Ok(temporary)
    });

    let error = apply_with(&rig, &plan, "claude-code", &path, &guard_home).expect_err("refused");

    assert_eq!(error.reason, "changed_since_preview");
    assert_eq!(fs::read_to_string(&path).expect("read"), edited);
    assert!(strays(path.parent().expect("parent")).is_empty());
    assert!(kept_records(&guard_home, "claude-code").is_empty());
}

#[test]
fn a_file_created_after_the_preview_is_never_replaced() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let path = settings_file(home.path(), "cursor");
    let plan = preview("cursor", &path, "/guard-home");
    assert_eq!(plan.action, "create_file");
    let calls = std::cell::Cell::new(0);
    let mut rig = Rig::new();
    rig.read = Box::new(|target| {
        calls.set(calls.get() + 1);
        let result = Real.read(target);
        if calls.get() == 2 {
            fs::write(target, b"{\"mcpServers\": {}}\n")?;
        }
        result
    });

    let error = apply_with(&rig, &plan, "cursor", &path, &guard_home).expect_err("refused");

    assert_eq!(error.reason, "changed_since_preview");
    assert_eq!(fs::read(&path).expect("read"), b"{\"mcpServers\": {}}\n");
    assert!(strays(path.parent().expect("parent")).is_empty());
}

#[test]
fn a_write_that_does_not_read_back_is_undone() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let path = seed(home.path(), "codex");
    let before = fs::read(&path).expect("read");
    let plan = preview("codex", &path, "/guard-home");
    let damaged = std::cell::Cell::new(false);
    let mut rig = Rig::new();
    rig.replace = Box::new(|from, to| {
        Real.replace(from, to)?;
        if to == path && !damaged.replace(true) {
            let mut text = fs::read(to)?;
            text.extend_from_slice(b"damaged = true\n");
            fs::write(to, text)?;
        }
        Ok(())
    });

    let error = apply_with(&rig, &plan, "codex", &path, &guard_home).expect_err("undone");

    assert_eq!(error.reason, "write_not_verified");
    assert_eq!(fs::read(&path).expect("read"), before);
    #[cfg(unix)]
    assert_eq!(mode_bits(&path), 0o640);
    assert!(kept_records(&guard_home, "codex").is_empty());
}

/// Replaces the file once, then refuses every later move onto it.
fn refuse_after_first_move<'a>(
    path: &'a Path,
    calls: &'a std::cell::Cell<u32>,
    first: impl Fn(&Path, &Path) -> Result<(), Failure> + 'a,
) -> MoveFn<'a> {
    Box::new(move |from, to| {
        if to != path {
            return Real.replace(from, to);
        }
        calls.set(calls.get() + 1);
        if calls.get() > 1 {
            return Err(denied());
        }
        first(from, to)
    })
}

#[test]
fn a_write_that_cannot_be_put_back_keeps_the_copy() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let path = seed(home.path(), "codex");
    let before = fs::read(&path).expect("read");
    let plan = preview("codex", &path, "/guard-home");
    let calls = std::cell::Cell::new(0);
    let mut rig = Rig::new();
    rig.replace = refuse_after_first_move(&path, &calls, |from, to| {
        Real.replace(from, to)?;
        let mut text = fs::read(to)?;
        text.extend_from_slice(b"damaged = true\n");
        fs::write(to, text)?;
        Ok(())
    });

    let error = apply_with(&rig, &plan, "codex", &path, &guard_home).expect_err("kept");

    assert_eq!(error.reason, "put_back_failed");
    assert!(error.message.contains("restore codex"));
    let records = kept_records(&guard_home, "codex");
    assert_eq!(records.len(), 1);
    assert_eq!(
        fs::read(records[0].with_extension("before")).expect("copy"),
        before
    );

    // Following the message brings the earlier file back whole, damage included.
    let restored = restore_with(&Real, "codex", &path, &guard_home).expect("restored");

    assert_eq!(restored.scope, "file");
    assert_eq!(fs::read(&path).expect("read"), before);
    assert!(kept_records(&guard_home, "codex").is_empty());
}

#[test]
fn a_failed_write_that_removed_the_file_is_restored() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let path = seed(home.path(), "codex");
    let before = fs::read(&path).expect("read");
    let plan = preview("codex", &path, "/guard-home");
    let calls = std::cell::Cell::new(0);
    let mut rig = Rig::new();
    rig.replace = refuse_after_first_move(&path, &calls, |_, to| Ok(fs::remove_file(to)?));

    let error = apply_with(&rig, &plan, "codex", &path, &guard_home).expect_err("kept");

    assert_eq!(error.reason, "put_back_failed");
    assert!(!path.exists());

    let restored = restore_with(&Real, "codex", &path, &guard_home).expect("restored");

    assert_eq!(restored.scope, "file");
    assert_eq!(fs::read(&path).expect("read"), before);
}

#[test]
fn nothing_is_created_without_hard_links() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let path = settings_file(home.path(), "cursor");
    let plan = preview("cursor", &path, "/guard-home");
    assert_eq!(plan.action, "create_file");
    let mut rig = Rig::new();
    rig.link = Box::new(|_, _| Err(Failure::Io(io::Error::from_raw_os_error(1))));

    let error = apply_with(&rig, &plan, "cursor", &path, &guard_home).expect_err("refused");

    assert_eq!(error.reason, "write_failed");
    assert!(!path.exists());
    assert!(strays(path.parent().expect("parent")).is_empty());
    assert!(kept_records(&guard_home, "cursor").is_empty());
}

#[test]
fn nothing_is_written_when_no_copy_can_be_kept() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let path = seed(home.path(), "codex");
    let before = fs::read(&path).expect("read");
    let blocker = backups_dir(&guard_home, "codex");
    fs::create_dir_all(blocker.parent().expect("parent")).expect("folder");
    fs::write(blocker, "not a folder").expect("blocker");
    let plan = preview("codex", &path, "/guard-home");

    let error = apply_with(&Real, &plan, "codex", &path, &guard_home).expect_err("refused");

    assert_eq!(error.reason, "backup_failed");
    assert_eq!(fs::read(&path).expect("read"), before);
}

#[cfg(unix)]
#[test]
fn a_linked_settings_file_is_refused() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let target = seed(&home.path().join("elsewhere"), "codex");
    let before = fs::read(&target).expect("read");
    let link = settings_file(&home.path().join("home"), "codex");
    fs::create_dir_all(link.parent().expect("parent")).expect("folder");
    std::os::unix::fs::symlink(&target, &link).expect("link");
    let plan = preview("codex", &link, "/guard-home");

    let error = apply_with(&Real, &plan, "codex", &link, &guard_home).expect_err("refused");

    assert_eq!(error.reason, "settings_file_is_link");
    assert!(link.is_symlink());
    assert_eq!(fs::read(&target).expect("read"), before);
}

#[test]
fn an_action_the_write_does_not_know_is_not_answered() {
    let home = tempfile::tempdir().expect("home");
    let path = seed(home.path(), "codex");
    let request = json!({
        "ai_tool": "codex",
        "path": path.to_string_lossy(),
        "guard_home": home.path().join("guard").to_string_lossy(),
        "entry": entry("codex", "/guard-home"),
        "action": "unchanged",
        "before_sha256": null,
        "after": "",
    });

    assert!(answer_op("apply", &request).is_none());
}
