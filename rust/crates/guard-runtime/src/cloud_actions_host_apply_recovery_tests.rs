//! Recovery from an interrupted `apply`.
//!
//! The AI tool's settings file must end either as it was or recoverable with
//! `restore`, never changed with no copy to go back to. A test stands in for
//! the process being stopped with `Failure::Interrupt`.

use std::cell::Cell;
use std::fs;

use super::*;

const AFTER_GUARD: &[u8] = b"# The AI tool wrote this after Guard.\n";

fn codex() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let home = tempfile::tempdir().expect("home");
    let path = seed(home.path(), "codex");
    let guard_home = home.path().join("guard");
    (home, path, guard_home)
}

fn interrupted_at(path: &Path) -> MoveFn<'_> {
    Box::new(move |from, to| {
        if to == path {
            return Err(Failure::Interrupt);
        }
        Real.replace(from, to)
    })
}

#[test]
fn an_interrupt_before_the_move_changes_nothing() {
    let (_home, path, guard_home) = codex();
    let before = fs::read(&path).expect("read");
    let plan = preview("codex", &path, "/guard-home");
    let mut rig = Rig::new();
    rig.replace = interrupted_at(&path);

    let error = apply_with(&rig, &plan, "codex", &path, &guard_home).expect_err("stopped");

    assert_eq!(error.reason, "interrupted");
    assert_eq!(fs::read(&path).expect("read"), before);
    assert!(strays(path.parent().expect("parent")).is_empty());
    assert_eq!(kept_files(&guard_home, "codex"), 0);

    // Running the same command again works.
    apply_with(&Real, &plan, "codex", &path, &guard_home).expect("applied");
    assert_eq!(fs::read(&path).expect("read"), plan.after);
}

#[test]
fn an_interrupt_right_after_the_move_puts_the_earlier_file_back() {
    let (_home, path, guard_home) = codex();
    let before = fs::read(&path).expect("read");
    let plan = preview("codex", &path, "/guard-home");
    let interrupted = Cell::new(false);
    let mut rig = Rig::new();
    rig.replace = Box::new(|from, to| {
        Real.replace(from, to)?;
        // The move has landed, but Guard has not yet noted it.
        if to == path && !interrupted.replace(true) {
            return Err(Failure::Interrupt);
        }
        Ok(())
    });

    let error = apply_with(&rig, &plan, "codex", &path, &guard_home).expect_err("stopped");

    assert_eq!(error.reason, "interrupted");
    assert_eq!(fs::read(&path).expect("read"), before);
    assert!(strays(path.parent().expect("parent")).is_empty());
    assert_eq!(kept_files(&guard_home, "codex"), 0);
}

#[test]
fn an_edit_after_an_interrupted_move_is_kept_and_restore_stays_available() {
    let (_home, path, guard_home) = codex();
    let plan = preview("codex", &path, "/guard-home");
    let edited = [AFTER_GUARD, plan.after.as_slice()].concat();
    let mut rig = Rig::new();
    rig.replace = Box::new(|from, to| {
        Real.replace(from, to)?;
        if to == path {
            fs::write(to, &edited)?;
            return Err(Failure::Interrupt);
        }
        Ok(())
    });

    let error = apply_with(&rig, &plan, "codex", &path, &guard_home).expect_err("stopped");

    // Guard does not overwrite an edit it did not make, and keeps its copy.
    assert_eq!(error.reason, "interrupted");
    assert_eq!(fs::read(&path).expect("read"), edited);
    assert!(strays(path.parent().expect("parent")).is_empty());
    assert_eq!(kept_records(&guard_home, "codex").len(), 1);

    // Restoring removes only Guard's entry; the later edit stays.
    let restored = restore_with(&Real, "codex", &path, &guard_home).expect("restored");
    assert_eq!(restored.scope, "entry");
    let text = fs::read_to_string(&path).expect("read");
    assert!(text.contains("# The AI tool wrote this after Guard."));
    assert!(text.contains("# Hand-written; keep this comment."));
    assert!(!text.contains("cloud-actions"));
}

#[test]
fn an_interrupt_before_the_move_leaves_another_writers_settings_alone() {
    let (_home, path, guard_home) = codex();
    let plan = preview("codex", &path, "/guard-home");
    let mut rig = Rig::new();
    rig.replace = Box::new(|from, to| {
        if to != path {
            return Real.replace(from, to);
        }
        // Another apply wrote the same settings; this one never moved its file.
        fs::write(to, &plan.after)?;
        Err(Failure::Interrupt)
    });

    let error = apply_with(&rig, &plan, "codex", &path, &guard_home).expect_err("stopped");

    assert_eq!(error.reason, "interrupted");
    assert_eq!(fs::read(&path).expect("read"), plan.after);
    assert!(strays(path.parent().expect("parent")).is_empty());
    assert_eq!(kept_files(&guard_home, "codex"), 0);
}

#[test]
fn an_edit_made_while_guard_prepares_the_put_back_is_kept() {
    let (_home, path, guard_home) = codex();
    let before = fs::read(&path).expect("read");
    let plan = preview("codex", &path, "/guard-home");
    let edited = [
        b"# The AI tool wrote this while Guard was putting its file back.\n".as_slice(),
        plan.after.as_slice(),
    ]
    .concat();
    let interrupted = Cell::new(false);
    let mut rig = Rig::new();
    rig.replace = Box::new(|from, to| {
        Real.replace(from, to)?;
        if to == path && !interrupted.replace(true) {
            return Err(Failure::Interrupt);
        }
        Ok(())
    });
    rig.temporary = Box::new(|target, payload, mode| {
        let temporary = Real.write_temporary(target, payload, mode)?;
        if target == path && payload == before.as_slice() && interrupted.get() {
            fs::write(target, &edited)?;
        }
        Ok(temporary)
    });

    let error = apply_with(&rig, &plan, "codex", &path, &guard_home).expect_err("stopped");

    assert_eq!(error.reason, "interrupted");
    assert_eq!(fs::read(&path).expect("read"), edited);
    assert!(strays(path.parent().expect("parent")).is_empty());
    assert_eq!(kept_records(&guard_home, "codex").len(), 1);
}

#[test]
fn an_unknown_move_result_with_the_file_unchanged_keeps_no_copy() {
    let (_home, path, guard_home) = codex();
    let before = fs::read(&path).expect("read");
    let plan = preview("codex", &path, "/guard-home");
    let mut rig = Rig::new();
    rig.replace = interrupted_at(&path);
    // Guard cannot tell whether its file was moved (for example, the check itself failed).
    rig.moved = Box::new(|_, _, _| None);

    let error = apply_with(&rig, &plan, "codex", &path, &guard_home).expect_err("stopped");

    assert_eq!(error.reason, "interrupted");
    assert_eq!(fs::read(&path).expect("read"), before);
    assert_eq!(kept_files(&guard_home, "codex"), 0);
    assert!(restore_with(&Real, "codex", &path, &guard_home).is_none());
}

#[test]
fn an_unknown_move_result_with_the_file_changed_keeps_the_copy() {
    let (_home, path, guard_home) = codex();
    let plan = preview("codex", &path, "/guard-home");
    let mut rig = Rig::new();
    rig.replace = Box::new(|from, to| {
        Real.replace(from, to)?;
        if to == path {
            return Err(Failure::Interrupt);
        }
        Ok(())
    });
    rig.moved = Box::new(|_, _, _| None);

    let error = apply_with(&rig, &plan, "codex", &path, &guard_home).expect_err("stopped");

    // The file now holds Guard's settings and nothing proves they are Guard's,
    // so the copy stays for `restore`.
    assert_eq!(error.reason, "interrupted");
    assert_eq!(fs::read(&path).expect("read"), plan.after);
    assert_eq!(kept_records(&guard_home, "codex").len(), 1);
    let restored = restore_with(&Real, "codex", &path, &guard_home).expect("restored");
    assert_eq!(restored.scope, "file");
    assert_eq!(fs::read(&path).expect("read"), CODEX_SETTINGS.as_bytes());
}

#[cfg(unix)]
#[test]
fn a_settings_folder_guard_cannot_write_is_left_alone() {
    use std::os::unix::fs::PermissionsExt;

    /// Gives the folder its rights back, even when an assertion fails.
    struct Rights<'a>(&'a Path);
    impl Drop for Rights<'_> {
        fn drop(&mut self) {
            let _ = fs::set_permissions(self.0, fs::Permissions::from_mode(0o700));
        }
    }

    let (_home, path, guard_home) = codex();
    let before = fs::read(&path).expect("read");
    let plan = preview("codex", &path, "/guard-home");
    let folder = path.parent().expect("parent");
    let _rights = Rights(folder);
    fs::set_permissions(folder, fs::Permissions::from_mode(0o500)).expect("chmod");
    if fs::File::create(folder.join(".probe")).is_ok() {
        // Running with permission to write anywhere.
        return;
    }

    let error = apply_with(&Real, &plan, "codex", &path, &guard_home).expect_err("refused");

    assert_eq!(error.reason, "write_failed");
    assert_eq!(fs::read(&path).expect("read"), before);
    assert_eq!(kept_files(&guard_home, "codex"), 0);
}
