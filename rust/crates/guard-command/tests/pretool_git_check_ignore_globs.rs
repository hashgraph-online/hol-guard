#![cfg(unix)]

//! `git check-ignore` with a shell glob prints names, never file content.

use crate::pretool_git_session_ops::session;

#[test]
fn check_ignore_over_a_directory_glob_is_a_proven_read() {
    let session = session("check-ignore-globs");
    let docs = session.primary.join("docs");
    std::fs::create_dir_all(&docs).unwrap();
    std::fs::write(docs.join("guide.md"), "guide\n").unwrap();
    std::fs::write(docs.join("notes.md"), "notes\n").unwrap();
    for command in [
        "git check-ignore -v docs/*",
        "git check-ignore -v docs/*.md node_modules",
        "git check-ignore -q -- *",
    ] {
        let result = session.evaluate_at(command, &session.primary);
        assert_eq!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
    for command in [
        // Without `--` a leading wildcard could expand to an option-named file.
        "git check-ignore -v *",
        "git check-ignore -v .env*",
        "git check-ignore -v .ssh/*",
        "git check-ignore -v ../*",
    ] {
        let result = session.evaluate_at(command, &session.primary);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}
