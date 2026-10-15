//! The client argv a frozen Guard writes for Cursor, beside the
//! interpreter argv a source install writes.

use std::time::Instant;

use super::tests::{client_text, HOOK_ARGV};
use super::*;

#[test]
fn a_frozen_guard_launcher_names_the_same_client() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("hol-guard-cursor-hook.py");
    std::fs::write(&script, client_text("/g", HOOK_ARGV, "3")).unwrap();
    let script = script.to_str().unwrap().to_owned();
    let argv = |launcher: &str, mode: &str| {
        [launcher, mode, &script, EVENT_FLAG, "preToolUse"].map(str::to_owned)
    };
    let started = Instant::now();
    for (launcher, mode) in [
        ("/usr/bin/python3", "-I"),
        ("/bin/hol-guard", FROZEN_CLIENT_COMMAND),
    ] {
        let client = client(&argv(launcher, mode), started).unwrap();
        assert_eq!(
            (client.guard_home.as_str(), client.event.as_str()),
            ("/g", "preToolUse")
        );
    }
    for mode in ["-c", "__guard-bounded-hook", ""] {
        assert!(
            client(&argv("/bin/hol-guard", mode), started).is_none(),
            "{mode}"
        );
    }
}
