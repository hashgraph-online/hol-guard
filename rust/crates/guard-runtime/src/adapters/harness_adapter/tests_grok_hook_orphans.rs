//! The orphaned clients a repair retires, and the ones it keeps.

use super::*;

/// The interpreter-wrapped client older installs wrote.
fn old_client(guard_home: &Path, workspace: Option<&Path>) -> String {
    let hook = config(guard_home, None, workspace, PYTHON, false);
    let script = guard_home.join("managed/bounded-hooks/grok.py");
    line(&[PYTHON, "-I", &text(&script), &hook.to_string()])
}

fn native_replacement(guard_home: &Path, frozen: bool) -> String {
    let executable = if frozen { FROZEN_CLI } else { PYTHON };
    bridge(RUNTIME, &config(guard_home, None, None, executable, frozen))
}

#[test]
fn a_missing_client_is_orphaned_but_never_operational_evidence() {
    let rig = Rig::new();
    let ctx = rig.source();
    let stale = old_client(&rig.root.join("deleted"), None);
    assert!(is_missing(
        &ctx,
        &stale,
        &native_replacement(&rig.root.join("current"), false)
    ));
    assert!(!recognizes(&ctx, &stale, None));
}

#[test]
fn a_workspace_fallback_difference_does_not_keep_the_missing_global_client() {
    let rig = Rig::new();
    let ctx = rig.source();
    let replacement = bridge(
        RUNTIME,
        &config(
            &rig.root.join("new"),
            None,
            Some(&rig.workspace()),
            PYTHON,
            false,
        ),
    );
    assert!(is_missing(
        &ctx,
        &old_client(&rig.root.join("old"), None),
        &replacement
    ));
}

#[test]
fn a_frozen_replacement_retires_an_orphaned_client() {
    let rig = Rig::new();
    let ctx = rig.source();
    for frozen in [false, true] {
        let stale = old_client(&rig.root.join("old"), None);
        assert!(is_missing(
            &ctx,
            &stale,
            &native_replacement(&rig.root.join("new"), frozen)
        ));
    }
}

#[test]
fn a_client_that_is_not_an_orphan_is_kept() {
    let rig = Rig::new();
    let ctx = rig.source();
    let old = rig.root.join("old");
    let replacement = native_replacement(&rig.root.join("new"), false);
    assert!(is_missing(&ctx, &old_client(&old, None), &replacement));
    let kept = |stale: &str| !is_missing(&ctx, stale, &replacement);
    // The client still exists.
    let script = old.join("managed/bounded-hooks/grok.py");
    fs::create_dir_all(script.parent().unwrap()).unwrap();
    fs::write(&script, "# existing client\n").unwrap();
    assert!(kept(&old_client(&old, None)));
    fs::remove_file(&script).unwrap();
    let stale = old_client(&old, None);
    // Other shell syntax, another script, another harness or another home.
    assert!(kept(&format!("{stale} ; echo other")));
    assert!(kept(
        &stale.replace("bounded-hooks/grok.py", "bounded-hooks/user.py")
    ));
    assert!(kept(
        &stale.replace("\"harness\":\"grok\"", "\"harness\":\"other\"")
    ));
    let homed = stale.replace(
        "\"--harness\"",
        &format!("\"--home\",\"{}\",\"--harness\"", rig.root.display()),
    );
    assert!(kept(&homed));
    // Not a Python interpreter, and not the native bridge either.
    assert!(kept(&stale.replace(PYTHON, "/bin/echo")));
    assert!(kept("echo custom-check"));
    assert!(!is_missing(&ctx, &replacement, &replacement));
}
