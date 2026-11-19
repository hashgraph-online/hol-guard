#![cfg(unix)]
//! A `for` loop whose body hands jq a filter such as
//! `{n:.number,checks:[.c[]?|select(.conclusion!=null)]}`.
//!
//! The unroller refuses a body that may rebind the loop variable. It looked
//! for a binding builtin in every run of letters, so `select` inside the
//! quoted filter, next to a bare `n`, read as zsh's `select n`, and the loop
//! kept a review its unrolled list did not get. A builtin is now read from the
//! words the shell builds.

use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;

fn allowed(harness: &str, command: &str, root: &std::path::Path) -> bool {
    let cwd = root.join("work");
    let answer = evaluate_pre_tool_envelope_with_execution_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            home_dir: root.to_str(),
            cwd: cwd.to_str(),
            ..PathContext::default()
        },
        None,
    );
    answer.minimum_action == "allow"
}

#[test]
fn a_builtin_named_in_a_quoted_filter_does_not_stop_the_unroll() {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/for-loop-quoted-builtin")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    for directory in ["work", ".ssh"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::write(root.join("work/a.json"), "{\"items\":[]}\n").unwrap();
    std::fs::write(root.join("work/b.json"), "{\"items\":[]}\n").unwrap();
    std::fs::write(root.join("work/names.txt"), "../.ssh/id_ed25519\n").unwrap();
    std::fs::write(root.join(".ssh/id_ed25519"), "key\n").unwrap();
    let pr_filter = "{n:.number,state:.state,head:.headRefOid[0:12],files:[.files[].path],\
                     checks:[.statusCheckRollup[]?|select(.conclusion!=null)|\
                     {name:(.name//.context),c:.conclusion}]}";
    for harness in ["cursor", "claude-code", "codex", "zcode"] {
        for (command, expected) in [
            (
                format!(
                    "for n in 7688 7519; do gh pr view \"$n\" --repo o/r --json \
                     number,state,headRefOid,files,statusCheckRollup 2>/dev/null | \
                     jq -c '{pr_filter}'; done"
                ),
                true,
            ),
            (
                "for f in a.json b.json; do jq -c '.items[] | select(.f != null)' \"$f\"; done"
                    .to_owned(),
                true,
            ),
            (
                "for f in a.json b.json; do grep -c 'read f' \"$f\"; done".to_owned(),
                true,
            ),
            (
                "for f in a.json b.json; do grep -c 'f$' \"$f\"; done".to_owned(),
                true,
            ),
            // A builtin the shell runs still rebinds the loop variable.
            (
                "for f in a.json; do 're'ad f < names.txt; cat \"$f\"; done".to_owned(),
                false,
            ),
            (
                "for f in a.json; do eval 'f=../.ssh/id_ed25519'; cat \"$f\"; done".to_owned(),
                false,
            ),
            (
                "for f in a.json; do trap 'read f < names.txt' DEBUG; cat \"$f\"; done".to_owned(),
                false,
            ),
            (
                "for f in a.json; do $'\\x72ead' f < names.txt; cat \"$f\"; done".to_owned(),
                false,
            ),
            // Each step is still judged on its own.
            (
                "for f in a.json ../.ssh/id_ed25519; do jq '.[] | select(.f)' \"$f\"; done"
                    .to_owned(),
                false,
            ),
        ] {
            assert_eq!(
                allowed(harness, &command, &root),
                expected,
                "{harness}: {command}"
            );
        }
    }
}
