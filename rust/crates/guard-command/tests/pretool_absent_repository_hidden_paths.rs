#![cfg(unix)]

//! Probing for a hidden folder of a repository by its full path.
//!
//! Agents check for build output before reading it, as
//! `ls ~/work/app/.next/tsconfig.tsbuildinfo 2>/dev/null` does before the
//! first build. When `.next` was not there yet, the probe went to review if
//! it spelled the full path, while the same probe spelled from inside the
//! checkout (`ls .next/tsconfig.tsbuildinfo`) was allowed. The missing path
//! prints `No such file or directory` and nothing else, so it now gets the
//! screens a listing of the same path would get if it existed: a repository
//! work tree below home, and no agent state, credential store or environment
//! file among the names.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn a_missing_hidden_build_folder_named_by_its_full_path_is_allowed() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/absent-repository-hidden-fixtures")
        .join(format!("fixture-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for directory in [
        "work/app/.git",
        "work/app/src",
        "work/sib/.git",
        "work/plain",
    ] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    let root = std::fs::canonicalize(&root).unwrap();
    std::fs::write(root.join("work/app/src/one.txt"), "ordinary fixture\n").unwrap();
    // A link in the existing prefix that leaves the repository is screened
    // where it leads, not where it is spelled.
    std::os::unix::fs::symlink(root.join("work/plain"), root.join("work/app/out")).unwrap();
    std::os::unix::fs::symlink(&root, root.join("work/app/up")).unwrap();
    let home = root.to_str().unwrap();
    let app = root.join("work/app");
    let app = app.to_str().unwrap();
    let sib = root.join("work/sib");
    let sib = sib.to_str().unwrap();
    let plain = root.join("work/plain");
    let plain = plain.to_str().unwrap();
    for harness in ["omp", "claude-code", "codex"] {
        for (command, allowed) in [
            ("ls .next/tsconfig.tsbuildinfo".to_owned(), true),
            (
                format!("ls {app}/.next/tsconfig.tsbuildinfo 2>/dev/null"),
                true,
            ),
            ("ls ~/work/app/.next/tsconfig.tsbuildinfo".to_owned(), true),
            (format!("ls -la {app}/.turbo"), true),
            (format!("ls {app}/src/.svelte-kit/output"), true),
            (format!("ls {sib}/.next/BUILD_ID"), true),
            // Agent state, credential stores and environment files keep the
            // review a listing of them gets.
            (format!("ls {app}/.agents/notes"), false),
            (format!("ls {app}/.aws/config"), false),
            (format!("ls {app}/.env.local"), false),
            (format!("ls {app}/.next/.env.production"), false),
            // A missing hidden name that is not build output, such as where a
            // tool keeps a login, or a package's own dot folder, stays
            // reviewed: the answer says whether the tool is set up.
            (format!("ls {app}/.aws-session"), false),
            (format!("ls {app}/.cache/build"), false),
            (format!("ls {app}/node_modules/.husky"), false),
            // Outside a repository the hidden name keeps its review.
            (format!("ls {plain}/.next/BUILD_ID"), false),
            (format!("ls {app}/out/.next/BUILD_ID"), false),
            (format!("ls {app}/up/.toolstate/x"), false),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                None,
                None,
                Some(home),
                Some(app),
            );
            assert_eq!(
                result.minimum_action == "allow",
                allowed,
                "{harness}: {command} => {} / {}",
                result.minimum_action,
                result.reason_code
            );
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}
