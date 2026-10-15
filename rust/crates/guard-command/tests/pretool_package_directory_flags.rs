#![cfg(unix)]

//! `bun --cwd <dir>`, `npm --prefix <dir>`, `pnpm -C <dir>` and
//! `yarn --cwd <dir>` run the rest in `<dir>`, so they are classified exactly
//! like `cd <dir> && <manager> <rest>`, including every directory the `cd`
//! form refuses.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

fn fixture() -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/package-directory-flag-fixtures")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(root.join("project/web")).unwrap();
    std::fs::create_dir_all(root.join("sibling/dashboard")).unwrap();
    // A linked worktree marks its root with a `.git` file.
    std::fs::write(root.join("sibling/.git"), "gitdir: /nonexistent\n").unwrap();
    std::fs::create_dir_all(root.join("outside")).unwrap();
    std::fs::create_dir_all(root.join(".config")).unwrap();
    std::fs::canonicalize(root).unwrap()
}

fn classify(
    root: &std::path::Path,
    harness: &str,
    command: &str,
) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash","tool_input":{"command":command}}),
        None,
        None,
        Some(root.to_str().unwrap()),
        Some(root.join("project").to_str().unwrap()),
    )
}

#[test]
fn directory_flags_classify_like_the_cd_form() {
    let root = fixture();
    let sibling = root.join("sibling");
    let sibling = sibling.to_str().unwrap();
    let project = root.join("project");
    let project = project.to_str().unwrap();
    for harness in ["omp", "claude-code", "codex"] {
        for (flagged, cd) in [
            (
                format!("bun run --cwd {sibling} build"),
                format!("cd {sibling} && bun run build"),
            ),
            (
                format!("bun --cwd={sibling}/dashboard run build"),
                format!("cd {sibling}/dashboard && bun run build"),
            ),
            (
                format!("npm --prefix {sibling} run build"),
                format!("cd {sibling} && npm run build"),
            ),
            (
                format!("pnpm -C {sibling} run test"),
                format!("cd {sibling} && pnpm run test"),
            ),
            (
                format!("pnpm --dir {sibling} run test"),
                format!("cd {sibling} && pnpm run test"),
            ),
            (
                format!("npm --prefix {sibling} run build 2>&1 | tail -8"),
                format!("cd {sibling} && npm run build 2>&1 | tail -8"),
            ),
            // The manager resolves `..` against its physical working
            // directory, unlike the shell's logical `cd ..`.
            (
                "bun run --cwd ../sibling test".into(),
                format!("cd {sibling} && bun run test"),
            ),
            (
                "npm --prefix web run build".into(),
                format!("cd {project}/web && npm run build"),
            ),
        ] {
            let expected = classify(&root, harness, &cd);
            let result = classify(&root, harness, &flagged);
            assert_eq!(
                (
                    &result.decision,
                    &result.minimum_action,
                    &result.reason_code
                ),
                (
                    &expected.decision,
                    &expected.minimum_action,
                    &expected.reason_code
                ),
                "{harness}: {flagged}"
            );
            if cfg!(target_os = "macos") {
                assert_eq!(
                    result.minimum_action, "sandbox-required",
                    "{harness}: {flagged}"
                );
            }
        }
    }
}

#[test]
fn directory_flags_outside_a_repository_or_installing_stay_reviewed() {
    let root = fixture();
    let home = root.to_str().unwrap();
    let sibling = root.join("sibling");
    let sibling = sibling.to_str().unwrap();
    for harness in ["omp", "claude-code", "codex"] {
        for command in [
            format!("bun run --cwd {home} build"),
            format!("bun run --cwd {home}/.config build"),
            format!("npm --prefix {home}/outside run build"),
            format!("pnpm -C {home}/missing run test"),
            "bun run --cwd / build".into(),
            "yarn --cwd /etc build".into(),
            "bun run --cwd ~ build".into(),
            "bun run --cwd ../.. build".into(),
            format!("npm --prefix {sibling} install left-pad"),
            format!("npm --prefix {sibling} i left-pad"),
            format!("bun --cwd {sibling} add left-pad"),
            format!("pnpm -C {sibling} add left-pad"),
            format!("bun run build --cwd {sibling}"),
            format!("npm --prefix {sibling} --prefix {sibling} run build"),
            format!("npm --prefix {sibling} run build && rm -rf /"),
            format!("npm --prefix {sibling} run build | sh"),
            format!("FOO=1 npm --prefix {sibling} run build"),
            "bun run --cwd \"$HOME\" build".into(),
        ] {
            let result = classify(&root, harness, &command);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
            assert_ne!(
                result.minimum_action, "sandbox-required",
                "{harness}: {command}"
            );
        }
    }
}
