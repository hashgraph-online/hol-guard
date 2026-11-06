#![cfg(unix)]

//! `bun --cwd <dir>`, `npm --prefix <dir>`, `pnpm -C <dir>` and
//! `yarn --cwd <dir>` run the rest in `<dir>`, so they are classified exactly
//! like `cd <dir> && <manager> <rest>`, including every directory the `cd`
//! form refuses.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

fn fixture() -> std::path::PathBuf {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/package-directory-flag-fixtures")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(root.join("project/web")).unwrap();
    std::fs::create_dir_all(root.join("sibling/dashboard")).unwrap();
    // A linked worktree marks its root with a `.git` file.
    std::fs::write(root.join("sibling/.git"), "gitdir: /nonexistent\n").unwrap();
    std::fs::create_dir_all(root.join("outside")).unwrap();
    std::fs::create_dir_all(root.join(".config")).unwrap();
    for directory in ["project", "sibling"] {
        package(&root.join(directory));
    }
    std::fs::canonicalize(root).unwrap()
}

/// Script bodies the narrow node sinks run, with the local Vite entrypoint.
fn package(directory: &std::path::Path) {
    let scripts = r#"{"scripts":{"build":"vite build","test":"node --test"}}"#;
    std::fs::write(directory.join("package.json"), scripts).unwrap();
    let entry = directory.join("node_modules/vite/bin/vite.js");
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(entry, "").unwrap();
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
            // A leading assignment belongs to the manager call, so it is
            // carried into the `cd` form rather than ending the peel.
            (
                format!("FOO=1 npm --prefix {sibling} run build"),
                format!("cd {sibling} && FOO=1 npm run build"),
            ),
            (
                format!("PORT=3000 CI=1 bun --cwd {sibling} run build"),
                format!("cd {sibling} && PORT=3000 CI=1 bun run build"),
            ),
            (
                "PORT=3000 npm --prefix web run build".into(),
                format!("cd {project}/web && PORT=3000 npm run build"),
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
            format!("PATH=/tmp npm --prefix {sibling} run build"),
            format!("FOO=\"1\" npm --prefix {sibling} run build"),
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

/// An inert assignment the shell applies to the manager steers nothing, so
/// the flagged run keeps the decision it has without the prefix. A name that
/// does steer the run keeps the owners' floor, prefix or not.
#[test]
fn an_inert_assignment_keeps_the_runs_own_decision() {
    let root = fixture();
    let sibling = root.join("sibling");
    let sibling = sibling.to_str().unwrap();
    for harness in ["omp", "claude-code", "codex"] {
        for (plain, prefixed) in [
            (
                format!("npm --prefix {sibling} run build"),
                format!("CI=1 npm --prefix {sibling} run build"),
            ),
            (
                format!("pnpm -C {sibling} run test"),
                format!("CI=1 LANG=C pnpm -C {sibling} run test"),
            ),
        ] {
            let expected = classify(&root, harness, &plain);
            let result = classify(&root, harness, &prefixed);
            assert_eq!(
                (&result.decision, &result.minimum_action),
                (&expected.decision, &expected.minimum_action),
                "{harness}: {prefixed}"
            );
        }
        // A port number names no host, so the prefixed run keeps the
        // decision the same run has without it.
        for (plain, prefixed) in [
            (
                format!("npm --prefix {sibling} run build"),
                format!("PORT=3000 npm --prefix {sibling} run build"),
            ),
            (
                format!("bun run --cwd {sibling} build"),
                format!("APP_PORT=3027 POSTGRES_PORT=55477 bun run --cwd {sibling} build"),
            ),
        ] {
            let expected = classify(&root, harness, &plain);
            let result = classify(&root, harness, &prefixed);
            assert_eq!(
                (&result.decision, &result.minimum_action),
                (&expected.decision, &expected.minimum_action),
                "{harness}: {prefixed}"
            );
        }
        // A value that names a host moves the connection off this machine,
        // so it still takes the owners' floor the `cd` form takes.
        for value in ["db.example.test:5432", "99999"] {
            let steered = classify(
                &root,
                harness,
                &format!("PORT={value} npm --prefix {sibling} run build"),
            );
            let cd_form = classify(
                &root,
                harness,
                &format!("cd {sibling} && PORT={value} npm run build"),
            );
            assert_eq!(
                (&steered.decision, &steered.minimum_action),
                (&cd_form.decision, &cd_form.minimum_action),
                "{harness}: PORT={value}"
            );
        }
    }
}
