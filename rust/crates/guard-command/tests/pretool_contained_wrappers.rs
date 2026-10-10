#![cfg(unix)]

use guard_command::contained_execution::{
    complete_workspace_snapshot, read_verified_output, typescript_snapshot_inputs,
};
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

#[test]
fn captured_output_binds_current_bytes_and_rejects_links_and_directories() {
    let root = fixture();
    let output_path = root.join("output.bin");
    std::fs::write(&output_path, b"abc").unwrap();

    let output = read_verified_output(&output_path).unwrap();
    assert_eq!(output.size_bytes, 3);
    assert_eq!(
        output.sha256,
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    std::fs::write(&output_path, []).unwrap();
    let empty = read_verified_output(&output_path).unwrap();
    assert_eq!(empty.size_bytes, 0);
    assert_eq!(
        empty.sha256,
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let link = root.join("linked-output.bin");
    std::os::unix::fs::symlink(&output_path, &link).unwrap();
    assert_eq!(
        read_verified_output(&link).unwrap_err(),
        "output_not_regular"
    );
    assert_eq!(
        read_verified_output(&root).unwrap_err(),
        "output_not_regular"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn captured_output_accepts_the_byte_limit_and_rejects_one_byte_more() {
    let root = fixture();
    let output_path = root.join("bounded-output.bin");
    let output_file = std::fs::File::create(&output_path).unwrap();
    let limit = 8 * 1024 * 1024;
    output_file.set_len(limit).unwrap();
    assert_eq!(
        read_verified_output(&output_path).unwrap().size_bytes,
        limit
    );

    output_file.set_len(limit + 1).unwrap();
    assert_eq!(
        read_verified_output(&output_path).unwrap_err(),
        "output_too_large"
    );
    drop(output_file);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn package_snapshot_sorts_paths_and_invalidates_the_binding_after_content_changes() {
    let root = fixture();
    let workspace = root.join("project");
    let package = workspace.join("node_modules/runner");
    std::fs::create_dir_all(&package).unwrap();
    std::fs::write(package.join("b.js"), b"abc").unwrap();
    std::fs::write(package.join("a.js"), []).unwrap();

    let (before, inputs) = complete_workspace_snapshot(&workspace, &package).unwrap();
    assert_eq!(
        inputs
            .iter()
            .map(|input| (input.path.as_str(), input.sha256.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (
                "a.js",
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),
            (
                "b.js",
                "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            ),
        ]
    );

    std::fs::write(package.join("a.js"), b"abc").unwrap();
    let (after, changed_inputs) = complete_workspace_snapshot(&workspace, &package).unwrap();
    assert_ne!(before, after);
    assert_eq!(
        changed_inputs[0].sha256,
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn package_snapshot_rejects_links_and_protected_entries_instead_of_omitting_them() {
    let root = fixture();
    let workspace = root.join("project");
    let package = workspace.join("node_modules/runner");
    std::fs::create_dir_all(&package).unwrap();
    let outside = root.join("outside/source.js");
    std::fs::write(&outside, b"abc").unwrap();
    let link = package.join("source.js");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    assert!(complete_workspace_snapshot(&workspace, &package).is_err());

    std::fs::remove_file(link).unwrap();
    std::fs::create_dir(package.join(".guard")).unwrap();
    assert!(complete_workspace_snapshot(&workspace, &package).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn typescript_snapshot_rejects_external_and_symlinked_sources() {
    let root = fixture();
    let workspace = root.join("project");
    let package = workspace.join("node_modules/runner");
    std::fs::create_dir_all(&package).unwrap();
    std::fs::write(package.join("runner.js"), b"abc").unwrap();
    std::fs::write(workspace.join("entry.ts"), b"abc").unwrap();

    let (_, _, _, sources) =
        typescript_snapshot_inputs(&workspace, &package, &["entry.ts".to_owned()]).unwrap();
    assert_eq!(
        sources
            .iter()
            .map(|input| (input.path.as_str(), input.sha256.as_str()))
            .collect::<Vec<_>>(),
        vec![(
            "entry.ts",
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )]
    );

    std::fs::write(root.join("outside/entry.ts"), b"outside").unwrap();
    assert_eq!(
        typescript_snapshot_inputs(&workspace, &package, &["../outside/entry.ts".to_owned()])
            .unwrap_err(),
        "source_outside_workspace"
    );
    std::os::unix::fs::symlink(workspace.join("entry.ts"), workspace.join("linked.ts")).unwrap();
    assert_eq!(
        typescript_snapshot_inputs(&workspace, &package, &["linked.ts".to_owned()]).unwrap_err(),
        "source_not_regular"
    );
    std::fs::remove_dir_all(root).unwrap();
}
