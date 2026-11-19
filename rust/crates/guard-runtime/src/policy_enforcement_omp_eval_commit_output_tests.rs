#![cfg(unix)]
//! The output of an Oh My Pi `commit` draft. `PreToolUse` lets the eval run
//! once the local Git write proof settles the draft, and that proof reads the
//! agent's Git setup from the execution environment the hook stamped. The
//! `PostToolUse` recheck that classifies the eval's output must judge it the
//! same way, or the output falls to the floor for unrecognized operations
//! and is withheld after the commit already ran.

use super::*;

const DRAFT: &str = "const d = await commit.draft(); await d.take('README.md'); return await d.commit('Add notes', {body: ['Explain the retry window.']});";

fn git(dir: &std::path::Path, home: &std::path::Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

/// The packaged command program with no extension turned on or off, as a
/// fresh install publishes it.
fn packaged_controls() -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let mut binding: guard_contracts::NativeCommandControlBindingV1 =
        serde_json::from_value(json!({
            "schema": "guard.native-command-control-binding.v1",
            "program_digest": program.program_digest,
            "catalog_digest": program.catalog_digest,
            "trust_digest": program.trust_digest,
            "health": "protected",
            "revision": 1,
            "managed_revision": 0,
            "effective_digest": "",
            "layers": [{
                "schema_version": "1.0.0",
                "kind": "local-admin",
                "catalog_digest": program.catalog_digest,
                "global_lockdown": false,
                "controls": []
            }]
        }))
        .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    guard_command::native_command_controls::CompiledNativeCommandControls::new(&binding).unwrap()
}

fn environment(home: &str) -> guard_contracts::GuardExecutionEnvironmentV1 {
    let path = std::env::var("PATH").unwrap();
    let values = std::collections::BTreeMap::from([
        ("GIT_CONFIG_NOSYSTEM", "1".to_owned()),
        ("HOME", home.to_owned()),
        ("PATH", path.clone()),
    ]);
    guard_contracts::GuardExecutionEnvironmentV1 {
        path,
        environment_names: values.keys().map(|key| (*key).to_owned()).collect(),
        environment_digest: crate::guard_store_wfcap_frame::sha256_hex(
            &serde_json::to_vec(&values).unwrap(),
        ),
        home: Some(home.to_owned()),
        git_config_no_system: true,
        ..Default::default()
    }
}

#[test]
fn a_commit_draft_output_is_a_command_output_under_the_stamped_environment() {
    // Not under the system temp directory, which the write proof treats as
    // a shared location, nor inside this repository's own checkout on macOS.
    let base = if cfg!(target_os = "macos") {
        std::path::PathBuf::from("/tmp")
    } else {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target")
    };
    let root = base.join(format!(
        "guard-omp-eval-commit-output-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("project")).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let project = root.join("project");
    git(&project, &root, &["init", "-q", "-b", "main"]);
    git(&project, &root, &["config", "user.name", "Fixture"]);
    git(
        &project,
        &root,
        &["config", "user.email", "fixture@example.test"],
    );
    std::fs::write(project.join("README.md"), "notes\n").unwrap();
    git(&project, &root, &["add", "README.md"]);
    git(&project, &root, &["commit", "-q", "-m", "init"]);
    std::fs::write(project.join("README.md"), "notes\nretry window\n").unwrap();

    let mut request = post_request(json!({
        "tool_name": "eval",
        "tool_input": {"language": "js", "code": DRAFT},
        "tool_response": "Committed 1a2b3c4 Add notes\n"
    }));
    request.harness = "omp".into();
    request.home_dir = root.to_str().unwrap().into();
    request.guard_home = root.join(".hol-guard").to_str().unwrap().into();
    request.cwd = Some(project.to_str().unwrap().into());
    let stamped = environment(root.to_str().unwrap());
    let controls = packaged_controls();
    let classify = |request: &NativeHookRequestV1, environment| {
        super::super::eval_output::bounded_output_action_in(request, Some(&controls), environment)
    };
    assert_eq!(
        classify(&request, Some(&stamped)),
        Some(PreToolActionTypeV1::Command)
    );
    // Without the stamped environment the proof cannot settle the draft, so
    // the output keeps the unrecognized-operation floor.
    assert_eq!(classify(&request, None), None);
    // A hook Git would start is never settled, environment or not.
    let hook = project.join(".git/hooks/pre-commit");
    std::fs::write(&hook, "#!/bin/sh\nexit 0\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(classify(&request, Some(&stamped)), None);
    std::fs::remove_dir_all(root).unwrap();
}
