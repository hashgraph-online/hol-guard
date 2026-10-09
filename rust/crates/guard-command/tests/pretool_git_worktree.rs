#![cfg(unix)]

#[path = "support/git_helper_fixture.rs"]
mod fixture;

use fixture::{evaluate_pre_tool_envelope_with_context, FixtureCleanup};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn worktree_controls(
    state: Option<&str>,
) -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let controls = state.map_or_else(Vec::new, |state| {
        vec![json!({
            "target_kind":"permission",
            "target_id":"command.git.permission.worktree",
            "state":state
        })]
    });
    let mut binding: guard_contracts::NativeCommandControlBindingV1 =
        serde_json::from_value(json!({
            "schema":"guard.native-command-control-binding.v1",
            "program_digest":program.program_digest,
            "catalog_digest":program.catalog_digest,
            "trust_digest":program.trust_digest,
            "health":"protected",
            "revision":1,
            "managed_revision":0,
            "effective_digest":"",
            "layers":[{
                "schema_version":"1.0.0",
                "kind":"local-admin",
                "catalog_digest":program.catalog_digest,
                "global_lockdown":false,
                "controls":controls
            }]
        }))
        .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    guard_command::native_command_controls::CompiledNativeCommandControls::new(&binding).unwrap()
}

fn git_extension_controls(
    state: &str,
) -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let mut binding: guard_contracts::NativeCommandControlBindingV1 =
        serde_json::from_value(json!({
            "schema":"guard.native-command-control-binding.v1",
            "program_digest":program.program_digest,
            "catalog_digest":program.catalog_digest,
            "trust_digest":program.trust_digest,
            "health":"protected",
            "revision":1,
            "managed_revision":0,
            "effective_digest":"",
            "layers":[{
                "schema_version":"1.0.0",
                "kind":"local-admin",
                "catalog_digest":program.catalog_digest,
                "global_lockdown":false,
                "controls":[{
                    "target_kind":"extension",
                    "target_id":"command.git",
                    "state":state
                }]
            }]
        }))
        .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    guard_command::native_command_controls::CompiledNativeCommandControls::new(&binding).unwrap()
}

fn evaluate(
    repository: &Path,
    controls: &guard_command::native_command_controls::CompiledNativeCommandControls,
    command: &str,
) -> guard_contracts::PreToolResultV1 {
    let home = repository.parent().unwrap();
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(controls),
        None,
        home.to_str(),
        repository.to_str(),
    )
}

fn evaluate_with_path(
    repository: &Path,
    controls: &guard_command::native_command_controls::CompiledNativeCommandControls,
    command: &str,
    path: &str,
) -> guard_contracts::PreToolResultV1 {
    use sha2::{Digest, Sha256};

    let home = repository.parent().unwrap();
    let environment = std::collections::BTreeMap::from([
        ("PATH", path.to_owned()),
        ("GIT_CONFIG_NOSYSTEM", "1".to_owned()),
        ("HOME", home.to_str().unwrap().to_owned()),
    ]);
    let context = guard_contracts::GuardExecutionEnvironmentV1 {
        path: path.to_owned(),
        environment_names: environment.keys().map(|key| (*key).to_owned()).collect(),
        environment_digest: hex::encode(Sha256::digest(serde_json::to_vec(&environment).unwrap())),
        home: Some(home.to_str().unwrap().to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
    };
    guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(controls),
        None,
        guard_command::pretool::PathContext {
            home_dir: home.to_str(),
            cwd: repository.to_str(),
            cdpath_unset: false,
        },
        Some(&context),
    )
}

fn git(repository: &Path, arguments: &[&str]) {
    let home = repository.parent().unwrap();
    assert!(std::process::Command::new("git")
        .arg("-C")
        .arg(repository)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .env_remove("GIT_AUTHOR_NAME")
        .env_remove("GIT_AUTHOR_EMAIL")
        .env_remove("GIT_COMMITTER_NAME")
        .env_remove("GIT_COMMITTER_EMAIL")
        .args(arguments)
        .status()
        .unwrap()
        .success());
}

#[test]
fn native_worktree_proof_admits_only_fresh_local_branch_creation() {
    let root_directory = if cfg!(target_os = "macos") {
        std::path::PathBuf::from("/tmp")
    } else {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target")
    };
    let root = std::fs::canonicalize(root_directory).unwrap().join(format!(
        "guard-git-worktree-proof-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let repository = root.join("repository");
    let _cleanup = FixtureCleanup(root.clone());
    std::fs::create_dir_all(&repository).unwrap();
    git(&repository, &["init", "--quiet"]);
    git(&repository, &["config", "user.name", "Guard Fixture"]);
    git(
        &repository,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    std::fs::write(repository.join("tracked.txt"), "fixture\n").unwrap();
    git(&repository, &["add", "tracked.txt"]);
    git(&repository, &["commit", "--quiet", "-m", "fixture"]);

    let enabled = fixture::github_controls("enabled");
    let destination = root.join("sibling-child");
    let command = format!(
        "git worktree add --quiet {} -b fixture-worktree HEAD",
        destination.display()
    );
    let admitted = evaluate(&repository, &enabled, &command);
    assert_eq!(admitted.minimum_action, "allow", "{}", admitted.reason_code);
    assert_eq!(admitted.reason_code, "native_exact_safe_worktree_add");
    assert_eq!(
        admitted
            .command_extensions
            .as_ref()
            .unwrap()
            .observations
            .iter()
            .find(|observation| observation.rule_id == "command.git.worktree")
            .unwrap()
            .effective_segment_indexes,
        vec![0]
    );

    git(
        &repository,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "fixture-worktree",
            destination.to_str().unwrap(),
            "HEAD",
        ],
    );
    assert!(destination.is_dir());

    git(
        &repository,
        &["update-ref", "refs/remotes/origin/local", "HEAD"],
    );
    let remote_destination = root.join("remote-child");
    let remote_command = format!(
        "git worktree add --quiet -b remote-worktree {} origin/local",
        remote_destination.display()
    );
    let remote_admitted = evaluate(&repository, &enabled, &remote_command);
    assert_eq!(remote_admitted.minimum_action, "allow", "{remote_command}");
    git(
        &repository,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "remote-worktree",
            remote_destination.to_str().unwrap(),
            "origin/local",
        ],
    );
    assert!(remote_destination.is_dir());

    let compound_destination = root.join("compound-child");
    let compound_command = format!(
        "cd {} && git worktree add {} -b compound-worktree HEAD 2>&1 | tail -3",
        repository.display(),
        compound_destination.display()
    );
    let compound = evaluate(&repository, &enabled, &compound_command);
    assert_eq!(compound.minimum_action, "allow", "{compound_command}");

    let config_tripwire = root.join("config-tripwire");
    let tripwire_command = format!("!touch {}", config_tripwire.display());
    std::fs::write(
        root.join(".gitconfig"),
        format!(
            "[alias]\n\tunused = {tripwire_command}\n[core]\n\teditor = {tripwire_command}\n[credential]\n\thelper = {tripwire_command}\n[diff \"unused\"]\n\texternal = {tripwire_command}\n[mergetool \"unused\"]\n\tcmd = {tripwire_command}\n"
        ),
    )
    .unwrap();

    let sleep_compound_destination = root.join("sleep-compound-child");
    let sleep_compound_command = format!(
        "sleep 0.01; cd {} && git worktree add {} -b sleep-compound-worktree HEAD",
        repository.display(),
        sleep_compound_destination.display()
    );
    let sleep_compound = evaluate(&repository, &enabled, &sleep_compound_command);
    assert_eq!(
        sleep_compound.minimum_action, "allow",
        "{sleep_compound_command}"
    );
    assert!(!config_tripwire.exists());

    #[cfg(target_os = "macos")]
    if let Ok(relative) = root.strip_prefix("/private/tmp") {
        let aliased_root = Path::new("/tmp").join(relative);
        let aliased_repository = aliased_root.join("repository");
        let aliased_destination = aliased_root.join("sleep-alias-child");
        let aliased_command = format!(
            "sleep 0.01; cd {} && git worktree add {} -b sleep-alias-worktree HEAD",
            aliased_repository.display(),
            aliased_destination.display()
        );
        let aliased = evaluate(&repository, &enabled, &aliased_command);
        assert_eq!(aliased.minimum_action, "allow", "{aliased_command}");
        assert_eq!(aliased.reason_code, "native_exact_safe_worktree_add");
    }

    let config_destination = root.join("config-child");
    let config_command = format!(
        "git worktree add --quiet {} -b config-worktree HEAD",
        config_destination.display()
    );
    let config_allowed = evaluate(&repository, &enabled, &config_command);
    assert_eq!(config_allowed.minimum_action, "allow", "{config_command}");
    git(
        &repository,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "config-worktree",
            config_destination.to_str().unwrap(),
            "HEAD",
        ],
    );
    assert!(config_destination.is_dir());
    assert!(!config_tripwire.exists());

    let hook_config_tripwire = root.join("hook-config-tripwire");
    std::fs::write(
        root.join(".gitconfig"),
        format!(
            "[hook \"worktree-setup\"]\n\tevent = post-checkout\n\tcommand = !touch {}\n",
            hook_config_tripwire.display()
        ),
    )
    .unwrap();
    let hook_config_destination = root.join("hook-config-child");
    let hook_config_command = format!(
        "git worktree add --quiet {} -b hook-config-worktree HEAD",
        hook_config_destination.display()
    );
    let hook_config = evaluate(&repository, &enabled, &hook_config_command);
    assert_ne!(hook_config.minimum_action, "allow", "{hook_config_command}");
    assert!(!hook_config_tripwire.exists());
    std::fs::write(
        root.join(".gitconfig"),
        format!(
            "[alias]\n\tunused = {tripwire_command}\n[core]\n\teditor = {tripwire_command}\n[credential]\n\thelper = {tripwire_command}\n[diff \"unused\"]\n\texternal = {tripwire_command}\n[mergetool \"unused\"]\n\tcmd = {tripwire_command}\n"
        ),
    )
    .unwrap();

    let unrelated_hook_tripwire = root.join("unrelated-hook-tripwire");
    let pre_commit = repository.join(".git/hooks/pre-commit");
    std::fs::write(
        &pre_commit,
        format!("#!/bin/sh\ntouch {}\n", unrelated_hook_tripwire.display()),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&pre_commit).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&pre_commit, permissions).unwrap();
    let unrelated_hook_destination = root.join("unrelated-hook-child");
    let unrelated_hook_command = format!(
        "git worktree add --quiet {} -b unrelated-hook-worktree HEAD",
        unrelated_hook_destination.display()
    );
    let unrelated_hook_allowed = evaluate(&repository, &enabled, &unrelated_hook_command);
    assert_eq!(
        unrelated_hook_allowed.minimum_action, "allow",
        "{unrelated_hook_command}"
    );
    git(
        &repository,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "unrelated-hook-worktree",
            unrelated_hook_destination.to_str().unwrap(),
            "HEAD",
        ],
    );
    assert!(unrelated_hook_destination.is_dir());
    assert!(!unrelated_hook_tripwire.exists());

    let missing_cwd_command = format!(
        "sleep 0.01; cd {} && git worktree add {} -b missing-cwd-worktree HEAD",
        root.join("missing-cwd").display(),
        root.join("missing-cwd-child").display()
    );
    let missing_cwd = evaluate(&repository, &enabled, &missing_cwd_command);
    assert_ne!(missing_cwd.minimum_action, "allow", "{missing_cwd_command}");

    for command in [
        format!(
            "sleep 0.01; cd {} && git worktree add --force {} -b forced-sleep-worktree HEAD",
            repository.display(),
            root.join("forced-sleep-child").display()
        ),
        format!(
            "sleep 0.01; cd {} && git worktree add {} -b $BRANCH HEAD",
            repository.display(),
            root.join("dynamic-sleep-child").display()
        ),
        format!(
            "sleep 0.01 | cd {} && git worktree add {} -b piped-sleep-worktree HEAD",
            repository.display(),
            root.join("piped-sleep-child").display()
        ),
        format!(
            "GIT_CONFIG_GLOBAL={} git worktree add --quiet {} -b env-worktree HEAD",
            root.join(".gitconfig").display(),
            root.join("env-child").display()
        ),
    ] {
        let result = evaluate(&repository, &enabled, &command);
        assert_ne!(result.minimum_action, "allow", "{command}");
    }

    let head_command = compound_command.replace("tail -3", "head -3");
    let head = evaluate(&repository, &enabled, &head_command);
    assert_ne!(head.minimum_action, "allow");

    let shadow_bin = root.join("shadow-bin");
    std::fs::create_dir_all(&shadow_bin).unwrap();
    let shadow_tail = shadow_bin.join("tail");
    std::fs::write(&shadow_tail, "#!/bin/sh\nexit 0\n").unwrap();
    let mut permissions = std::fs::metadata(&shadow_tail).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&shadow_tail, permissions).unwrap();
    let shadow_path = format!(
        "{}:{}",
        shadow_bin.display(),
        std::env::var("PATH").unwrap()
    );
    let shadowed_tail = evaluate_with_path(&repository, &enabled, &compound_command, &shadow_path);
    assert_ne!(shadowed_tail.minimum_action, "allow");

    let existing_destination_command = format!(
        "git worktree add --quiet -b existing-destination {} HEAD",
        destination.display()
    );
    let existing_destination = evaluate(&repository, &enabled, &existing_destination_command);
    assert_ne!(
        existing_destination.minimum_action, "allow",
        "{existing_destination_command}"
    );

    for parent in [".ssh", ".aws", ".hol-support", ".agents"] {
        std::fs::create_dir_all(root.join(parent)).unwrap();
    }
    let sensitive_destinations = [
        root.join(".ssh/native-worktree"),
        root.join(".aws/native-worktree"),
        root.join(".hol-support/native-worktree"),
        root.join(".agents/native-worktree"),
        root.join(".env"),
        root.join(".private-worktree"),
    ];
    for (index, destination) in sensitive_destinations.iter().enumerate() {
        let command = format!(
            "git worktree add --quiet {} -b sensitive-worktree-{index} HEAD",
            destination.display()
        );
        let result = evaluate(&repository, &enabled, &command);
        assert_ne!(result.minimum_action, "allow", "{command}");
        assert!(!destination.exists(), "{destination:?}");
    }

    let symlink_parent_target = root.join("symlink-parent-target");
    let symlink_parent = root.join("symlink-parent");
    std::fs::create_dir_all(&symlink_parent_target).unwrap();
    std::os::unix::fs::symlink(&symlink_parent_target, &symlink_parent).unwrap();
    let symlink_parent_destination = symlink_parent.join("native-worktree");
    let symlink_parent_command = format!(
        "git worktree add --quiet {} -b symlink-parent-worktree HEAD",
        symlink_parent_destination.display()
    );
    let symlink_parent_result = evaluate(&repository, &enabled, &symlink_parent_command);
    assert_ne!(
        symlink_parent_result.minimum_action, "allow",
        "{symlink_parent_command}"
    );
    assert!(!symlink_parent_destination.exists());

    for command in [
        "git worktree add --quiet --force -b blocked-force force-child HEAD",
        "git worktree add --quiet -b fixture-worktree second-child HEAD",
        "git worktree add --quiet -b second-child missing-ref HEAD~99",
        "git worktree add --quiet -b second-child -- filtered-child HEAD",
    ] {
        let result = evaluate(&repository, &enabled, command);
        assert_ne!(result.minimum_action, "allow", "{command}");
    }

    let hooks_path_command = format!(
        "git -c core.hooksPath={} worktree add --quiet -b second-child config-child HEAD",
        root.join("custom-hooks").display()
    );
    let hooks_path_result = evaluate(&repository, &enabled, &hooks_path_command);
    assert_ne!(
        hooks_path_result.minimum_action, "allow",
        "{hooks_path_command}"
    );

    let symlink_target = root.join("outside");
    std::fs::create_dir_all(&symlink_target).unwrap();
    std::os::unix::fs::symlink(&symlink_target, repository.join("symlink-child")).unwrap();
    let symlink = evaluate(
        &repository,
        &enabled,
        "git worktree add --quiet -b second-child symlink-child HEAD",
    );
    assert_ne!(symlink.minimum_action, "allow");

    let hook = repository.join(".git/hooks/post-checkout");
    std::fs::write(&hook, "#!/bin/sh\nexit 0\n").unwrap();
    let mut permissions = std::fs::metadata(&hook).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&hook, permissions).unwrap();
    let hooked = evaluate(
        &repository,
        &enabled,
        "git worktree add --quiet -b third-child hooked-child HEAD",
    );
    assert_ne!(hooked.minimum_action, "allow");
    std::fs::remove_file(&hook).unwrap();

    let extension_disabled = git_extension_controls("disabled");
    let extension_result = evaluate(&repository, &extension_disabled, &command);
    assert_eq!(extension_result.minimum_action, "block");
    assert!(extension_result.reason_code.ends_with("disabled"));

    git(&repository, &["config", "credential.helper", "!false"]);
    let helper = evaluate(
        &repository,
        &enabled,
        "git worktree add --quiet -b helper-worktree helper-child HEAD",
    );
    assert_ne!(helper.minimum_action, "allow");
    git(&repository, &["config", "--unset", "credential.helper"]);

    git(
        &repository,
        &["config", "remote.origin.partialCloneFilter", "blob:none"],
    );
    let partial_clone = evaluate(
        &repository,
        &enabled,
        "git worktree add --quiet -b partial-worktree partial-child HEAD",
    );
    assert_ne!(partial_clone.minimum_action, "allow");

    let disabled = worktree_controls(Some("disabled"));
    let denied = evaluate(&repository, &disabled, &command);
    assert_eq!(denied.minimum_action, "block");
    assert_eq!(denied.reason_code, "native_command_permission_disabled");
}
