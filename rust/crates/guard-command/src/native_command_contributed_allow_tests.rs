use super::CompiledNativeCommandControls;
use guard_contracts::{
    NativeCommandControlBindingV1, NativeExtensionControlLayerV1, NativeExtensionControlV1,
    NATIVE_COMMAND_CONTROL_BINDING_SCHEMA,
};
use std::fs;
use std::path::{Path, PathBuf};

/// Controls with the contributed `command.ollama` extension and every
/// permission it declares enabled, or with nothing enabled.
fn controls(enabled: bool) -> CompiledNativeCommandControls {
    let ids: &[(&str, &str)] = if enabled {
        &[
            ("extension", "command.ollama"),
            ("permission", "command.ollama.permission.push"),
            ("permission", "command.ollama.permission.rm"),
        ]
    } else {
        &[]
    };
    let ids: Vec<_> = ids
        .iter()
        .map(|(kind, id)| ((*kind).to_owned(), (*id).to_owned()))
        .collect();
    controls_for(&ids)
}

/// Controls with the contributed `command.ollama` extension and the packaged
/// `command.git` extension, with every permission each declares enabled.
fn ollama_and_git() -> CompiledNativeCommandControls {
    let program = crate::native_command_program::authored_test_support::full_program();
    let mut ids = vec![
        ("extension".to_owned(), "command.ollama".to_owned()),
        ("extension".to_owned(), "command.git".to_owned()),
    ];
    ids.extend(
        program
            .extensions
            .iter()
            .filter(|extension| {
                matches!(
                    extension.extension_id.as_str(),
                    "command.ollama" | "command.git"
                )
            })
            .flat_map(|extension| extension.permissions.iter())
            .map(|permission| ("permission".to_owned(), permission.permission_id.clone())),
    );
    controls_for(&ids)
}

fn controls_for(ids: &[(String, String)]) -> CompiledNativeCommandControls {
    let program = crate::native_command_program::authored_test_support::full_program();
    let mut binding = NativeCommandControlBindingV1 {
        active_security_digest: None,
        schema: NATIVE_COMMAND_CONTROL_BINDING_SCHEMA.into(),
        authority: None,
        program_digest: program.program_digest.clone(),
        catalog_digest: program.catalog_digest.clone(),
        trust_digest: program.trust_digest.clone(),
        health: "protected".into(),
        revision: 1,
        managed_revision: 0,
        effective_digest: String::new(),
        layers: vec![NativeExtensionControlLayerV1 {
            schema_version: "1.0.0".into(),
            kind: "local-admin".into(),
            catalog_digest: program.catalog_digest.clone(),
            global_lockdown: false,
            controls: ids
                .iter()
                .map(|(kind, id)| NativeExtensionControlV1 {
                    target_kind: kind.clone(),
                    target_id: id.clone(),
                    state: "enabled".into(),
                })
                .collect(),
        }],
    };
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    CompiledNativeCommandControls::for_program(&binding, program).unwrap()
}

struct Fixture(PathBuf);

impl Fixture {
    /// A project holding an ordinary file, a secret, and a link to the secret.
    fn new() -> Self {
        // Under /tmp rather than the per-user temporary directory, which
        // Guard treats as an allowed location of its own.
        let root = PathBuf::from(format!(
            "/tmp/guard-contributed-allow-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        let project = root.join("home/project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("README.md"), "fixture\n").unwrap();
        fs::write(project.join(".env"), "SYNTHETIC_ONLY=fixture\n").unwrap();
        std::os::unix::fs::symlink(project.join(".env"), project.join("alias")).unwrap();
        Self(root.canonicalize().unwrap())
    }

    fn evaluate(&self, controls: &CompiledNativeCommandControls, command: &str) -> String {
        let home = self.0.join("home");
        let cwd: &Path = &home.join("project");
        crate::pretool::evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
            Some(controls),
            None,
            home.to_str(),
            cwd.to_str(),
        )
        .minimum_action
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A contributed extension's allowed action passes inside a compound when
/// every other step passes as a command of its own.
///
/// The reads after the allowed step used to lose their proof because an
/// earlier step was not proven safe by Guard itself, so the compound asked
/// although each of its steps passed alone.
#[test]
fn an_allowed_contributed_action_passes_with_reads_after_it() {
    let fixture = Fixture::new();
    let allowed = controls(true);
    for command in [
        "ollama rm stale-model",
        "ls -la",
        "cat README.md",
        "ollama rm stale-model && ls -la && cat README.md",
        "ollama rm stale-model && cat README.md",
        "ollama rm stale-model; ls -la",
    ] {
        assert_eq!(fixture.evaluate(&allowed, command), "allow", "{command}");
    }
}

/// A step that does not pass alone keeps the compound from passing, and the
/// action itself still needs the user's Allow.
#[test]
fn a_step_that_fails_alone_still_holds_the_compound() {
    let fixture = Fixture::new();
    let allowed = controls(true);
    for command in [
        "cat alias",
        "ollama rm stale-model && cat alias",
        "ollama rm stale-model && cat .env",
    ] {
        assert_ne!(fixture.evaluate(&allowed, command), "allow", "{command}");
    }
    let unset = controls(false);
    assert_ne!(
        fixture.evaluate(&unset, "ollama rm stale-model && ls -la && cat README.md"),
        "allow"
    );
}

/// `org/app` below a fresh home, one commit deep, with a GitHub `origin` whose
/// `main` is that commit, so `git worktree add ... origin/main` needs no
/// network.
fn repository() -> (Fixture, PathBuf, PathBuf) {
    let root = PathBuf::from(format!(
        "/tmp/guard-contributed-allow-worktree-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    let home = root.join("home");
    let repository = home.join("org/app");
    fs::create_dir_all(&repository).unwrap();
    let fixture = Fixture(root.canonicalize().unwrap());
    let home = fixture.0.join("home");
    let repository = home.join("org/app");
    let git = |arguments: &[&str]| {
        assert!(std::process::Command::new("git")
            .arg("-C")
            .arg(&repository)
            .env("HOME", &home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_COMMON_DIR")
            .env_remove("GIT_OBJECT_DIRECTORY")
            .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
            .args(arguments)
            .status()
            .unwrap()
            .success());
    };
    git(&["init", "--quiet", "--initial-branch=main"]);
    git(&["config", "user.name", "Guard Fixture"]);
    git(&["config", "user.email", "guard-fixture@example.invalid"]);
    git(&[
        "remote",
        "add",
        "origin",
        "https://github.com/example-org/app-portal.git",
    ]);
    fs::write(repository.join("README.md"), "fixture\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "--quiet", "-m", "fixture"]);
    git(&["update-ref", "refs/remotes/origin/main", "HEAD"]);
    (fixture, home, repository)
}

/// Evaluate `command` as a hook does, with the shell's execution environment
/// stamped, so the Git configuration probe can answer for the session.
fn evaluate_in(
    home: &Path,
    cwd: &Path,
    controls: &CompiledNativeCommandControls,
    command: &str,
) -> guard_contracts::PreToolResultV1 {
    use sha2::{Digest, Sha256};
    let path = std::env::var("PATH").unwrap();
    let home_text = home.to_str().unwrap().to_owned();
    let environment = std::collections::BTreeMap::from([
        ("GIT_CONFIG_NOSYSTEM", "1".to_owned()),
        ("HOME", home_text.clone()),
        ("PATH", path.clone()),
    ]);
    let execution = guard_contracts::GuardExecutionEnvironmentV1 {
        path,
        environment_names: environment.keys().map(|key| (*key).to_owned()).collect(),
        environment_digest: hex::encode(Sha256::digest(serde_json::to_vec(&environment).unwrap())),
        home: Some(home_text),
        git_config_no_system: true,
        ..Default::default()
    };
    crate::pretool::evaluate_pre_tool_envelope_with_execution_context(
        "omp",
        "PreToolUse",
        &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
        Some(controls),
        None,
        crate::pretool::PathContext {
            literal_words: &[],
            guard_home: None,
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
            cdpath_unset: false,
            rustup_override_absent: false,
            cargo_config_inert: false,
            npm_config_inert: false,
            pip_config_inert: false,
            python_environment_inert: false,
            shell_home_matches: false,
            ripgrep_config_absent: false,
            gem_config_absent: false,
            http_config_absent: false,
            openssl_config_absent: false,
            psql_environment: Default::default(),
            creates_nothing: false,
        },
        Some(&execution),
    )
}

const ADD: &str = "git worktree add -b ext-review ../ext-wt origin/main";

/// An allowed contributed action runs inside the worktree the same command
/// creates, as it runs anywhere else.
///
/// Entering the new checkout used to be covered only when Git and GitHub
/// steps followed it, so the allowed action after the `cd` left the `cd`
/// uncovered, and the Git read after the action was probed nowhere and kept
/// a configuration review the user's Allow could not answer.
#[test]
fn an_allowed_contributed_action_runs_inside_a_new_worktree() {
    let (_fixture, home, repository) = repository();
    let allowed = ollama_and_git();
    let mut failures = Vec::new();
    for command in [
        format!("{ADD} && cd ../ext-wt && ollama rm stale-model && git status --short"),
        format!("{ADD} && cd ../ext-wt && ollama rm stale-model"),
        format!("{ADD} && cd ../ext-wt && git status --short && ollama rm stale-model"),
        format!("{ADD}; cd ../ext-wt && ollama rm stale-model && git log --oneline -1"),
    ] {
        let result = evaluate_in(&home, &repository, &allowed, &command);
        if result.minimum_action != "allow" {
            failures.push(format!(
                "{command}: {} {}",
                result.minimum_action, result.reason_code
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Only the action the user allowed may follow the `cd`. A path read, a step
/// that can rewrite the new checkout, or the same chain without the Allow
/// keeps its review.
#[test]
fn a_new_worktree_entry_covers_only_allowed_actions() {
    let (_fixture, home, repository) = repository();
    let allowed = ollama_and_git();
    for command in [
        format!("{ADD} && cd ../ext-wt && ollama rm stale-model && cat README.md"),
        format!("{ADD} && cd ../ext-wt && ollama rm stale-model && ls -la"),
        format!("{ADD} && cd ../ext-wt && ollama rm stale-model && cp README.md copy.md"),
        format!("{ADD} && cd ../ext-wt && ollama rm stale-model && npm install"),
        format!("{ADD} && cd ../ext-wt && ollama rm stale-model && ./ollama rm stale-model"),
        format!("{ADD} && cd ../ext-other && ollama rm stale-model && git status --short"),
        format!("{ADD} || cd ../ext-wt && ollama rm stale-model && git status --short"),
    ] {
        let result = evaluate_in(&home, &repository, &allowed, &command);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
    let unset = controls(false);
    let command = format!("{ADD} && cd ../ext-wt && ollama rm stale-model && git status --short");
    assert_ne!(
        evaluate_in(&home, &repository, &unset, &command).minimum_action,
        "allow"
    );
}

/// A permitted action whose meaning the `cd` could change keeps the entry
/// reviewed even though the same step passes on its own: a path operand is
/// judged against the shell's directory but opened in the new checkout, and
/// an environment prefix or redirect reaches past the action the permission
/// names.
#[test]
fn a_permitted_action_the_entry_could_change_keeps_its_review() {
    let (_fixture, home, repository) = repository();
    let allowed = ollama_and_git();
    for step in [
        "ollama rm ../stale-model",
        "ollama rm ./stale-model",
        "ollama rm ~/stale-model",
        "OLLAMA_HOST=127.0.0.1:9 ollama rm stale-model",
        "ollama rm stale-model > removed.txt",
        // A bare name the new checkout holds: alone it names nothing here,
        // after the `cd` it names the checked-out file.
        "ollama rm README.md",
        "ollama rm --name=README.md",
        // A case-insensitive file system opens `readme.md` as `README.md`,
        // and Windows drops trailing dots and spaces.
        "ollama rm readme.md",
        "ollama rm README.md.",
        // An attached value may follow any letter of a short cluster.
        "ollama rm -vfREADME.md stale-model",
        "ollama rm key=README.md",
        "ollama rm -f README.md stale-model",
        // Names the comparison cannot model count as held: Unicode, an
        // NTFS stream, a Windows short name.
        "ollama rm r\u{e9}adme.md",
        "ollama rm README.md:stream",
        "ollama rm README~1.MD",
    ] {
        let alone = evaluate_in(&home, &repository, &allowed, step);
        assert_eq!(
            alone.minimum_action, "allow",
            "{step}: {}",
            alone.reason_code
        );
        let command = format!("{ADD} && cd ../ext-wt && {step} && git status --short");
        let result = evaluate_in(&home, &repository, &allowed, &command);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

/// A bare name the checkout does not hold keeps the entry allowed, and a
/// step before it that can rewrite the checkout, in any letter case, takes
/// that proof away.
#[test]
fn a_bare_name_counts_only_against_the_unchanged_checkout() {
    let (_fixture, home, repository) = repository();
    let allowed = ollama_and_git();
    let command = format!("{ADD} && cd ../ext-wt && ollama rm stale-model && git status --short");
    let result = evaluate_in(&home, &repository, &allowed, &command);
    assert_eq!(result.minimum_action, "allow", "{}", result.reason_code);
    for step in ["CHMOD -R 777 .", "Touch stale-model"] {
        let command = format!(
            "{ADD} && cd ../ext-wt && {step} && ollama rm stale-model && git status --short"
        );
        let result = evaluate_in(&home, &repository, &allowed, &command);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}
