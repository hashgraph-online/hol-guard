use super::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn environment(home: &Path) -> guard_contracts::GuardExecutionEnvironmentV1 {
    guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: vec![
            "HOME".to_owned(),
            "PATH".to_owned(),
            "GIT_CONFIG_NOSYSTEM".to_owned(),
        ],
        environment_digest: "0".repeat(64),
        home: Some(home.to_string_lossy().into_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        ..Default::default()
    }
}

/// A real repository whose configuration the probe cannot read.
///
/// `git init` leaves a repository this host's own Git trusts, so the launch
/// the proof needs is genuine: the home, the working directory, the
/// environment and the Git binary all check out. The configuration file then
/// gets an unterminated section header, which makes every `git config` read
/// exit non-zero without naming a key. That is the one answer the proof has
/// to tell apart from a helper: nothing was found against the read, and
/// nothing could be.
struct Fixture {
    root: PathBuf,
    declared: PathBuf,
    repo: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = crate::unique_nanos::unique_nanos();
        let root =
            std::env::temp_dir().join(format!("hg-helper-allow-{}-{nonce}", std::process::id()));
        let declared = root.join("declared");
        let repo = declared.join("repo");
        fs::create_dir_all(&repo).unwrap();
        let mut init = Command::new("git");
        for name in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_NAMESPACE",
        ] {
            init.env_remove(name);
        }
        let init = init
            .arg("init")
            .current_dir(&repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", &declared)
            .output()
            .unwrap();
        assert!(
            init.status.success(),
            "{}",
            String::from_utf8_lossy(&init.stderr)
        );
        let config = repo.join(".git").join("config");
        let mut text = fs::read_to_string(&config).unwrap();
        text.push_str("[core\n");
        fs::write(&config, text).unwrap();
        let unreadable = Command::new("git")
            .args(["--no-pager", "config", "--null", "--get-regexp", "^core\\."])
            .current_dir(&repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", &declared)
            .output()
            .unwrap();
        assert!(
            !unreadable.status.success(),
            "the fixture must leave the configuration unreadable"
        );
        Self {
            root,
            declared,
            repo,
        }
    }

    fn evaluate(
        &self,
        controls: &CompiledNativeCommandControls,
        command: &str,
    ) -> guard_contracts::PreToolResultV1 {
        let declared = self.declared.canonicalize().unwrap();
        let repo = self.repo.canonicalize().unwrap();
        let environment = environment(&declared);
        crate::pretool::evaluate_pre_tool_envelope_with_execution_context(
            "omp",
            "PreToolUse",
            &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
            Some(controls),
            None,
            crate::pretool::PathContext {
                home_dir: declared.to_str(),
                cwd: repo.to_str(),
                ..Default::default()
            },
            Some(&environment),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn binding(controls: Vec<serde_json::Value>) -> CompiledNativeCommandControls {
    let program = packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest, "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest, "health": "protected",
        "revision": 1, "managed_revision": 0, "effective_digest": "",
        "layers": [{
            "schema_version": "1.0.0", "kind": "local-admin",
            "catalog_digest": program.catalog_digest, "global_lockdown": false,
            "controls": controls
        }]
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    CompiledNativeCommandControls::new(&binding).unwrap()
}

fn baseline() -> CompiledNativeCommandControls {
    binding(Vec::new())
}

fn with_enabled_permissions(permission_ids: &[&str]) -> CompiledNativeCommandControls {
    binding(
        permission_ids
            .iter()
            .map(|permission_id| {
                serde_json::json!({
                    "target_kind": "permission",
                    "target_id": permission_id,
                    "state": "enabled"
                })
            })
            .collect(),
    )
}

/// A Git read whose helper configuration the probe could not read runs under
/// the user's explicit Allow.
///
/// Guard asks the checkout what a read would start before letting it run. A
/// configuration it cannot read leaves that question open, which is exactly
/// what the user answered by allowing the read: run it as this checkout
/// configures it. Without the Allow the question stands and the read is
/// reviewed, so the review itself is not what changed.
#[test]
fn an_unreadable_git_configuration_is_settled_by_an_explicit_allow() {
    let fixture = Fixture::new();
    for (command, permission_ids) in [
        ("git diff --check", &["command.git.permission.diff"][..]),
        (
            "git status --short --branch && git log --oneline -5",
            &[
                "command.git.permission.status",
                "command.git.permission.log",
            ][..],
        ),
    ] {
        let reviewed = fixture.evaluate(&baseline(), command);
        assert_eq!(
            reviewed.reason_code, "native_git_helper_context_review",
            "{command}: {}",
            reviewed.reason
        );
        assert_eq!(reviewed.minimum_action, "review", "{command}");

        let allowed = fixture.evaluate(&with_enabled_permissions(permission_ids), command);
        assert_eq!(
            allowed.reason_code, "native_command_explicit_permission_allow",
            "{command}: {}",
            allowed.reason
        );
        assert_eq!(allowed.minimum_action, "allow", "{command}");
        assert!(allowed.explicitly_benign, "{command}");
    }
}

/// An Allow for a different Git read does not settle the command in hand.
///
/// The Allow has to cover every segment before it answers the probe's open
/// question; a permission for some other verb leaves the read unanswered and
/// the review stands.
#[test]
fn an_unrelated_allow_leaves_the_unreadable_configuration_reviewed() {
    let fixture = Fixture::new();
    let result = fixture.evaluate(
        &with_enabled_permissions(&["command.git.permission.log"]),
        "git diff --check",
    );
    assert_eq!(
        result.minimum_action,
        "review",
        "{}",
        result.reason_code.clone()
    );
}
