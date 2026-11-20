use super::*;

use crate::managed_policy_registry::{RegistryAuthority, RegistryRead};
use std::fs;

use crate::managed_policy_load::MachineSystem;

struct Dirs {
    root: PathBuf,
}

impl Dirs {
    fn new(label: &str) -> Self {
        let nonce = crate::unique_nanos::unique_nanos();
        let root = std::env::temp_dir().join(format!(
            "hol-guard-config-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("home")).unwrap();
        fs::create_dir_all(root.join("ws")).unwrap();
        // A canonical workspace has no symlinked ancestor, and macOS's
        // temporary directory sits below the `/var` -> `/private/var` link.
        let root = fs::canonicalize(&root).unwrap();
        Self { root }
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn workspace(&self) -> PathBuf {
        self.root.join("ws")
    }

    fn load(&self, workspace: bool) -> EvalResult<GuardConfig> {
        let workspace_dir = self.workspace();
        load_effective_guard_config(
            &self.home(),
            workspace.then_some(&workspace_dir),
            false,
            &self.unmanaged(),
        )
    }

    /// A machine root this test owns and never populates: no profile and no
    /// cache, which is an unmanaged machine.
    fn unmanaged(&self) -> ManagedPolicySource {
        ManagedPolicySource {
            system: MachineSystem::Other,
            policy_path: None,
            write_cache: false,
            machine_root: Some(self.root.join("machine")),
            registry: RegistryAuthority::Native,
        }
    }

    /// A machine whose policy is the document at `path`.
    fn managed(&self, path: &Path) -> ManagedPolicySource {
        ManagedPolicySource {
            policy_path: Some(path.to_path_buf()),
            ..self.unmanaged()
        }
    }
}

impl Drop for Dirs {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// The decision rule in `finalize_incomplete_lockfile_evaluation`.
fn incomplete_lockfile_decision(result: &EvalResult<GuardConfig>) -> &'static str {
    match result {
        Ok(config) if !matches!(config.security_level.as_str(), "strict" | "paranoid") => "ask",
        _ => "block",
    }
}

#[test]
fn missing_config_is_the_default_and_allows_an_approvable_pause() {
    let dirs = Dirs::new("missing");
    let result = dirs.load(true);
    let config = result.as_ref().unwrap();
    assert_eq!(config.security_level, "balanced");
    assert_eq!(config.protection_posture, "protected");
    assert!(!config.protection_posture_explicit);
    assert_eq!(incomplete_lockfile_decision(&result), "ask");
}

#[test]
fn missing_guard_home_directory_is_the_default() {
    let dirs = Dirs::new("nohome");
    let missing = dirs.root.join("never-created");
    let config = load_effective_guard_config(&missing, None, false, &dirs.unmanaged()).unwrap();
    assert_eq!(config.security_level, "balanced");
    assert!(!missing.exists());
}

#[test]
fn explicit_default_config_allows_an_approvable_pause() {
    let dirs = Dirs::new("balanced");
    fs::write(
        dirs.home().join("config.toml"),
        "security_level = \"gentle\"\n",
    )
    .unwrap();
    let result = dirs.load(false);
    assert_eq!(result.as_ref().unwrap().security_level, "gentle");
    assert_eq!(incomplete_lockfile_decision(&result), "ask");
}

#[test]
fn strict_and_paranoid_configs_stay_blocked() {
    for level in ["strict", "paranoid"] {
        let dirs = Dirs::new(level);
        fs::write(
            dirs.home().join("config.toml"),
            format!("security_level = \"{level}\"\n"),
        )
        .unwrap();
        let result = dirs.load(true);
        let config = result.as_ref().unwrap();
        assert_eq!(config.security_level, level);
        assert_eq!(config.protection_posture, "extra_careful");
        assert_eq!(incomplete_lockfile_decision(&result), "block");
    }
}

#[test]
fn unknown_security_level_falls_back_to_the_default_like_python() {
    let dirs = Dirs::new("unknown-level");
    fs::write(
        dirs.home().join("config.toml"),
        "security_level = \"lax\"\n",
    )
    .unwrap();
    assert_eq!(dirs.load(false).unwrap().security_level, "balanced");
}

#[test]
fn malformed_config_is_an_error_and_stays_blocked() {
    let dirs = Dirs::new("malformed");
    fs::write(dirs.home().join("config.toml"), "security_level = [\n").unwrap();
    let result = dirs.load(false);
    assert!(result.is_err());
    assert_eq!(incomplete_lockfile_decision(&result), "block");
}

#[test]
fn non_utf8_and_oversized_configs_are_errors() {
    let dirs = Dirs::new("bytes");
    fs::write(dirs.home().join("config.toml"), [0xff, 0xfe, 0xfd]).unwrap();
    assert!(dirs.load(false).is_err());
    fs::write(
        dirs.home().join("config.toml"),
        vec![b'#'; MAX_CONFIG_BYTES + 1],
    )
    .unwrap();
    assert!(dirs.load(false).is_err());
}

#[test]
fn config_that_is_a_directory_is_an_error() {
    let dirs = Dirs::new("directory");
    fs::create_dir(dirs.home().join("config.toml")).unwrap();
    assert!(dirs.load(false).is_err());
}

#[cfg(unix)]
#[test]
fn symlinked_config_file_is_an_error() {
    let dirs = Dirs::new("symlink");
    let target = dirs.root.join("elsewhere.toml");
    fs::write(&target, "security_level = \"relaxed\"\n").unwrap();
    std::os::unix::fs::symlink(&target, dirs.home().join("config.toml")).unwrap();
    assert!(dirs.load(false).is_err());
}

#[test]
fn malformed_workspace_override_is_an_error() {
    let dirs = Dirs::new("bad-workspace");
    fs::write(dirs.workspace().join(".hol-guard.toml"), "not = [valid\n").unwrap();
    let result = dirs.load(true);
    assert!(result.is_err());
    assert_eq!(incomplete_lockfile_decision(&result), "block");
}

#[test]
fn workspace_override_cannot_weaken_or_strengthen_policy_keys() {
    let dirs = Dirs::new("workspace-precedence");
    fs::write(
        dirs.home().join("config.toml"),
        "security_level = \"strict\"\n",
    )
    .unwrap();
    fs::write(
        dirs.workspace().join(".hol-guard.toml"),
        "security_level = \"relaxed\"\nmode = \"observe\"\nprotection_posture = \"watch\"\n\
         [risk_actions]\npackage_script = \"allow\"\n",
    )
    .unwrap();
    let config = dirs.load(true).unwrap();
    assert_eq!(config.security_level, "strict");
    assert_eq!(config.protection_posture, "extra_careful");
    assert!(!config.protection_posture_explicit);
    assert_eq!(config.risk_actions, Some(Default::default()));

    fs::write(dirs.home().join("config.toml"), "").unwrap();
    fs::write(
        dirs.workspace().join(".ai-plugin-scanner-guard.toml"),
        "security_level = \"strict\"\n",
    )
    .unwrap();
    assert_eq!(dirs.load(true).unwrap().security_level, "balanced");
}

#[test]
fn home_posture_and_risk_actions_are_normalized_like_python() {
    let dirs = Dirs::new("posture");
    fs::write(
        dirs.home().join("config.toml"),
        "mode = \"observe\"\nprotection_posture = \" Extra-Careful \"\n\
         [risk_actions]\npackage_script = \"ask\"\nnetwork_egress = { action = \"bogus\" }\nunknown_key = \"block\"\n\
         [harness_risk_actions.codex]\npersistence = \"block\"\n\
         [harness_risk_actions.empty]\nunknown_key = \"block\"\n",
    )
    .unwrap();
    let config = dirs.load(false).unwrap();
    assert_eq!(config.protection_posture, "extra_careful");
    assert!(config.protection_posture_explicit);
    let risk = config.risk_actions.unwrap();
    assert_eq!(
        risk.get("package_script").map(String::as_str),
        Some("review")
    );
    assert_eq!(
        risk.get("network_egress").map(String::as_str),
        Some("require-reapproval")
    );
    assert!(!risk.contains_key("unknown_key"));
    let harness = config.harness_risk_actions.unwrap();
    assert_eq!(harness.len(), 1);
    assert_eq!(harness["codex"]["persistence"], "block");
}

#[test]
fn observe_mode_derives_the_watch_posture() {
    let dirs = Dirs::new("observe");
    fs::write(dirs.home().join("config.toml"), "mode = \"observe\"\n").unwrap();
    assert_eq!(dirs.load(false).unwrap().protection_posture, "watch");
}

#[test]
fn nested_config_merge_replaces_inherited_actions() {
    let base: Value = serde_json::json!({"a": {"action": "block", "keep": 1}, "b": 1});
    let over: Value = serde_json::json!({"a": {"default_action": "allow"}, "b": 2});
    let merged = merge_config_payload(base.as_object().unwrap(), over.as_object().unwrap());
    assert_eq!(
        Value::Object(merged),
        serde_json::json!({"a": {"default_action": "allow", "keep": 1}, "b": 2})
    );
}

#[test]
fn a_managed_requirement_composes_over_the_local_configuration() {
    let dirs = Dirs::new("managed");
    fs::write(
        dirs.home().join("config.toml"),
        "security_level = \"relaxed\"\n",
    )
    .unwrap();
    let policy = dirs.root.join("managed-policy.json");
    fs::write(
        &policy,
        serde_json::json!({
            "schemaVersion": "hol-guard-mdm-policy.v1",
            "settings": {"security_level": "paranoid"},
            "lockedSettings": ["security_level"],
        })
        .to_string(),
    )
    .unwrap();

    let result = load_effective_guard_config(&dirs.home(), None, false, &dirs.managed(&policy));
    let config = result.as_ref().unwrap();

    // The local file asked for `relaxed`; a locked managed setting cannot be
    // weakened, so the effective level is the administrator's.
    assert_eq!(config.security_level, "paranoid");
    assert_eq!(config.managed_policy_status, "active");
    assert_eq!(
        config.managed_locked_settings,
        vec!["security_level".to_owned()]
    );
    assert!(config.managed_policy_hash.is_some());
    assert_eq!(incomplete_lockfile_decision(&result), "block");
}

#[test]
fn an_unreadable_machine_policy_applies_the_fail_closed_floor() {
    let dirs = Dirs::new("managed-unreadable");
    fs::write(
        dirs.home().join("config.toml"),
        "security_level = \"relaxed\"\n",
    )
    .unwrap();
    let source = ManagedPolicySource {
        system: MachineSystem::Windows,
        registry: RegistryAuthority::Fixed(RegistryRead::Denied),
        ..dirs.unmanaged()
    };

    let result = load_effective_guard_config(&dirs.home(), None, false, &source);
    let config = result.as_ref().unwrap();

    // Configured machine authority this runtime cannot read is not an
    // unmanaged machine: the floor stands in for the policy.
    assert_eq!(config.managed_policy_status, "inaccessible");
    assert_eq!(config.security_level, "paranoid");
    assert!(config
        .managed_locked_settings
        .contains(&"default_action".to_owned()));
    assert_eq!(incomplete_lockfile_decision(&result), "block");
}

#[test]
fn an_invalid_machine_policy_fails_closed_rather_than_reading_as_absent() {
    let dirs = Dirs::new("managed-invalid");
    let policy = dirs.root.join("managed-policy.json");
    fs::write(&policy, "{}").unwrap();

    let result = load_effective_guard_config(&dirs.home(), None, false, &dirs.managed(&policy));
    let config = result.as_ref().unwrap();

    assert_eq!(config.managed_policy_status, "invalid");
    assert_eq!(config.security_level, "paranoid");
    assert_eq!(incomplete_lockfile_decision(&result), "block");
}

#[test]
fn canonical_workspace_requirement_rejects_relative_and_parent_paths() {
    let dirs = Dirs::new("canonical");
    let relative = Path::new("ws");
    let unmanaged = dirs.unmanaged();
    assert!(load_effective_guard_config(&dirs.home(), Some(relative), true, &unmanaged).is_err());
    // `join` folds `..` into a Windows verbatim path, so the step is spelled out.
    let parent = PathBuf::from(format!(
        "{}{sep}..{sep}ws",
        dirs.workspace().display(),
        sep = std::path::MAIN_SEPARATOR
    ));
    assert!(load_effective_guard_config(&dirs.home(), Some(&parent), true, &unmanaged).is_err());
    assert!(
        load_effective_guard_config(&dirs.home(), Some(&dirs.workspace()), true, &unmanaged)
            .is_ok()
    );
}

#[test]
fn resident_loader_reports_the_requested_guard_home() {
    let dirs = Dirs::new("loader");
    let result = ResidentConfigLoader.load_guard_config(&dirs.home(), None, false);
    // The production loader also reads this machine's own managed policy. An
    // unmanaged host reports no policy; a Windows host cannot read the registry
    // key, which is a fail-closed status rather than an absent one.
    if let Ok(config) = result {
        assert_eq!(config.guard_home.as_deref(), Some(dirs.home().as_path()));
        assert!(
            matches!(
                config.managed_policy_status.as_str(),
                "absent" | "inaccessible"
            ),
            "{}",
            config.managed_policy_status
        );
    }
}
