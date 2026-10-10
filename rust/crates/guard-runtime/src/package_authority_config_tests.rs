use super::*;
use std::fs;

struct Dirs {
    root: PathBuf,
}

impl Dirs {
    fn new(label: &str) -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hol-guard-config-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("home")).unwrap();
        fs::create_dir_all(root.join("ws")).unwrap();
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
            &[],
        )
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
    let config = load_effective_guard_config(&missing, None, false, &[]).unwrap();
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
fn a_machine_managed_policy_source_fails_closed() {
    let dirs = Dirs::new("managed");
    let policy = dirs.root.join("managed-policy.json");
    let absent = dirs.root.join("absent.json");
    assert!(load_effective_guard_config(&dirs.home(), None, false, &[absent.clone()]).is_ok());
    fs::write(&policy, "{}").unwrap();
    let result = load_effective_guard_config(&dirs.home(), None, false, &[absent, policy]);
    assert!(result.is_err());
    assert_eq!(incomplete_lockfile_decision(&result), "block");
}

#[test]
fn canonical_workspace_requirement_rejects_relative_and_parent_paths() {
    let dirs = Dirs::new("canonical");
    let relative = Path::new("ws");
    assert!(load_effective_guard_config(&dirs.home(), Some(relative), true, &[]).is_err());
    let parent = dirs.workspace().join("..").join("ws");
    assert!(load_effective_guard_config(&dirs.home(), Some(&parent), true, &[]).is_err());
    assert!(load_effective_guard_config(&dirs.home(), Some(&dirs.workspace()), true, &[]).is_ok());
}

#[test]
fn resident_loader_reports_the_requested_guard_home() {
    let dirs = Dirs::new("loader");
    let result = ResidentConfigLoader.load_guard_config(&dirs.home(), None, false);
    // The production loader also probes this machine's managed policy paths;
    // when none exist it must agree with the pure loader.
    if let Ok(config) = result {
        assert_eq!(config.guard_home.as_deref(), Some(dirs.home().as_path()));
        assert_eq!(config.managed_policy_status, "absent");
    }
}
