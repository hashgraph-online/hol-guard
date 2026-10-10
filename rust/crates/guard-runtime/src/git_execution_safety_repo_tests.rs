//! Real-Git repository vectors for the resident git-execution-safety checks.
use guard_contracts::{
    GitExecutionSafetyCheckV1 as Check, GitExecutionSafetyRequestV1,
    GIT_EXECUTION_SAFETY_REQUEST_SCHEMA,
};
use std::path::{Path, PathBuf};
use std::process::Command;

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn temp_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-git-safety-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::canonicalize(root).unwrap()
}

fn git(repository: &Path, home: &Path, arguments: &[&str]) {
    let mut command = Command::new("git");
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_NAMESPACE",
        "GIT_CONFIG",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "XDG_CONFIG_HOME",
    ] {
        command.env_remove(name);
    }
    let status = command
        .args(arguments)
        .current_dir(repository)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

fn caller_groups() -> Vec<u32> {
    let output = Command::new("id").arg("-G").output().unwrap();
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .filter_map(|group| group.parse().ok())
        .collect()
}

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    repository: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root = temp_root(label);
        let home = root.join("home");
        let repository = root.join("repo");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&repository).unwrap();
        git(
            &repository,
            &home,
            &["init", "--quiet", "--initial-branch=main"],
        );
        git(
            &repository,
            &home,
            &["commit", "--quiet", "--allow-empty", "-m", "init"],
        );
        git(
            &repository,
            &home,
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/example/project.git",
            ],
        );
        Self {
            root,
            home,
            repository,
        }
    }

    fn config(&self, key: &str, value: &str) {
        git(&self.repository, &self.home, &["config", key, value]);
    }

    fn request(&self, check: Check) -> GitExecutionSafetyRequestV1 {
        let environment = [
            ("PATH", std::env::var("PATH").unwrap_or_default()),
            ("HOME", self.home.to_string_lossy().into_owned()),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
        GitExecutionSafetyRequestV1 {
            schema: GIT_EXECUTION_SAFETY_REQUEST_SCHEMA.to_owned(),
            request_id: "test".to_owned(),
            check,
            cwd: self.repository.to_string_lossy().into_owned(),
            home: self.home.to_string_lossy().into_owned(),
            account_home: Some(self.home.to_string_lossy().into_owned()),
            groups: caller_groups(),
            environment,
            git_binary: None,
            git_path: None,
            arguments: Vec::new(),
            branch: Some("main".to_owned()),
            reference: None,
        }
    }

    fn allowed(&self, check: Check) -> bool {
        crate::git_execution_safety_checks::decide(&self.request(check)).allowed
    }

    fn host_git_is_trusted(&self) -> bool {
        let trusted = self.allowed(Check::ResolveBinary);
        if !trusted {
            eprintln!("SKIPPED: host git is not in a trusted root");
        }
        trusted
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn repository_checks_follow_the_retired_python_behaviour() {
    let fixture = Fixture::new("checks");
    if !fixture.host_git_is_trusted() {
        // The host Git lives in a user-controlled root; the proof stays closed.
        assert!(!fixture.allowed(Check::StatusConfig));
        return;
    }
    assert!(fixture.allowed(Check::StatusConfig));
    assert!(fixture.allowed(Check::ObjectQuery));
    assert!(fixture.allowed(Check::WorktreeAdd));
    assert!(fixture.allowed(Check::FetchOrigin));
    assert!(fixture.allowed(Check::PushOrigin));

    // Credential helpers do not route a local worktree checkout.
    fixture.config("credential.helper", "!false");
    assert!(fixture.allowed(Check::WorktreeAdd));
    assert!(!fixture.allowed(Check::FetchOrigin));
    assert!(!fixture.allowed(Check::PushOrigin));
}

#[test]
fn partial_clone_configuration_blocks_checkout_and_object_queries() {
    for (key, value) in [
        ("extensions.partialClone", "origin"),
        ("extensions.partialClone", "false"),
        ("remote.origin.promisor", "true"),
        ("remote.origin.partialCloneFilter", "blob:none"),
        ("remote.origin.partialCloneFilter", "false"),
    ] {
        let fixture = Fixture::new("partial");
        if !fixture.host_git_is_trusted() {
            return;
        }
        fixture.config(key, value);
        assert!(!fixture.allowed(Check::WorktreeAdd), "{key}={value}");
        assert!(!fixture.allowed(Check::ObjectQuery), "{key}={value}");
    }
}

#[test]
fn status_config_rejects_pagers_and_fsmonitor_helpers() {
    for (key, value) in [
        ("core.pager", "less"),
        ("pager.status", "less"),
        ("core.fsmonitor", "/tmp/fsmonitor.sh"),
    ] {
        let fixture = Fixture::new("status");
        if !fixture.host_git_is_trusted() {
            return;
        }
        fixture.config(key, value);
        assert!(!fixture.allowed(Check::StatusConfig), "{key}={value}");
        assert!(!fixture.allowed(Check::WorktreeAdd), "{key}={value}");
    }
    let fixture = Fixture::new("status-cat");
    if fixture.host_git_is_trusted() {
        fixture.config("core.pager", "cat");
        fixture.config("core.fsmonitor", "false");
        assert!(fixture.allowed(Check::StatusConfig));
        let mut request = fixture.request(Check::StatusConfig);
        request
            .environment
            .insert("GIT_PAGER".to_owned(), "less".to_owned());
        assert!(!crate::git_execution_safety_checks::decide(&request).allowed);
    }
}

#[test]
fn environment_snapshot_blocks_checkout_fetch_and_routing() {
    let fixture = Fixture::new("environment");
    if !fixture.host_git_is_trusted() {
        return;
    }
    for (check, name, value) in [
        (Check::WorktreeAdd, "GIT_EXEC_PATH", "helpers"),
        (Check::WorktreeAdd, "GIT_OBJECT_DIRECTORY", " "),
        (Check::FetchOrigin, "GIT_SSH_COMMAND", "payload"),
        (Check::StatusConfig, "GIT_DIR", "."),
        (Check::ObjectQuery, "GIT_CONFIG_COUNT", "1"),
    ] {
        let mut request = fixture.request(check);
        request
            .environment
            .insert(name.to_owned(), value.to_owned());
        assert!(
            !crate::git_execution_safety_checks::decide(&request).allowed,
            "{name}"
        );
    }
}

#[test]
fn push_requires_a_stable_account_and_a_checked_out_branch() {
    let fixture = Fixture::new("push");
    if !fixture.host_git_is_trusted() {
        return;
    }
    let mut request = fixture.request(Check::PushOrigin);
    request.account_home = None;
    assert!(!crate::git_execution_safety_checks::decide(&request).allowed);
    request.account_home = Some(fixture.root.to_string_lossy().into_owned());
    assert!(!crate::git_execution_safety_checks::decide(&request).allowed);
    let mut request = fixture.request(Check::PushOrigin);
    request.branch = Some("other".to_owned());
    assert!(!crate::git_execution_safety_checks::decide(&request).allowed);
    request.branch = Some("-main".to_owned());
    assert!(!crate::git_execution_safety_checks::decide(&request).allowed);
    fixture.config("remote.origin.pushurl", "https://example.invalid/x.git");
    assert!(!fixture.allowed(Check::PushOrigin));
}

#[test]
fn executable_repository_hooks_block_fetch_push_and_checkout() {
    use std::os::unix::fs::PermissionsExt;
    for (hook, check) in [
        ("post-checkout", Check::WorktreeAdd),
        ("reference-transaction", Check::WorktreeAdd),
        ("post-fetch", Check::FetchOrigin),
        ("pre-push", Check::PushOrigin),
    ] {
        let fixture = Fixture::new("hooks");
        if !fixture.host_git_is_trusted() {
            return;
        }
        let path = fixture.repository.join(".git/hooks").join(hook);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(fixture.allowed(check), "non-executable {hook} is inert");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!fixture.allowed(check), "executable {hook}");
    }
}

#[test]
fn worktree_filter_check_is_scoped_to_the_selected_reference() {
    let fixture = Fixture::new("filters");
    if !fixture.host_git_is_trusted() {
        return;
    }
    let git_path =
        crate::git_execution_safety_checks::decide(&fixture.request(Check::ResolveBinary))
            .resolved_path
            .map(PathBuf::from)
            .unwrap();
    let request = fixture.request(Check::WorktreeAdd);
    let uses = |reference: &str| {
        crate::git_execution_safety_checks::ref_uses_checkout_filter_for_tests(
            &request,
            &git_path,
            &fixture.repository,
            reference,
        )
    };
    assert!(!uses("HEAD"));
    std::fs::write(
        fixture.repository.join(".gitattributes"),
        "*.txt filter=guard-test\n",
    )
    .unwrap();
    std::fs::write(fixture.repository.join("a.txt"), "data\n").unwrap();
    git(
        &fixture.repository,
        &fixture.home,
        &["add", ".gitattributes", "a.txt"],
    );
    git(
        &fixture.repository,
        &fixture.home,
        &["commit", "--quiet", "-m", "add filter"],
    );
    assert!(uses("HEAD"));
    assert!(uses("--help"));
    // A filter attribute alone is inert; a configured driver makes it block.
    // Hosts that ship system-level filter drivers (for example git-lfs on CI
    // images) already configure one, so the baseline follows the host.
    let host_configures_filters = Command::new(&git_path)
        .args(["config", "--system", "--get-regexp", "^filter\\."])
        .env("HOME", &fixture.home)
        .output()
        .is_ok_and(|output| output.status.success() && !output.stdout.is_empty());
    assert_eq!(
        fixture.allowed(Check::WorktreeAdd),
        !host_configures_filters
    );
    fixture.config("filter.guard-test.clean", "cat");
    assert!(!fixture.allowed(Check::WorktreeAdd));
}

#[test]
fn binary_trust_rejects_user_controlled_roots() {
    let fixture = Fixture::new("binary");
    let mut request = fixture.request(Check::BinaryTrusted);
    let inside = fixture.repository.join("git");
    std::fs::write(&inside, "#!/bin/sh\n").unwrap();
    request.git_path = Some(inside.to_string_lossy().into_owned());
    assert!(!crate::git_execution_safety_checks::decide(&request).allowed);
    request.git_path = None;
    assert!(!crate::git_execution_safety_checks::decide(&request).allowed);
    request.git_path = Some("git".to_owned());
    assert!(!crate::git_execution_safety_checks::decide(&request).allowed);
    // A PATH that only contains the repository never resolves to a trusted Git.
    let mut request = fixture.request(Check::ResolveBinary);
    request.environment.insert(
        "PATH".to_owned(),
        fixture.repository.to_string_lossy().into_owned(),
    );
    assert!(!crate::git_execution_safety_checks::decide(&request).allowed);
}

#[test]
fn resident_op_binds_the_request_and_rejects_bad_schemas() {
    let fixture = Fixture::new("resident");
    let mut request = fixture.request(Check::StatusArguments);
    request.arguments = strings(&["status", "--short"]);
    let wire = serde_json::json!({"operation": "git_execution_safety", "request": request});
    let bytes = serde_json::to_vec(&wire).unwrap();
    let output: serde_json::Value = serde_json::from_slice(
        &crate::resident_protocol::evaluate_resident_bytes(&bytes, None).unwrap(),
    )
    .unwrap();
    assert_eq!(output["status"], "ok");
    assert_eq!(output["allowed"], true);
    assert!(output["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    request.schema = "wrong".to_owned();
    let wire = serde_json::json!({"operation": "git_execution_safety", "request": request});
    let output: serde_json::Value = serde_json::from_slice(
        &crate::resident_protocol::evaluate_resident_bytes(
            &serde_json::to_vec(&wire).unwrap(),
            None,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(output["status"], "error");
    assert_eq!(output["allowed"], false);
    assert!(crate::resident_protocol::capabilities()
        .features
        .iter()
        .any(|feature| feature == guard_contracts::GIT_EXECUTION_SAFETY_FEATURE));
}

#[test]
fn absent_account_config_directory_is_a_stable_global_config() {
    use crate::git_execution_safety_binary::global_config_environment_is_stable;
    let home = temp_root("xdg-absent");
    let account = home.to_string_lossy().into_owned();
    let environment = |xdg: String| -> crate::git_execution_safety_config::Environment {
        [
            ("HOME".to_owned(), account.clone()),
            ("XDG_CONFIG_HOME".to_owned(), xdg),
        ]
        .into_iter()
        .collect()
    };
    let config = home.join(".config");
    assert!(!config.exists());
    assert!(global_config_environment_is_stable(
        &environment(config.to_string_lossy().into_owned()),
        Some(&account),
    ));
    assert!(!global_config_environment_is_stable(
        &environment(home.join("elsewhere").to_string_lossy().into_owned()),
        Some(&account),
    ));
    assert!(!global_config_environment_is_stable(
        &environment(format!("{}/../x", config.display())),
        Some(&account),
    ));
    assert!(!global_config_environment_is_stable(
        &environment("  ".to_owned()),
        Some(&account),
    ));
    let _ = std::fs::remove_dir_all(&home);
}
