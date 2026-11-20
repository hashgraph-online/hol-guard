//! The machine half of the native `git push origin <branch>` proof.
//!
//! guard-command proves the command shape; this verdict asks the repository
//! itself, with the same checks the compound Git decision runs for a push: the
//! branch is checked out, origin is one credential-free GitHub HTTPS remote, the
//! credential helpers and hooks are trusted and no configuration reroutes the
//! push. The probes see only `PATH`, `HOME` and `XDG_CONFIG_HOME`.
use std::collections::BTreeMap;
use std::path::Path;

use guard_command::pretool::GitPushRequest;
use guard_contracts::{
    GitExecutionSafetyCheckV1, GitExecutionSafetyRequestV1, GIT_EXECUTION_SAFETY_REQUEST_SCHEMA,
};

use crate::git_execution_safety_binary::binary_path_is_trusted;
use crate::git_execution_safety_checks::decide;

pub(crate) fn install() {
    guard_command::pretool::install_git_push_verdict(verdict);
}

fn verdict(push: &GitPushRequest<'_>) -> bool {
    // A relative value resolves from whichever directory reads it: the account
    // check and the probes would each see a different global configuration.
    if push
        .xdg_config_home
        .is_some_and(|xdg| !Path::new(xdg).is_absolute())
    {
        return false;
    }
    let Some(account_home) = account_home() else {
        return false;
    };
    let Some(groups) = groups() else {
        return false;
    };
    // The probes run this program in the repository: only Git itself.
    let name = push.git.file_name().and_then(|name| name.to_str());
    if !matches!(name, Some("git" | "git.exe")) {
        return false;
    }
    // `decide` trusts a supplied binary; prove it the way resolution would.
    if !binary_path_is_trusted(push.git, push.repository, push.home, &groups) {
        return false;
    }
    decide(&request(push, account_home, groups)).allowed
}

fn request(
    push: &GitPushRequest<'_>,
    account_home: String,
    groups: Vec<u32>,
) -> GitExecutionSafetyRequestV1 {
    let home = push.home.to_string_lossy().into_owned();
    let mut environment = BTreeMap::from([
        ("PATH".to_owned(), push.path.to_owned()),
        ("HOME".to_owned(), home.clone()),
    ]);
    if let Some(xdg) = push.xdg_config_home {
        environment.insert("XDG_CONFIG_HOME".to_owned(), xdg.to_owned());
    }
    GitExecutionSafetyRequestV1 {
        schema: GIT_EXECUTION_SAFETY_REQUEST_SCHEMA.to_owned(),
        request_id: String::new(),
        check: GitExecutionSafetyCheckV1::PushOrigin,
        cwd: push.repository.to_string_lossy().into_owned(),
        home,
        account_home: Some(account_home),
        groups,
        environment,
        git_binary: Some(push.git.to_string_lossy().into_owned()),
        git_path: None,
        arguments: Vec::new(),
        branch: Some(push.branch.to_owned()),
        reference: push.creates_branch.then(|| "HEAD".to_owned()),
    }
}

#[cfg(unix)]
pub(crate) fn account_home() -> Option<String> {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::current()).ok()??;
    Path::new(&user.dir)
        .is_absolute()
        .then(|| user.dir.to_string_lossy().into_owned())
}

#[cfg(not(unix))]
pub(crate) fn account_home() -> Option<String> {
    None
}

/// The account's groups, which decide whether a group-writable directory on
/// the Git path is writable by this account. `getgroups` has no safe binding
/// on Apple targets, so the system `id` reports them.
#[cfg(unix)]
pub(crate) fn groups() -> Option<Vec<u32>> {
    let output = std::process::Command::new("/usr/bin/id")
        .arg("-G")
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    let mut groups = std::str::from_utf8(&output.stdout)
        .ok()?
        .split_whitespace()
        .map(|group| group.parse().ok())
        .collect::<Option<Vec<u32>>>()?;
    let effective = nix::unistd::getegid().as_raw();
    if !groups.contains(&effective) {
        groups.push(effective);
    }
    Some(groups)
}

#[cfg(not(unix))]
pub(crate) fn groups() -> Option<Vec<u32>> {
    None
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn push<'a>(git: &'a Path, repository: &'a Path, home: &'a Path) -> GitPushRequest<'a> {
        GitPushRequest {
            git,
            repository,
            branch: "feature/one",
            home,
            path: "/usr/bin:/bin",
            xdg_config_home: None,
            creates_branch: false,
        }
    }

    #[test]
    fn the_request_carries_only_the_routing_environment() {
        let (git, repository, home) = (
            PathBuf::from("/usr/bin/git"),
            PathBuf::from("/home/tester/project"),
            PathBuf::from("/home/tester"),
        );
        let built = request(
            &push(&git, &repository, &home),
            "/home/tester".into(),
            vec![20],
        );
        assert_eq!(built.check, GitExecutionSafetyCheckV1::PushOrigin);
        assert_eq!(built.branch.as_deref(), Some("feature/one"));
        assert_eq!(built.cwd, "/home/tester/project");
        assert_eq!(built.reference, None);
        assert_eq!(
            built.environment.keys().collect::<Vec<_>>(),
            ["HOME", "PATH"]
        );
        // A set NOSYSTEM would fail the routing screen before any probe runs.
        assert!(!built.environment.contains_key("GIT_CONFIG_NOSYSTEM"));
        let mut with_xdg = push(&git, &repository, &home);
        with_xdg.xdg_config_home = Some("/home/tester/.config");
        let built = request(&with_xdg, "/home/tester".into(), Vec::new());
        assert_eq!(
            built.environment.get("XDG_CONFIG_HOME").map(String::as_str),
            Some("/home/tester/.config")
        );
        let mut created = push(&git, &repository, &home);
        created.creates_branch = true;
        let built = request(&created, "/home/tester".into(), Vec::new());
        assert_eq!(built.reference.as_deref(), Some("HEAD"));
        assert_eq!(built.branch.as_deref(), Some("feature/one"));
    }

    #[test]
    fn the_account_facts_come_from_the_process() {
        let home = account_home().unwrap();
        assert!(Path::new(&home).is_absolute());
        let effective = nix::unistd::getegid().as_raw();
        assert!(groups().unwrap().contains(&effective));
    }

    #[test]
    fn a_git_binary_the_account_can_replace_is_refused() {
        let root = std::env::temp_dir().join(format!(
            "hol-guard-edge-push-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let git = root.join("git");
        std::fs::write(&git, "#!/bin/sh\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!verdict(&push(&git, &root, &root)));
        std::fs::remove_dir_all(root).unwrap();
    }
}
