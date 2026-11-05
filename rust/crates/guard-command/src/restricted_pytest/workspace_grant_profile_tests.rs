use super::super::workspace_grant::{loopback_any_port, GrantRules, GRANT_PROFILE};
use super::*;

fn input(profile: &str, capabilities: &[&str]) -> Input {
    Input {
        profile_version: profile.into(),
        workspace: PathBuf::from("/w/proj"),
        cwd: PathBuf::from("/w/proj"),
        private_root: PathBuf::from("/private/tmp/guard-private"),
        command: vec!["/bin/sh".into(), "-c".into(), "lanectl status".into()],
        capabilities: capabilities.iter().map(|name| (*name).to_owned()).collect(),
        ..Input::default()
    }
}

fn credential_lines(profile: &str) -> Vec<&str> {
    profile
        .lines()
        .filter(|line| line.starts_with("(deny file-read* file-write* (regex"))
        .collect()
}

#[test]
fn loopback_network_reaches_only_localhost() {
    let profile = macos_profile(&input(GRANT_PROFILE, &["loopback-network"])).unwrap();
    let network: Vec<&str> = profile
        .lines()
        .filter(|line| line.contains("network"))
        .collect();
    assert_eq!(network, loopback_any_port());
    assert!(network
        .iter()
        .all(|line| line.contains("(local ip \"localhost:*\")")
            || line.contains("(remote ip \"localhost:*\")")));
    assert!(profile.lines().any(|line| line == "(deny default)"));
    // No grant line follows the credential denials.
    let last = profile.lines().last().unwrap();
    assert!(
        last.starts_with("(deny file-read* file-write* (regex"),
        "{last}"
    );
}

#[test]
fn a_grant_without_loopback_keeps_the_network_closed() {
    let profile = macos_profile(&input(GRANT_PROFILE, &[])).unwrap();
    assert!(
        !profile.lines().any(|line| line.contains("network")),
        "{profile}"
    );
    let base = macos_profile(&input(WORKSPACE_CONTAINED_PROFILE, &[])).unwrap();
    assert_eq!(profile, base, "an empty grant composes the base profile");
}

#[test]
fn readonly_pytest_may_bind_loopback_but_not_listen_or_connect() {
    let workspace = std::env::temp_dir().join(format!(
        "guard-pytest-listener-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    std::fs::create_dir_all(&workspace).unwrap();
    let workspace = workspace.canonicalize().unwrap();
    let profile_for = |profile: &str| {
        let mut value = input(profile, &[]);
        value.workspace = workspace.clone();
        value.cwd = workspace.clone();
        value.allowed_executables = vec![PathBuf::from("/usr/bin/python3")];
        macos_profile(&value).unwrap()
    };
    let pytest = profile_for("pytest-readonly-v2");
    let network: Vec<&str> = pytest
        .lines()
        .filter(|line| line.contains("network"))
        .collect();
    assert_eq!(network, PYTEST_LOOPBACK_BIND);
    for denied in ["network-inbound", "network-outbound"] {
        assert!(!pytest.contains(denied), "{pytest}");
    }
    // The credential denials still come after the bind, so they win.
    let lines: Vec<&str> = pytest.lines().collect();
    let bind = lines.iter().position(|line| *line == network[0]).unwrap();
    let tail = &lines[bind + 1..];
    assert!(!tail.is_empty());
    assert!(
        tail.iter().all(|line| line.starts_with("(deny file-read")),
        "{pytest}"
    );
    for other in ["git-readonly-v1", "python-eval-readonly-v1"] {
        assert!(!profile_for(other).contains("network"), "{other}");
    }
    std::fs::remove_dir_all(&workspace).unwrap();
}

#[test]
fn capabilities_never_reopen_credentials() {
    let base = macos_profile(&input(WORKSPACE_CONTAINED_PROFILE, &[])).unwrap();
    let state = PathBuf::from("/home/dev/.lanectl");
    let rules = GrantRules {
        reads: vec![state.clone()],
        writes: vec![state.clone()],
        network: loopback_any_port(),
    };
    let mut granted = input(GRANT_PROFILE, &GRANT_CAPABILITIES_FOR_TEST);
    granted.read_only_roots = vec![state.clone()];
    let profile = workspace_profile::compose_with(
        &granted,
        &existing(MAC_ROOTS),
        &existing(MAC_FILES),
        &rules,
    )
    .unwrap();
    assert!(profile.contains("(subpath \"/home/dev/.lanectl\")"));
    assert!(profile
        .lines()
        .any(|line| line.starts_with("(allow file-write*")
            && line.contains("(subpath \"/home/dev/.lanectl\")")));
    let credentials = credential_lines(&profile);
    assert!(!credentials.is_empty());
    assert_eq!(credentials, credential_lines(&base));
    let tail: Vec<&str> = profile.lines().rev().take(credentials.len()).collect();
    assert!(tail
        .iter()
        .all(|line| line.starts_with("(deny file-read* file-write* (regex")));
}

#[test]
fn capabilities_belong_only_to_the_grant_profile() {
    assert!(macos_profile(&input(WORKSPACE_CONTAINED_PROFILE, &["loopback-network"])).is_err());
    assert!(macos_profile(&input(GRANT_PROFILE, &["network"])).is_err());
    assert!(bubblewrap_argv(&input(GRANT_PROFILE, &[])).is_err());
}

#[test]
fn a_state_capability_composes_only_inside_the_given_home() {
    let root = std::env::temp_dir().join(format!("guard-grant-profile-{}", std::process::id()));
    let state_parent = root.join("home");
    std::fs::create_dir_all(&state_parent).unwrap();
    let canonical = state_parent.canonicalize().unwrap();
    let state = canonical.join(".lanectl");
    std::fs::create_dir_all(&state).unwrap();
    let mut granted = input(GRANT_PROFILE, &["state-dir-read"]);
    granted.read_only_roots = vec![state.clone()];
    assert!(macos_profile(&granted).is_err(), "no home, no state");
    granted.home = Some(state_parent);
    let profile = macos_profile(&granted).unwrap();
    assert!(profile.contains(&format!("(subpath \"{}\")", state.display())));
    granted.home = Some(PathBuf::from("/"));
    assert!(macos_profile(&granted).is_err(), "another home");
    let _ = std::fs::remove_dir_all(&root);
}

const GRANT_CAPABILITIES_FOR_TEST: [&str; 3] =
    ["loopback-network", "state-dir-read", "state-dir-write"];

#[test]
#[cfg(unix)]
fn collection_grants_metadata_for_links_in_the_directories_pytest_walks() {
    let root = std::env::temp_dir().join(format!(
        "guard-collection-links-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    let workspace = root.join("worktree");
    let main = root.join("main");
    for directory in [
        workspace.join("dashboard/node_modules/pkg"),
        workspace.join(".hidden"),
        main.join("dashboard/node_modules"),
        main.join("skipped"),
        main.join("hidden"),
        main.join("nested-skip"),
    ] {
        std::fs::create_dir_all(directory).unwrap();
    }
    std::fs::write(main.join("server.key"), "synthetic").unwrap();
    let workspace = workspace.canonicalize().unwrap();
    let main = main.canonicalize().unwrap();
    std::fs::remove_dir_all(workspace.join("dashboard/node_modules")).unwrap();
    let link =
        |target: &std::path::Path, at: &str| std::os::unix::fs::symlink(target, workspace.join(at));
    link(
        &main.join("dashboard/node_modules"),
        "dashboard/node_modules",
    )
    .unwrap();
    link(&main.join("hidden"), ".hidden/link").unwrap();
    link(&main.join("server.key"), "dashboard/server-key").unwrap();
    std::fs::create_dir_all(workspace.join("build")).unwrap();
    link(&main.join("skipped"), "build/link").unwrap();
    std::fs::create_dir_all(workspace.join("node_modules/pkg")).unwrap();
    link(&main.join("nested-skip"), "node_modules/pkg/link").unwrap();
    let mut value = input("pytest-readonly-v2", &[]);
    value.workspace = workspace.clone();
    value.cwd = workspace.clone();
    let targets = collection_link_metadata(&value).unwrap();
    assert_eq!(targets, vec![main.join("dashboard/node_modules")]);
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
#[cfg(unix)]
fn collection_lists_both_roots_before_the_budget_limits_descent() {
    let root = std::env::temp_dir().join(format!(
        "guard-collection-budget-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    let workspace = root.join("worktree");
    let outside = root.join("outside");
    for directory in [
        workspace.join("tests"),
        workspace.join("deep"),
        outside.join("root"),
        outside.join("deep"),
    ] {
        std::fs::create_dir_all(directory).unwrap();
    }
    for name in ["a.py", "b.py", "c.py"] {
        std::fs::write(workspace.join("tests").join(name), "").unwrap();
    }
    let workspace = workspace.canonicalize().unwrap();
    let outside = outside.canonicalize().unwrap();
    std::os::unix::fs::symlink(outside.join("root"), workspace.join("link")).unwrap();
    std::os::unix::fs::symlink(outside.join("deep"), workspace.join("deep/link")).unwrap();
    let mut value = input("pytest-readonly-v2", &[]);
    value.workspace = workspace.clone();
    value.cwd = workspace.join("tests");
    let targets = collection_links::walk(&value, 2).unwrap();
    assert_eq!(targets, vec![outside.join("root")]);
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
#[cfg(unix)]
fn collection_walks_a_skipped_directory_the_command_names() {
    let root = std::env::temp_dir().join(format!(
        "guard-collection-selected-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    let workspace = root.join("worktree");
    let outside = root.join("outside");
    for directory in [
        workspace.join("build/tests"),
        outside.join("named"),
        outside.join("unnamed"),
        outside.join("beyond"),
    ] {
        std::fs::create_dir_all(directory).unwrap();
    }
    let workspace = workspace.canonicalize().unwrap();
    let outside = outside.canonicalize().unwrap();
    std::fs::create_dir_all(workspace.join("dist")).unwrap();
    std::os::unix::fs::symlink(outside.join("named"), workspace.join("build/tests/link")).unwrap();
    std::os::unix::fs::symlink(outside.join("unnamed"), workspace.join("dist/link")).unwrap();
    std::os::unix::fs::symlink(outside.join("beyond"), outside.join("named/link")).unwrap();
    let mut value = input("pytest-readonly-v2", &[]);
    value.workspace = workspace.clone();
    value.cwd = workspace.clone();
    value.command = [
        "python",
        "-m",
        "pytest",
        "-q",
        "build/tests::test_x",
        "../outside",
    ]
    .map(String::from)
    .to_vec();
    let targets = collection_link_metadata(&value).unwrap();
    assert_eq!(targets, vec![outside.join("named")]);
    std::fs::remove_dir_all(&root).unwrap();
}
