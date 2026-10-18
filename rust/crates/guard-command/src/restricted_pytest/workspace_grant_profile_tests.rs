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
