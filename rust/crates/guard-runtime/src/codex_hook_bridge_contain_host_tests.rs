use super::contains_on;
use crate::hook_decision_containment_route::LINUX_PROFILES;

/// A Linux host runs a project's own pytest and every other read-only
/// profile under bubblewrap, so the Codex bridge routes those denials to
/// the sink instead of leaving Codex a hard block the other harnesses on the
/// same host never see.
#[test]
fn a_linux_host_routes_every_profile_its_sink_runs() {
    for profile in LINUX_PROFILES {
        assert!(contains_on("linux", Some(profile)), "{profile}");
    }
    assert!(!contains_on("linux", Some("unknown-profile-v1")));
    assert!(!contains_on("linux", None));
}

#[test]
fn other_hosts_keep_their_own_tables() {
    for profile in [
        "pytest-readonly-v2",
        "git-readonly-v1",
        "workspace-contained-v1",
    ] {
        assert!(contains_on("macos", Some(profile)), "{profile}");
    }
    assert!(contains_on("windows", Some("pytest-readonly-v2")));
    assert!(contains_on("windows", Some("python-eval-readonly-v1")));
    assert!(!contains_on("windows", Some("git-readonly-v1")));
    assert!(!contains_on("windows", Some("workspace-contained-v1")));
    assert!(!contains_on("other", Some("pytest-readonly-v2")));
    assert!(!contains_on("plan9", Some("pytest-readonly-v2")));
}

/// The host this runs on: on Linux the parent kept pytest a hard block.
#[cfg(target_os = "linux")]
#[test]
fn this_linux_host_routes_a_projects_own_pytest() {
    assert!(super::platform_contains(Some("pytest-readonly-v2")));
    assert!(super::platform_contains(Some("python-eval-readonly-v1")));
}
