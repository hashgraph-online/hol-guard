//! The shell's HOME counts as the declared home only when its own spelling is
//! plain text. `~` expands to that spelling, so a HOME the shell would split
//! once a variable holding it is used unquoted names other paths, even when
//! it links to the declared directory.

use super::super::PathContext;
use guard_contracts::GuardExecutionEnvironmentV1;

fn environment(home: &std::path::Path) -> GuardExecutionEnvironmentV1 {
    GuardExecutionEnvironmentV1 {
        home: home.to_str().map(str::to_owned),
        path: "/usr/bin:/bin".to_owned(),
        environment_names: vec!["HOME".to_owned(), "PATH".to_owned()],
        environment_digest: "0".repeat(64),
        ..Default::default()
    }
}

#[test]
fn a_shell_home_spelled_with_a_space_is_not_the_declared_home() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/tests-shell-home-spelling")
        .join(std::process::id().to_string());
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("home")).unwrap();
    let root = std::fs::canonicalize(&root).unwrap();
    let declared = root.join("home");
    let plain = root.join("alias");
    let spaced = root.join("alias extra");
    std::os::unix::fs::symlink(&declared, &plain).unwrap();
    std::os::unix::fs::symlink(&declared, &spaced).unwrap();
    let matches = |shell: &std::path::Path| {
        PathContext::shell_home_matches_for(declared.to_str(), Some(&environment(shell)))
    };
    let results = (matches(&declared), matches(&plain), matches(&spaced));
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(results, (true, true, false));
}
