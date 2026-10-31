//! Configuration text Git hands to a shell or a path walk: the words a
//! helper's `echo` prints and hook folders reached through a link.
use super::denials;
use std::path::Path;

#[cfg(unix)]
#[test]
fn hooks_path_follows_a_link_before_stepping_out_of_it() {
    // Git follows a link before it applies `..`, so `~/link/../.hooks` with
    // the link inside the worktree is the worktree's `.hooks`, not home's.
    let root = super::scratch("hooks-link-parent");
    let (home, repo) = (root.join("home"), root.join("repo"));
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::os::unix::fs::symlink(repo.join("app"), home.join("link")).unwrap();
    std::fs::write(
        repo.join(".git/config"),
        "[core]\n\thooksPath = ~/link/../.hooks\n",
    )
    .unwrap();
    assert_eq!(
        super::workspace_write_denials(&repo, Some(&home)),
        Some(vec![repo.join(".hooks")])
    );
    std::os::unix::fs::symlink(repo.join("gone"), home.join("dangling")).unwrap();
    std::fs::write(
        repo.join(".git/config"),
        "[core]\n\thooksPath = ~/dangling/../.hooks\n",
    )
    .unwrap();
    assert_eq!(super::workspace_write_denials(&repo, Some(&home)), None);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn text_a_helper_echoes_is_data_but_its_substitutions_are_screened() {
    let ws = Path::new("/w/repo");
    let helper = |value: &str| denials(&format!("[credential]\n\thelper = {value}\n"), ws);
    let answer = r#""!f() { echo \"username=x-access-token\"; echo \"password=$(gh auth token --hostname example.com)\"; }; f""#;
    assert!(helper(answer).is_some());
    let local = r#""!f() { echo \"password=$(./tools/token read)\"; }; f""#;
    assert!(helper(local).unwrap().contains(&ws.join("tools/token")));
    for value in [
        r#""!f() { echo \"./my tool.sh\" | sh; }; f""#,
        r#""!echo() { sh \"$@\"; }; echo \"./my tool.sh\"""#,
        r#""!f() { echo \"x\" > \"./a b\"; }; f""#,
        r#""!f() { echo \"$(cat \"a b\")\"; }; f""#,
        r#""!f() { echo \"$HOME/a b\"; }; f""#,
        r#""!sh -c \"./my tool.sh\"""#,
        r#""!alias echo=sh; echo \"./my tool.sh\"""#,
        r#""!f() { echo \"./my tool.sh\"; $_; }; f""#,
        r#""!f() { $(echo \"./my tool.sh\"); }; f""#,
    ] {
        assert_eq!(helper(value), None, "{value}");
    }
    // Text something hands back to a shell is a path, never masked away: the
    // last argument through `$_` or `${_}`, a substitution's output, or an
    // argument of a command that is only partly named `echo`.
    for value in [
        r#""!f() { echo \"./tools/token\"; $_ get; }; f""#,
        r#""!f() { echo \"./tools/token\"; ${_} get; }; f""#,
        r#""!f() { $(echo \"./tools/token\") get; }; f""#,
        r#""!echoX() { \"$@\"; }; f() { echo'X' \"./tools/token\"; }; f""#,
    ] {
        let kept = helper(value);
        assert!(
            kept.as_ref()
                .is_none_or(|paths| paths.contains(&ws.join("tools/token"))),
            "{value}: {kept:?}"
        );
    }
}
