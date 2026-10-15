use super::project;
use std::path::PathBuf;

fn directory(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("guard-chain-pwd-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("sub")).unwrap();
    root.canonicalize().unwrap()
}

#[test]
fn uses_before_any_directory_change_take_the_working_directory() {
    let cwd = directory("uses");
    let d = cwd.to_str().unwrap();
    for (command, expected) in [
        (
            "git worktree add ../wt -b report && ln -s \"$(pwd)/node_modules\" ../wt/node_modules && cd ../wt && npm run report".to_owned(),
            format!("git worktree add ../wt -b report && ln -s \"{d}/node_modules\" ../wt/node_modules && cd ../wt && npm run report"),
        ),
        (
            "ln -s $PWD/node_modules ../wt/node_modules; ls ../wt".to_owned(),
            format!("ln -s {d}/node_modules ../wt/node_modules; ls ../wt"),
        ),
        (
            "ln -s \"${PWD}/node_modules\" ../wt/node_modules".to_owned(),
            format!("ln -s \"{d}/node_modules\" ../wt/node_modules"),
        ),
        (
            "ln -s `pwd`/node_modules ../wt/node_modules".to_owned(),
            format!("ln -s {d}/node_modules ../wt/node_modules"),
        ),
        (
            "D=$(pwd) && ls $D/sub".to_owned(),
            format!("D={d} && ls $D/sub"),
        ),
        // Single-quoted and escaped spellings are literal text.
        (
            "echo '$(pwd)' \\$PWD \"$PWD\"".to_owned(),
            format!("echo '$(pwd)' \\$PWD \"{d}\""),
        ),
    ] {
        assert_eq!(
            project(&command, d).as_deref(),
            Some(expected.as_str()),
            "{command}"
        );
    }
}

#[test]
fn a_possible_directory_change_before_a_use_keeps_it_opaque() {
    let cwd = directory("changes");
    let d = cwd.to_str().unwrap();
    for command in [
        "cd sub && ln -s $(pwd)/x y",
        "cd sub; ln -s $PWD/x y",
        "pushd sub && echo $PWD",
        "builtin cd sub && echo $(pwd)",
        "command cd sub && echo $(pwd)",
        "eval cd sub && echo $(pwd)",
        "source env.sh && echo $(pwd)",
        "$CMD sub && echo $(pwd)",
        "'cd' sub && echo $(pwd)",
        // zsh's AUTO_CD turns a bare directory name into `cd`.
        "sub && echo $(pwd)",
        "ls | cd sub && echo $(pwd)",
        "PWD=/etc && echo $PWD",
        "export PWD=/etc; echo $(pwd)",
        "IFS=/ && echo $(pwd)",
        // A redirection before the command word must not hide a `cd`.
        "2>/dev/null cd /etc && cat $(pwd)/passwd",
        "> out cd sub && echo $(pwd)",
        "<in cd sub; echo $PWD",
        "A=1 2>&1 cd sub && echo $(pwd)",
    ] {
        assert_eq!(project(command, d), None, "{command}");
    }
    // A change after the last use leaves the earlier uses exact.
    assert!(project("echo $(pwd) && cd sub && ls", d).is_some());
    // A redirection after the command word leaves it visible.
    assert!(project("ls $(pwd) 2>/dev/null; cat .gitignore", d).is_some());
}

#[test]
fn other_expansions_and_shapes_keep_the_command_opaque() {
    let cwd = directory("shapes");
    let d = cwd.to_str().unwrap();
    for command in [
        "echo $(pwd) $(id -u)",
        "echo $(pwd -P)",
        "echo $( pwd )",
        "echo $(pwd)$(whoami)",
        "echo ${PWD%/*}",
        "echo ${PWD:-x}",
        "echo $PWD:h",
        "echo $PWD[1]",
        "(echo $(pwd))",
        "echo $(pwd) > out.txt <<EOF",
        "echo $(pwd) &",
        "echo hi # $(pwd)",
        "ls",
        "echo $PWDX",
    ] {
        assert_eq!(project(command, d), None, "{command}");
    }
}

#[test]
fn a_directory_the_shell_would_rewrite_is_never_substituted() {
    let cwd = directory("dir name");
    let d = cwd.to_str().unwrap();
    assert_eq!(project("echo $(pwd)", d), None);
    assert_eq!(project("echo $(pwd)", "relative/dir"), None);
    assert_eq!(project("echo $(pwd)", "/nonexistent-guard-dir/x"), None);
    let plain = directory("plain");
    let p = plain.to_str().unwrap();
    assert_eq!(project("echo $(pwd)", &format!("{p}/../{}", "plain")), None);
}
