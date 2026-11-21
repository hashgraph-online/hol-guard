use super::project;
use std::path::PathBuf;

fn directory(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("guard-chain-home-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join(".nvm")).unwrap();
    root.canonicalize().unwrap()
}

// `project` substitutes only a POSIX absolute directory, so a Windows home
// directory is never projected.
#[cfg(unix)]
#[test]
fn home_uses_before_any_assignment_take_the_home_directory() {
    let home = directory("uses");
    let h = home.to_str().unwrap();
    for (command, expected) in [
        (
            "find \"$HOME/.nvm/versions/node\" -mindepth 1 -maxdepth 1 -type d -print".to_owned(),
            format!("find \"{h}/.nvm/versions/node\" -mindepth 1 -maxdepth 1 -type d -print"),
        ),
        (
            "shasum -a 256 \"$HOME/Downloads/widgets-1.4.0\"/*".to_owned(),
            format!("shasum -a 256 \"{h}/Downloads/widgets-1.4.0\"/*"),
        ),
        (
            "find $HOME/Downloads/widgets-1.4.0 -type f -print | sort".to_owned(),
            format!("find {h}/Downloads/widgets-1.4.0 -type f -print | sort"),
        ),
        (
            "printf 'NVM_DIR=%s\\n' \"${HOME}/.nvm\"; ls ${HOME}/.nvm".to_owned(),
            format!("printf 'NVM_DIR=%s\\n' \"{h}/.nvm\"; ls {h}/.nvm"),
        ),
        // `printf` stops reading options at its format string, so an
        // expansion after it is text it prints, not a name it sets.
        (
            "printf '%s\\n' \"$node\"; ls \"$HOME/.nvm\"".to_owned(),
            format!("printf '%s\\n' \"$node\"; ls \"{h}/.nvm\""),
        ),
        // A directory change moves the working directory, not HOME.
        (
            "cd /tmp && ls \"$HOME/.nvm\"".to_owned(),
            format!("cd /tmp && ls \"{h}/.nvm\""),
        ),
        // Single-quoted and escaped spellings are literal text.
        (
            "ls '$HOME/.nvm' \\$HOME \"$HOME\"".to_owned(),
            format!("ls '$HOME/.nvm' \\$HOME \"{h}\""),
        ),
    ] {
        assert_eq!(
            project(&command, h).as_deref(),
            Some(expected.as_str()),
            "{command}"
        );
    }
}

#[test]
fn a_possible_home_change_before_a_use_keeps_it_opaque() {
    let home = directory("changes");
    let h = home.to_str().unwrap();
    for command in [
        "HOME=/etc && cat $HOME/passwd",
        "HOME=/etc; cat \"$HOME/passwd\"",
        "export HOME=/etc; cat $HOME/passwd",
        "unset HOME; ls $HOME",
        "read HOME; cat $HOME/x",
        "typeset -x HOME=/etc && cat $HOME/passwd",
        "eval \"$X\" && cat $HOME/x",
        "source env.sh && cat $HOME/x",
        ". ./env.sh; cat $HOME/x",
        "$CMD && cat $HOME/x",
        "builtin export HOME=/etc && cat $HOME/x",
        "IFS=/ && ls $HOME",
        "2>/dev/null export HOME=/etc && cat $HOME/passwd",
        // `printf -v` takes the name it sets as an option operand, so a name
        // the shell assembles from expansions never spells HOME in the text.
        "printf -v p HO; printf -v s ME; printf -v $p$s %s /etc; cat $HOME/passwd",
        "printf -vHOME %s /etc; cat $HOME/passwd",
        "printf \"-v\" $p$s %s /etc && cat $HOME/passwd",
        // The option word itself can come from an expansion.
        "o=-v p=HO s=ME; printf $o $p$s %s /etc; cat $HOME/passwd",
        // So can an expansion after the dash, a substitution, a brace
        // expansion or a glob.
        "x=v p=HO s=ME; printf -$x$p$s %s /etc; cat $HOME/passwd",
        "printf `echo -vHOME` %s /etc; cat $HOME/passwd",
        "printf {-vHO,}ME %s /etc; cat $HOME/passwd",
        "printf -[v]HOME %s /etc; cat $HOME/passwd",
        // zsh's `print -v` sets a name the same way, and other zsh
        // builtins set one given as an operand.
        "p=HO s=ME; print -v $p$s /etc; cat $HOME/passwd",
        "p=HO s=ME; print -rv $p$s /etc; cat $HOME/passwd",
        "p=HO s=ME; getln $p$s; cat $HOME/passwd",
        "p=HO s=ME; strftime -s $p$s %s 0; cat $HOME/passwd",
        "p=HO s=ME; zstat -A $p$s /etc; cat $HOME/passwd",
        "p=HO s=ME; zstyle -s ctx style $p$s; cat $HOME/passwd",
        "p=HO s=ME; syserror -e $p$s; cat $HOME/passwd",
        "p=HO s=ME; sysopen -u $p$s -r /etc/hosts; cat $HOME/passwd",
        "p=HO s=ME; syswrite -c $p$s x; cat $HOME/passwd",
        "p=HO s=ME; zsystem flock -f $p$s /tmp/lock; cat $HOME/passwd",
        "p=HO s=ME; pcre_match -v $p$s /etc; cat $HOME/passwd",
        "p=HO s=ME; zgetattr /etc attr $p$s; cat $HOME/passwd",
        "p=HO s=ME; compgen -V $p$s -W /etc; cat $HOME/passwd",
    ] {
        assert_eq!(project(command, h), None, "{command}");
    }
    // A change after the last use leaves the earlier uses exact.
    if cfg!(unix) {
        assert!(project("ls $HOME/.nvm && source env.sh", h).is_some());
    }
}

#[test]
fn other_home_expansions_and_shapes_keep_the_command_opaque() {
    let home = directory("shapes");
    let h = home.to_str().unwrap();
    for command in [
        "ls ${HOME%/*}",
        "ls ${HOME:-/etc}",
        "ls $HOME:h",
        "ls $HOME[1]",
        "ls $HOMEDIR",
        "(ls $HOME)",
        "ls $HOME &",
        "ls # $HOME",
        "ls ~/.nvm",
    ] {
        assert_eq!(project(command, h), None, "{command}");
    }
}

#[test]
fn a_home_the_shell_would_rewrite_is_never_substituted() {
    let spaced = directory("home dir");
    assert_eq!(project("ls $HOME", spaced.to_str().unwrap()), None);
    assert_eq!(project("ls $HOME", "relative/home"), None);
    assert_eq!(project("ls $HOME", "/nonexistent-guard-home/x"), None);
}
