//! A home dotfile's path as the only word of `grep`/`rg` is not a search.

use std::path::Path;

use crate::shell_secret_read_stdin_search::lone_search_pattern_names_home_dotpath;

const HOME: &str = "/home/agent";

fn words(command: &str) -> (String, Vec<String>) {
    let mut parts = command.split_whitespace().map(str::to_owned);
    let name = parts.next().expect("command name");
    (name, parts.collect())
}

fn names_dotpath(command: &str) -> bool {
    let (name, args) = words(command);
    lone_search_pattern_names_home_dotpath(&name, &args, Some(Path::new(HOME)))
}

#[test]
fn lone_home_dotpath_pattern_is_not_a_search() {
    for command in [
        "grep /home/agent/.secrets/key.txt",
        "egrep /home/agent/.secrets/key.txt",
        "fgrep /home/agent/.secrets/key.txt",
        "rg /home/agent/.secrets/key.txt",
        "grep ~/.ssh/id_rsa",
        "grep -i $HOME/.aws/credentials",
        "rg -- /home/agent/.netrc",
        "grep -A 3 /home/agent/.secrets/key.txt",
        "grep -T /home/agent/.secrets/key.txt",
        "grep -d skip /home/agent/.ssh/id_rsa",
        "grep -d read /home/agent/.ssh/id_rsa",
        "grep -id skip /home/agent/.ssh/id_rsa",
        "grep --directories=skip /home/agent/.ssh/id_rsa",
        "rg --encoding utf-8 /home/agent/.secrets/key.txt",
        "rg -j 1 /home/agent/.secrets/key.txt",
        "rg -j1 /home/agent/.secrets/key.txt",
        "rg -ij 1 /home/agent/.secrets/key.txt",
        "rg -i /home/agent/.secrets/key.txt",
        "rg -r x /home/agent/.secrets/key.txt",
        "rg -M 80 /home/agent/.secrets/key.txt",
        "rg -d 2 /home/agent/.secrets/key.txt",
        "rg --color never /home/agent/.secrets/key.txt",
        "rg --maxdepth 1 /home/agent/.secrets/key.txt",
        "rg --color=never /home/agent/.secrets/key.txt",
        "rg --maxdepth=1 /home/agent/.secrets/key.txt",
        "rg --threads 1 /home/agent/.secrets/key.txt",
        "rg --max-columns 80 /home/agent/.secrets/key.txt",
        "rg --glob='~*' /home/agent/.secrets/key.txt",
    ] {
        assert!(
            names_dotpath(command),
            "{command} must not pass as a search"
        );
    }
}

#[test]
fn ordinary_searches_still_pass() {
    for command in [
        "grep -r /home/agent/.secrets/key.txt .",
        "grep -rn /home/agent/.secrets/key.txt",
        "grep -R /home/agent/.ssh/id_rsa",
        "grep --recursive /home/agent/.ssh/id_rsa",
        "grep -d recurse /home/agent/.ssh/id_rsa",
        "rg /home/agent/.secrets/key.txt src",
        "grep /home/agent/.secrets/key.txt notes.txt",
        "grep -e /home/agent/.secrets/key.txt",
        "grep -ie /home/agent/.ssh/id_rsa",
        "rg -ie /home/agent/.ssh/id_rsa",
        "rg -i -e /home/agent/.ssh/id_rsa",
        "rg -e /home/agent/.ssh/id_rsa",
        "rg -e/home/agent/.ssh/id_rsa",
        "grep -i -e /home/agent/.ssh/id_rsa",
        "grep --directories=recurse /home/agent/.ssh/id_rsa",
        "grep -f patterns.txt",
        "rg --files /home/agent/.ssh",
        "grep private_key",
        "grep -rn private_key src/",
        "rg /home/agent/project/src/main.rs",
        "grep /etc/hosts",
        "rg /home/agent/..",
        "grep ~/notes.txt",
        "grep /home/agent/.secrets/key.txt -",
        "cat /home/agent/.secrets/key.txt",
    ] {
        assert!(
            !names_dotpath(command),
            "{command} must stay an ordinary search"
        );
    }
}

#[test]
fn quoted_and_escaped_less_than_are_not_input_redirects() {
    use crate::shell_secret_read_stdin_search::has_input_redirect_syntax;
    assert!(!has_input_redirect_syntax("grep '/home/agent/.config/a<b'"));
    assert!(!has_input_redirect_syntax(r"grep /home/agent/.config/a\<b"));
    assert!(!has_input_redirect_syntax(
        "grep /home/agent/.config/tool # < ignored"
    ));
    assert!(has_input_redirect_syntax(
        "grep /home/agent/.config/tool < notes.txt"
    ));
}

#[test]
fn a_whole_command_floors_only_an_unfed_lone_dotpath_search() {
    let model = |command: &str| {
        crate::parse_command(
            &serde_json::from_value(serde_json::json!({"command": command})).unwrap(),
        )
        .unwrap()
    };
    for command in [
        "grep /home/agent/.secrets/key.txt",
        "rg ~/.secrets/key.txt",
        // The option's quoted value must never settle an unquoted secret
        // pattern even when the bytes are identical.
        "rg --glob='~/.ssh/id_rsa' ~/.ssh/id_rsa",
        "rg ~/.ssh/id_rsa --glob='~/.ssh/id_rsa'",
        "cd /tmp && fgrep /home/agent/.secrets/key.txt",
        "grep '/home/agent/.config/a<b'",
        "grep \"$HOME/.ssh/id_rsa\"",
        // Empty quotes immediately before $HOME do not prevent expansion.
        "grep ''$HOME/.ssh/id_rsa",
        "rg ''$HOME/.ssh/id_rsa",
        // Empty quotes do not prevent the later expansion.
        "grep ''$HOME/.config/example",
        // Quoted decoys in assignments and option values must not disguise
        // an independently expanding HOME pattern.
        "X='$HOME'/.ssh/id_rsa grep \"$HOME\"/.ssh/id_rsa",
        "rg --glob='$HOME'/.ssh/id_rsa \"$HOME\"/.ssh/id_rsa",
        "grep -A '$HOME'/.ssh/id_rsa \"$HOME\"/.ssh/id_rsa",
        "grep $HOME/.ssh/id_rsa #'$HOME/.ssh/id_rsa",
        "rg '/home/agent/.ssh/id_rsa'",
    ] {
        assert!(
            crate::shell_secret_read_stdin_search::lone_home_dotpath_search(
                &model(command),
                Some(HOME)
            ),
            "{command}"
        );
    }
    for command in [
        "ps aux | grep /home/agent/.ssh/id_rsa",
        "grep /home/agent/.ssh/id_rsa < notes.txt",
        "grep -rn /home/agent/.ssh/id_rsa .",
        "grep -c TODO README.md",
        "rg '~/.ssh/id_rsa'",
        "grep \"~/.ssh/id_rsa\"",
        "rg '$HOME/.aws/credentials'",
        // A quoted HOME marker joined to an unquoted path suffix is still literal.
        "grep '$HOME'/.config/example",
        "rg '$HOME'/.ssh/id_rsa",
        "grep '${HOME}'/.aws/credentials",
        "rg '~'/.ssh/id_rsa",
        r"grep \$HOME/.aws/credentials",
        r#"grep "\$HOME/.aws/credentials""#,
        r"rg \~/.ssh/id_rsa",
    ] {
        assert!(
            !crate::shell_secret_read_stdin_search::lone_home_dotpath_search(
                &model(command),
                Some(HOME)
            ),
            "{command}"
        );
    }
}

#[cfg(unix)]
#[test]
fn either_spelling_of_a_symlinked_home_matches() {
    let root = std::env::temp_dir().join(format!("lone-dotpath-{}", std::process::id()));
    let real = root.join("real");
    std::fs::create_dir_all(real.join(".secrets")).unwrap();
    let link = root.join("link");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let pattern = format!("{}/.secrets/key.txt", link.display());
    let args = vec![pattern];
    assert!(lone_search_pattern_names_home_dotpath(
        "grep",
        &args,
        Some(&real)
    ));
    let args = vec![format!("{}/.secrets/key.txt", real.display())];
    assert!(lone_search_pattern_names_home_dotpath(
        "grep",
        &args,
        Some(&link)
    ));
    std::fs::remove_dir_all(&root).unwrap();
}
