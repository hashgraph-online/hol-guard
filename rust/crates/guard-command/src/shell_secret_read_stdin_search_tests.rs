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
fn search_lane_stops_vouching_for_a_lone_home_dotpath() {
    use crate::codex_output_env::Ctx;
    use crate::sfrs_developer_inspection::read_only_lookup_search_args_are_safe;
    use crate::sfrs_token_vectors::NoEnvHost;
    let host = NoEnvHost;
    let ctx = Ctx::new(&host, "/", "/");
    let home = Some(Path::new(HOME));
    let (name, args) = words("grep /home/agent/.secrets/key.txt");
    assert!(!read_only_lookup_search_args_are_safe(
        &name, &args, home, &ctx
    ));
    let (name, args) = words("grep ~/.secrets/key.txt");
    assert!(!read_only_lookup_search_args_are_safe(
        &name, &args, None, &ctx
    ));
    // With no home to resolve against, only the `~/` spelling is known.
    let (name, args) = words("grep -n needle");
    assert!(read_only_lookup_search_args_are_safe(
        &name, &args, None, &ctx
    ));
}

#[test]
fn quoted_and_escaped_less_than_are_not_input_redirects() {
    use crate::shell_secret_read_stdin_search::has_input_redirect_syntax;
    assert!(!has_input_redirect_syntax("grep '/home/agent/.config/a<b'"));
    assert!(!has_input_redirect_syntax(r"grep /home/agent/.config/a\<b"));
    assert!(!has_input_redirect_syntax("grep /home/agent/.config/tool # < ignored"));
    assert!(has_input_redirect_syntax("grep /home/agent/.config/tool < notes.txt"));
}

#[test]
fn a_whole_command_floors_only_an_unfed_lone_dotpath_search() {
    let model = |command: &str| {
        crate::parse_command(
            &serde_json::from_value(serde_json::json!({"command": command})).unwrap(),
        )
        .unwrap()
    };
    let context = crate::pretool::PathContext {
        home_dir: Some(HOME),
        ..Default::default()
    };
    for command in [
        "grep /home/agent/.secrets/key.txt",
        "rg ~/.secrets/key.txt",
        "cd /tmp && fgrep /home/agent/.secrets/key.txt",
        "grep '/home/agent/.config/a<b'",

    ] {
        assert!(
            crate::pretool::lone_home_dotpath_search(&model(command), context),
            "{command}"
        );
    }
    for command in [
        "ps aux | grep /home/agent/.ssh/id_rsa",
        "grep /home/agent/.ssh/id_rsa < notes.txt",
        "grep -rn /home/agent/.ssh/id_rsa .",
        "grep -c TODO README.md",
    ] {
        assert!(
            !crate::pretool::lone_home_dotpath_search(&model(command), context),
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
