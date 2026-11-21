use super::*;

const HELP: &str = "Usage: tool <command>\n\nCommands:\n  build   Build the project\n  deploy  Deploy the project\n";

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn ids(commands: &[LocalCliCommand]) -> Vec<&str> {
    commands
        .iter()
        .map(|command| command.command_id.as_str())
        .collect()
}

#[test]
fn a_compiled_program_is_asked_for_help_and_each_command_once() {
    let mut asked: Vec<Vec<String>> = Vec::new();
    let mut probe = |argv: &[String]| {
        asked.push(argv.to_vec());
        if argv.len() == 2 {
            HELP.to_owned()
        } else {
            String::new()
        }
    };
    let (commands, status) = discover(
        "tool",
        "executable",
        &argv(&["/nonexistent/tool", "--help"]),
        &mut probe,
    );
    assert_eq!(status, Status::Ok);
    assert_eq!(ids(&commands), ["build", "deploy"]);
    assert_eq!(
        asked,
        [
            argv(&["/nonexistent/tool", "--help"]),
            argv(&["/nonexistent/tool", "build", "--help"]),
            argv(&["/nonexistent/tool", "deploy", "--help"]),
        ]
    );
}

#[test]
fn nested_help_adds_the_subcommands_under_their_parent() {
    let mut probe = |argv: &[String]| match argv.len() {
        2 => HELP.to_owned(),
        _ if argv[1] == "deploy" => {
            "Commands:\n  preview  Deploy a preview\n  prod     Deploy production\n".to_owned()
        }
        _ => String::new(),
    };
    let (commands, status) = discover(
        "tool",
        "executable",
        &argv(&["/nonexistent/tool", "--help"]),
        &mut probe,
    );
    assert_eq!(status, Status::Ok);
    assert_eq!(
        ids(&commands),
        ["build", "deploy", "deploy.preview", "deploy.prod"]
    );
    assert_eq!(commands[2].name, "deploy preview");
    assert_eq!(commands[2].parent_id.as_deref(), Some("deploy"));
}

#[test]
fn a_command_that_repeats_the_top_level_help_adds_nothing() {
    let mut probe = |_: &[String]| HELP.to_owned();
    let (commands, _) = discover(
        "tool",
        "executable",
        &argv(&["/nonexistent/tool", "--help"]),
        &mut probe,
    );
    assert_eq!(ids(&commands), ["build", "deploy"]);
}

#[test]
fn silent_help_is_a_failed_read() {
    let mut probe = |_: &[String]| String::new();
    let (commands, status) = discover(
        "tool",
        "executable",
        &argv(&["/nonexistent/tool", "--help"]),
        &mut probe,
    );
    assert!(commands.is_empty());
    assert_eq!(status, Status::Failed);
}

#[test]
fn a_script_that_never_checks_for_help_is_not_run() {
    let folder = tempfile::tempdir().unwrap();
    let script = folder.path().join("tool.sh");
    std::fs::write(&script, "#!/bin/sh\nrm -rf \"$1\"\n").unwrap();
    let script = script.to_string_lossy().into_owned();
    let mut asked = 0;
    let mut probe = |_: &[String]| {
        asked += 1;
        HELP.to_owned()
    };
    let (_, status) = discover(
        "tool",
        "script",
        &argv(&["/bin/sh", &script, "--help"]),
        &mut probe,
    );
    assert_eq!(asked, 0);
    assert_ne!(status, Status::Failed);
}

#[test]
fn the_first_of_each_command_id_is_kept() {
    let command = |id: &str, description: &str| LocalCliCommand {
        command_id: id.to_owned(),
        name: id.to_owned(),
        usage: String::new(),
        description: description.to_owned(),
        parent_id: None,
    };
    let kept = distinct([
        command("a", "help"),
        command("a", "source"),
        command("b", ""),
    ]);
    assert_eq!(ids(&kept), ["a", "b"]);
    assert_eq!(kept[0].description, "help");
}

#[test]
fn a_request_needs_a_known_kind_and_a_help_argv() {
    let answer = run_command(br#"{"name": "tool", "kind": "binary", "argv": ["/x", "--help"]}"#);
    assert_eq!(answer["ok"], json!(false));
    let answer = run_command(br#"{"name": "tool", "kind": "executable", "argv": ["/x"]}"#);
    assert_eq!(answer["ok"], json!(false));
}
