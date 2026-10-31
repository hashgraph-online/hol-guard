use super::*;

fn names(text: &str) -> Vec<String> {
    parse_cli_help_text(text, None, &[])
        .into_iter()
        .map(|command| command.name)
        .collect()
}

#[test]
fn a_commands_section_names_its_rows() {
    let help = "Usage: tool [options]\n\nCommands:\n  build   Build it\n  ship    Ship it\n";
    let parsed = parse_cli_help_text(help, None, &[]);
    assert_eq!(names(help), vec!["build", "ship"]);
    assert_eq!(parsed[0].description, "Build it");
    assert_eq!(parsed[0].command_id, "build");
    assert_eq!(parsed[0].usage, "build");
    assert!(parsed[0].parent_id.is_none());
}

#[test]
fn a_blank_line_closes_the_section() {
    let help = "Commands:\n  build   Build it\n\nnotacommand   prose\n";
    assert_eq!(names(help), vec!["build"]);
}

#[test]
fn help_and_completion_rows_are_never_commands() {
    let help = "Commands:\n  help   Show help\n  completions  Shell completions\n  run  Run\n";
    assert_eq!(names(help), vec!["run"]);
}

#[test]
fn an_argparse_choice_set_names_its_commands() {
    let help = "positional arguments:\n  {add,remove,list}\n";
    assert_eq!(names(help), vec!["add", "remove", "list"]);
}

#[test]
fn a_choice_set_is_read_even_without_a_section() {
    assert_eq!(
        names("usage: tool {add,remove} ...\n"),
        vec!["add", "remove"]
    );
}

#[test]
fn a_yargs_group_counts_only_invocation_prefixed_rows() {
    let help = concat!(
        "ACCOUNT\n",
        "  wrangler d1 create   Create a database\n",
        "  some prose that is not a row\n",
        "EXAMPLES\n",
        "  wrangler d1 execute  Should not count\n",
    );
    let invocation = vec!["wrangler".to_owned(), "d1".to_owned()];
    let parsed = parse_cli_help_text(help, None, &invocation);
    assert_eq!(
        parsed.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        vec!["create"]
    );
    assert_eq!(parsed[0].description, "Create a database");
}

#[test]
fn a_parent_id_keys_every_command_under_it() {
    let help = "Commands:\n  create  Make one\n";
    let parsed = parse_cli_help_text(help, Some("d1"), &[]);
    assert_eq!(parsed[0].command_id, "d1.create");
    assert_eq!(parsed[0].parent_id.as_deref(), Some("d1"));
}

#[test]
fn the_same_command_is_recorded_once() {
    let help = "Commands:\n  build  First\n  build  Second\n";
    let parsed = parse_cli_help_text(help, None, &[]);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].description, "First");
}

#[test]
fn a_description_is_cut_at_two_hundred_characters() {
    let help = format!("Commands:\n  build  {}\n", "x".repeat(250));
    let parsed = parse_cli_help_text(&help, None, &[]);
    assert_eq!(parsed[0].description.chars().count(), 200);
}

#[test]
fn an_option_row_is_not_a_command() {
    let help = "Commands:\n  --verbose  Be loud\n  build  Build it\n";
    assert_eq!(names(help), vec!["build"]);
}

#[test]
fn a_one_word_header_closes_the_section() {
    let help = "Commands:\n  build  Build it\nOptions:\n  verbose  Say more\n";
    assert_eq!(names(help), vec!["build"]);
}

#[test]
fn a_two_word_header_reads_as_a_row_and_keeps_the_section_open() {
    // `Other things:` splits into a name and a description, so the parse
    // cannot tell it from a command row. Python does the same.
    let help = "Commands:\n  build  Build it\nOther things:\n  ship  Ship it\n";
    assert_eq!(names(help), vec!["build", "Other", "ship"]);
}

/// Decisions recorded from the Python parser this module replaced. Each
/// case was produced by handing the same text, parent and invocation to
/// `runtime/local_cli_help.parse_cli_help_text`, so a disagreement here is
/// a behaviour change, not a style difference.
#[test]
fn recorded_python_decisions_replay() {
    const FIXTURE: &str =
        include_str!("../../../../tests/fixtures/guard-local-cli-help-parse.v1.json");
    let document: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    assert_eq!(
        document["schema"], "guard-local-cli-help-parse-parity.v1",
        "fixture schema moved"
    );
    let cases = document["cases"].as_array().expect("cases");
    assert!(cases.len() >= 20, "the fixture records too few cases");
    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let invocation: Vec<String> = case["invocation"]
            .as_array()
            .expect("invocation")
            .iter()
            .map(|word| word.as_str().expect("invocation word").to_owned())
            .collect();
        let parsed = parse_cli_help_text(
            case["text"].as_str().expect("case text"),
            case["parent_id"].as_str(),
            &invocation,
        );
        assert_eq!(
            serde_json::to_value(&parsed).expect("commands serialise"),
            case["expected"],
            "case {name} disagrees with Python"
        );
    }
}

#[test]
fn a_request_under_another_schema_is_refused() {
    let request = LocalCliHelpParseRequestV1 {
        schema: "guard-local-cli-help-parse-request.v2".to_owned(),
        request_id: "local-cli-help-parse-test".to_owned(),
        text: "Commands:\n  build  Build it\n".to_owned(),
        parent_id: None,
        invocation: Vec::new(),
        script_source: false,
    };
    assert_eq!(
        evaluate_local_cli_help_parse_request(&request),
        Err("native_local_cli_help_parse_schema_mismatch".to_owned())
    );

    // The same request under the declared schema still answers.
    let request = LocalCliHelpParseRequestV1 {
        schema: LOCAL_CLI_HELP_PARSE_REQUEST_SCHEMA.to_owned(),
        ..request
    };
    assert!(evaluate_local_cli_help_parse_request(&request).is_ok());
}

fn ids(text: &str, parent_id: Option<&str>, script_source: bool) -> Vec<String> {
    commands_and_variations(text, parent_id, &["tool".to_owned()], script_source)
        .into_iter()
        .map(|command| command.command_id)
        .collect()
}

#[test]
fn help_without_subcommands_reports_its_options() {
    let help = "Usage: tool [--force]\n\nOptions:\n  --force  Skip checks\n";
    assert_eq!(ids(help, None, false), vec!["--force"]);
}

#[test]
fn help_with_subcommands_reports_only_the_subcommands() {
    let help = "Commands:\n  build  Build it\n\nOptions:\n  --force  Skip checks\n";
    assert_eq!(ids(help, None, false), vec!["build"]);
}

#[test]
fn a_nested_commands_help_is_never_read_for_options() {
    let help = "Options:\n  --force  Skip checks\n";
    assert!(ids(help, Some("deploy"), false).is_empty());
}

#[test]
fn a_script_brace_expansion_is_not_a_choice_set() {
    let script = "#!/bin/sh\n# Usage: tool [--clean]\nmkdir -p {src,dist}\n[ \"$1\" = \"--clean\" ] && rm -rf dist\n";
    assert_eq!(ids(script, None, true), vec!["--clean"]);
    // The same text read as help output keeps the choice-set reading.
    assert_eq!(ids(script, None, false), vec!["src", "dist"]);
}

#[test]
fn a_script_comment_commands_section_names_subcommands_beside_its_options() {
    let script = "#!/bin/sh\n# Commands:\n#   build  Build it\n#   ship   Ship it\n#\n# Options:\n#   --force  Skip\n";
    assert_eq!(ids(script, None, true), vec!["build", "ship", "--force"]);
}

#[test]
fn a_script_whose_comments_name_commands_still_reports_its_code_options() {
    let script = concat!(
        "#!/bin/sh\n",
        "# Commands:\n",
        "#   build  Build it\n",
        "case \"$1\" in\n",
        "  build) build ;;\n",
        "  --force) FORCE=1 ;;\n",
        "esac\n",
    );
    assert_eq!(ids(script, None, true), vec!["build", "--force"]);
}

#[test]
fn python_line_boundaries_and_whitespace_are_honoured() {
    // `\x1c` ends a line for `str.splitlines` and is whitespace for
    // `str.isspace`, so this row is indented and its section closes.
    let help = "Commands:\u{1c}\u{1f}build  Build it\u{1c}";
    assert_eq!(names(help), vec!["build"]);
}
