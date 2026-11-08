use super::*;
use crate::command_parse_surface::{parse_command, CommandModelRequestV1};

fn proven(command: &str) -> bool {
    let model = parse_command(&CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .expect(command);
    exact_safe_command(&model)
}

#[test]
fn a_dump_piped_into_a_name_filter_is_proven() {
    for command in [
        "printenv | grep -oE '^(ALPHAHOST|BETAHOST)[A-Z_]*'",
        "printenv | grep -oE '^ALPHAHOST[A-Z_]*' | sort",
        "printenv | grep -oE '^ALPHAHOST[A-Z_]*' | sort -u | head -40",
    ] {
        assert!(proven(command), "{command}");
    }
}

#[test]
fn anything_that_could_render_a_value_is_refused() {
    for command in [
        "printenv",
        "printenv | cut -d= -f1",
        "printenv | awk -F= '{print $1}'",
        "printenv | sort | head",
        "printenv | grep x",
        "printenv | grep -oE '^ALPHA|[A-Za-z0-9_]+'",
        "printenv PATH | grep -oE '^ALPHA[A-Z_]*'",
        "printenv ; grep -oE '^ALPHA[A-Z_]*'",
        "printenv | grep -oE '^ALPHA[A-Z_]*' > names.txt",
        "printenv | grep -oE '^ALPHA[A-Z_]*' | xargs -n1 printenv",
        "printenv | grep -oE '^ALPHA[A-Z_]*' | sh",
        "printenv | grep -oE '^ALPHA[A-Z_]*' | cat secrets.txt",
        "printenv | grep -oE '^ALPHA[A-Z_]*' | sort -o /tmp/names",
        "printenv | tee all.txt | grep -oE '^ALPHA[A-Z_]*'",
        "SECRET=1 printenv | grep -oE '^ALPHA[A-Z_]*'",
    ] {
        assert!(!proven(command), "{command}");
    }
}

/// The basename of a path is not the program the shell runs. `/tmp/sort`
/// carries the name of a stage this proof trusts while running whatever the
/// agent put there, so the qualified name refuses the pipeline.
#[test]
fn a_path_qualified_stage_is_refused() {
    assert!(!proven("printenv | /tmp/grep -oE '^ALPHAHOST[A-Z_]*'"));
    assert!(!proven(
        "printenv | grep -oE '^ALPHAHOST[A-Z_]*' | /tmp/sort -u"
    ));
}

/// A bare `env` is a command prefix, so the parser cannot say with certainty
/// what it runs and the model arrives `uncertain`. The pipeline keeps its
/// review rather than resting a proof on a model that is not exact.
#[test]
fn a_bare_env_prefix_is_left_to_review() {
    assert!(!proven("env | grep -oE '^ALPHAHOST[A-Z_]*'"));
}
