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
        "printenv | cut -d= -f1",
        "printenv | awk -F= '{print $1}'",
        "printenv | grep -oE '^(ALPHAHOST|BETAHOST)[A-Z_]*'",
        "printenv | cut -d= -f1 | sort",
        "printenv | cut -d= -f1 | sort -u | head -40",
    ] {
        assert!(proven(command), "{command}");
    }
}

#[test]
fn anything_that_could_render_a_value_is_refused() {
    for command in [
        "printenv",
        "printenv | cut -d= -f2",
        "printenv | sort | head",
        "printenv | grep x",
        "printenv PATH | cut -d= -f1",
        "printenv ; cut -d= -f1",
        "printenv | cut -d= -f1 > names.txt",
        "printenv | cut -d= -f1 | xargs -n1 printenv",
        "printenv | cut -d= -f1 | sh",
        "printenv | cut -d= -f1 | cat secrets.txt",
        "printenv | tee all.txt | cut -d= -f1",
        "SECRET=1 printenv | cut -d= -f1",
    ] {
        assert!(!proven(command), "{command}");
    }
}

/// A bare `env` is a command prefix, so the parser cannot say with certainty
/// what it runs and the model arrives `uncertain`. The pipeline keeps its
/// review rather than resting a proof on a model that is not exact.
#[test]
fn a_bare_env_prefix_is_left_to_review() {
    assert!(!proven("env | cut -d= -f1"));
}
