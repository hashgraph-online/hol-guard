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
fn an_awk_listing_of_environment_names_is_proven() {
    for command in [
        "awk 'BEGIN { for (name in ENVIRON) print name }'",
        "awk 'BEGIN{for(k in ENVIRON)print k}' | sort",
        "awk 'BEGIN { for (k in ENVIRON) print k }' | sort -u | head -40",
    ] {
        assert!(proven(command), "{command}");
    }
}

/// A dump of the environment renders every value before any filter sees it,
/// and a value with a newline in it reaches the filter as a line of its own,
/// so no filter over it is proven.
#[test]
fn a_dump_piped_into_any_filter_is_refused() {
    for command in [
        "printenv",
        "printenv | grep -oE '^(PATH|HOME)[A-Z_]*'",
        "printenv | grep -oE '^AKIA[A-Z0-9_]*'",
        "printenv | grep -oE '^ALPHAHOST[A-Z_]*' | sort -u | head -40",
        "printenv | cut -d= -f1",
        "printenv | awk -F= '{print $1}'",
        "printenv | awk 'BEGIN { for (k in ENVIRON) print k }'",
        "env | grep -oE '^(PATH|HOME)[A-Z_]*'",
    ] {
        assert!(!proven(command), "{command}");
    }
}

#[test]
fn anything_that_could_render_a_value_or_reach_further_is_refused() {
    for command in [
        "awk 'BEGIN { for (k in ENVIRON) print k, ENVIRON[k] }'",
        "awk 'BEGIN { for (k in ENVIRON) print ENVIRON[k] }'",
        "awk 'BEGIN { for (k in ENVIRON) print k }' > names.txt",
        "awk 'BEGIN { for (k in ENVIRON) print k }' | sort -o /tmp/names",
        "awk 'BEGIN { for (k in ENVIRON) print k }' | xargs -n1 printenv",
        "awk 'BEGIN { for (k in ENVIRON) print k }' | sh",
        "awk 'BEGIN { for (k in ENVIRON) print k }' | cat secrets.txt",
        "awk 'BEGIN { for (k in ENVIRON) print k }' ; printenv",
        "awk -f names.awk",
        "SECRET=1 awk 'BEGIN { for (k in ENVIRON) print k }'",
        "/tmp/awk 'BEGIN { for (k in ENVIRON) print k }'",
        "awk 'BEGIN { for (k in ENVIRON) print k }' | /tmp/sort -u",
    ] {
        assert!(!proven(command), "{command}");
    }
}
