use super::*;

fn names_only(command: &str) -> bool {
    printenv_renders_only_names(command)
}

#[test]
fn a_dump_piped_into_a_name_filter_renders_no_value() {
    for command in [
        "printenv | cut -d= -f1",
        "printenv | cut -d = -f 1",
        "printenv | cut --delimiter== --fields=1",
        "printenv | awk -F= '{print $1}'",
        "printenv | awk -F '=' '{ print $1 }'",
        "printenv | grep -oE '^(ALPHAHOST|BETAHOST)[A-Z_]*'",
        "printenv | grep -o '^[A-Za-z_]*'",
        "printenv | cut -d= -f1 | sort | head -20",
    ] {
        assert!(names_only(command), "{command}");
    }
}

#[test]
fn a_stage_that_could_render_a_value_keeps_the_review() {
    for command in [
        // no filter at all
        "printenv",
        "printenv | sort | head",
        "printenv | grep x",
        // the filter keeps the value field
        "printenv | cut -d= -f2",
        "printenv | cut -d= -f1,2",
        "printenv | cut -d: -f1",
        "printenv | awk -F= '{print $2}'",
        "printenv | awk -F= '{print}'",
        "printenv | awk '{print $1}'",
        // the match can leave the name
        "printenv | grep -oE 'TOKEN'",
        "printenv | grep -oE '^.*'",
        "printenv | grep -oE '^[^=]*'",
        "printenv | grep -E '^[A-Z_]*'",
        "printenv | grep -oE '^[0-A]*'",
        // the dump reaches somewhere else first
        "printenv > /tmp/env.txt",
        "printenv | tee all.txt | cut -d= -f1",
        "printenv ; cut -d= -f1",
        // a named dump is not a bare one
        "printenv PATH | cut -d= -f1",
    ] {
        assert!(!names_only(command), "{command}");
    }
}

#[test]
fn a_bracket_expression_that_spans_the_separator_is_refused() {
    assert!(pattern_matches_inside_a_name("^[A-Z_]*"));
    assert!(pattern_matches_inside_a_name("^(a|b)[a-z0-9_]+"));
    assert!(!pattern_matches_inside_a_name("[A-Z_]*"));
    assert!(!pattern_matches_inside_a_name("^[^A]*"));
    assert!(!pattern_matches_inside_a_name("^[0-A]*"));
    assert!(!pattern_matches_inside_a_name("^a\\w*"));
    assert!(!pattern_matches_inside_a_name("^"));
}
