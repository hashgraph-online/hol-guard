use super::unwrap;

#[test]
fn a_trailing_brace_group_reads_as_its_command_list() {
    assert_eq!(
        unwrap("{ npm run build; npm test; }").as_deref(),
        Some("npm run build; npm test")
    );
    assert_eq!(
        unwrap("cd web && { npm test; }").as_deref(),
        Some("cd web &&   npm test")
    );
    assert_eq!(unwrap("{\n  pytest -q\n}").as_deref(), Some("pytest -q"));
}

#[test]
fn a_group_that_does_not_end_the_command_keeps_its_review() {
    assert_eq!(unwrap("{ pytest -q; } 2>&1"), None);
    assert_eq!(unwrap("{ npm test; } && echo done"), None);
}

#[test]
fn brace_expansion_and_parameter_expansion_are_not_groups() {
    assert_eq!(unwrap("echo {a,b}"), None);
    assert_eq!(unwrap("{a,b}"), None);
    assert_eq!(unwrap("echo ${HOME}"), None);
    assert_eq!(unwrap("{ echo ${HOME}; }"), None);
}

#[test]
fn an_unterminated_list_is_not_a_group() {
    assert_eq!(unwrap("{ npm test }"), None);
    assert_eq!(unwrap("{ echo \"a;\" }"), None);
}

#[test]
fn a_quoted_or_escaped_brace_is_not_a_group() {
    assert_eq!(unwrap("echo '{ npm test; }'"), None);
    assert_eq!(unwrap("echo \"{ npm test; }\""), None);
    assert_eq!(unwrap("echo \\{ npm test; }"), None);
}

#[test]
fn a_group_that_does_not_open_a_list_element_is_not_unwrapped() {
    assert_eq!(unwrap("echo hi { npm test; }"), None);
    assert_eq!(unwrap("npm test | { tee log; }"), None);
}

#[test]
fn an_empty_or_oversized_group_is_refused() {
    assert_eq!(unwrap("{   }"), None);
    assert_eq!(unwrap(&format!("{{ echo {}; }}", "a".repeat(9000))), None);
    assert_eq!(unwrap("{ cat <<EOF; }"), None);
}

#[test]
fn a_conditional_list_keeps_the_group_that_makes_it_conditional() {
    // `npm test` runs only when `cd web` succeeded; the braces are the whole
    // of that, so the flattened text would not be the same command.
    assert_eq!(unwrap("cd web && { npm ci; npm test; }"), None);
    assert_eq!(unwrap("make || { git checkout .; git clean -fd; }"), None);
    assert_eq!(unwrap("cd web && {\n  npm ci\n  npm test\n}"), None);
    // A separator that is not conditional runs the same list either way.
    assert_eq!(
        unwrap("cd web; { npm ci; npm test; }").as_deref(),
        Some("cd web;   npm ci; npm test")
    );
    // One command behind the operator stays conditional once ungrouped.
    assert_eq!(
        unwrap("cd web && {\n  npm test\n}").as_deref(),
        Some("cd web &&  \n  npm test")
    );
}

#[test]
fn a_commented_terminator_or_brace_is_not_a_group() {
    // The shell sees `{ echo hi` with no closing brace and refuses the whole
    // command, so `echo hi #` must not be decided in its place.
    assert_eq!(unwrap("{ echo hi # ; }"), None);
    assert_eq!(unwrap("{ npm test; # }"), None);
    // A `#` inside a word is part of it, not a comment.
    assert_eq!(
        unwrap("{ git log --format=%h#%s; }").as_deref(),
        Some("git log --format=%h#%s")
    );
}

#[test]
fn an_operator_on_the_line_above_still_makes_the_list_conditional() {
    // The shell reads `make ||` and the group below it as one conditional
    // list, so flattening it would run `git checkout .` either way.
    assert_eq!(unwrap("make ||\n{ git checkout .; git clean -fd; }"), None);
    assert_eq!(unwrap("cd web &&\n{ npm ci; npm test; }"), None);
    // A comment can hold the operator the scan is looking for.
    assert_eq!(
        unwrap("make || # fall back\n{ git checkout .; git clean -fd; }"),
        None
    );
    // A newline that is the separator itself is not conditional.
    assert_eq!(
        unwrap("npm ci\n{ npm run build; npm test; }").as_deref(),
        Some("npm ci\n  npm run build; npm test")
    );
    // One command behind an operator on the line above means the same either
    // way, so it is still read as its list.
    assert_eq!(
        unwrap("make ||\n{ npm test; }").as_deref(),
        Some("make ||\n  npm test")
    );
}
