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
fn a_group_of_one_command_reads_as_that_command_wherever_it_stands() {
    // Braces group without a child shell, so one command inside them runs
    // exactly as it runs without them, whatever follows the group.
    assert_eq!(
        unwrap("{ pytest -q; } 2>&1").as_deref(),
        Some("pytest -q    2>&1")
    );
    assert_eq!(
        unwrap("{ npm test; } && echo done").as_deref(),
        Some("npm test    && echo done")
    );
    assert_eq!(unwrap("{ ls; } | wc -l").as_deref(), Some("ls    | wc -l"));
    assert_eq!(
        unwrap("npm test | { tee log; }").as_deref(),
        Some("npm test |   tee log")
    );
}

#[test]
fn a_group_that_does_not_end_the_command_keeps_a_list_body() {
    // Blanking these would end the pipeline or the conditional at the body's
    // own separator, which is not the command that was submitted.
    assert_eq!(unwrap("{ ls; cat Cargo.toml; } | head"), None);
    assert_eq!(unwrap("{ npm ci; npm test; } && echo done"), None);
    assert_eq!(unwrap("npm test | { tee log; cat log; }"), None);
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
    assert_eq!(unwrap("echo hi; echo there { npm test; }"), None);
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

#[test]
fn a_redirected_group_whose_body_redirects_keeps_its_braces() {
    // `> outer` collects nothing while the group holds it; blanking the braces
    // sends `printf` there instead, which is a different output target than
    // the one the submitted command writes to.
    assert_eq!(unwrap("{ printf x > inner; } > outer"), None);
    assert_eq!(unwrap("{ cat < seed; } < other"), None);
    // A redirection on one side alone reads the same either way.
    assert_eq!(
        unwrap("{ pytest -q; } 2>&1").as_deref(),
        Some("pytest -q    2>&1")
    );
    assert!(unwrap("{ printf x > inner; } | cat").is_some());
}

#[test]
fn a_newline_terminated_group_is_not_flattened_into_what_follows() {
    // The newline is not blanked with the braces, so it would leave the
    // operator that follows the group at the start of its own line.
    assert_eq!(unwrap("{ make\n} && rm -rf build"), None);
    assert_eq!(unwrap("{ cat seed\n} | wc -l"), None);
    assert_eq!(unwrap("npm test | { tee log\n}"), None);
    // Nothing follows this one, so the newline it ends on changes nothing.
    assert_eq!(unwrap("{ pytest -q\n}").as_deref(), Some("pytest -q"));
}

#[test]
fn a_newline_terminated_body_is_read_through_its_last_character() {
    // The `&` is the body's own last character rather than a blanked
    // terminator: inside the braces it backgrounds that command alone, and
    // flattened it would background the whole conditional list.
    assert_eq!(unwrap("cd web && { npm run watch &\n}"), None);
}
