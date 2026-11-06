use super::*;

fn has(command: &str, spelling: &str) -> bool {
    spellings(command).texts.iter().any(|text| text == spelling)
}

#[test]
fn spacing_and_separators_read_as_the_command() {
    for command in [
        "  npm publish",
        "npm  publish",
        "npm publish ;",
        "npm publish &",
    ] {
        assert!(has(command, "npm publish"), "{command}");
    }
}

#[test]
fn each_step_of_a_line_is_listed() {
    for command in [
        "npm test && npm publish",
        "npm test; npm publish",
        "npm test || npm publish",
        "npm test | npm publish",
        "(npm publish)",
        "{ npm publish; }",
        "if true; then npm publish; fi",
        "npm publish > publish.log",
        "npm publish >publish.log 2>&1",
        "npm publish < /dev/null",
    ] {
        assert!(has(command, "npm publish"), "{command}");
    }
}

#[test]
fn prefixes_and_paths_read_as_the_program() {
    for command in [
        "CI=1 npm publish",
        "env CI=1 npm publish",
        "/usr/local/bin/npm publish",
        "bash -c 'npm publish'",
        "sh -lc \"npm publish\"",
        "bash -c '(npm publish)'",
    ] {
        assert!(has(command, "npm publish"), "{command}");
    }
}

#[test]
fn quoted_words_keep_their_quotes() {
    assert!(has(
        "git  commit -m 'two words'",
        "git commit -m 'two words'"
    ));
    assert!(has(
        "git  commit -m 'two words'",
        "git commit -m \"two words\""
    ));
}

#[test]
fn text_a_step_only_prints_is_not_a_step() {
    for command in [
        "echo npm publish",
        "echo \"x; npm publish\"",
        "echo '(npm publish)'",
        "git commit -m 'npm publish'",
        "cat <<EOF\nnpm publish\nEOF",
    ] {
        assert!(!has(command, "npm publish"), "{command}");
    }
}

#[test]
fn the_command_itself_is_not_listed() {
    let listed = spellings("npm publish");
    assert!(listed.texts.is_empty());
    assert!(listed.complete);
}

#[test]
fn a_padded_line_lists_every_step() {
    let line = (1..=60)
        .map(|n| format!("echo {n}"))
        .chain(["npm publish".to_owned()])
        .collect::<Vec<_>>()
        .join("; ");
    let listed = spellings(&line);
    assert!(listed.complete);
    assert!(listed.texts.iter().any(|text| text == "npm publish"));
    let grouped = format!("({line})");
    assert!(has(&grouped, "npm publish"));
}

#[test]
fn heredocs_and_shifts_do_not_hide_later_steps() {
    for command in [
        "cat <<EOF\nx\nEOF\nnpm publish",
        "cat <<'EOF' > notes\nx\nEOF\n(npm publish)",
        "cat <<-EOF\n\tx\n\tEOF\nnpm publish",
        "(npm publish); echo '<<'",
        "(npm publish) <<< x",
        "echo $((1<<2))\nnpm publish",
        "(echo $((1 << 2))); npm publish",
    ] {
        assert!(has(command, "npm publish"), "{command:?}");
    }
}

#[test]
fn an_unclosed_heredoc_is_read_as_steps() {
    assert!(has("cat <<EOF\nnpm publish", "npm publish"));
}

#[test]
fn quoted_spaces_are_kept_and_read_as_cloud_saves_them() {
    let command = "git  commit -m 'two  words'";
    assert!(has(command, "git commit -m 'two  words'"));
    assert!(has(command, "git commit -m 'two words'"));
    assert!(has(
        "(git commit -m 'two  words')",
        "git commit -m 'two words'"
    ));
}

#[test]
fn a_line_too_long_is_not_complete() {
    assert!(!spellings(&"x".repeat(MAX_COMMAND_BYTES + 1)).complete);
}

#[test]
fn nested_inline_scripts_list_the_inner_step() {
    let mut nested = "npm publish".to_owned();
    for _ in 0..4 {
        nested = format!("bash -c {}", quote(&nested));
    }
    assert!(has(&nested, "npm publish"), "{nested}");
}

fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

#[test]
fn quoted_heredoc_delimiters_do_not_hide_later_steps() {
    for command in [
        "cat <<'E O F'\nx\nE O F\nnpm publish",
        "cat <<'EOF;'\nx\nEOF;\nnpm publish",
        "cat <<\"END\"\nx\nEND\n(npm publish)",
    ] {
        assert!(has(command, "npm publish"), "{command:?}");
    }
}

#[test]
fn a_double_paren_bash_runs_as_groups_is_read_as_groups() {
    for command in ["((npm publish); true)", "((npm publish) )"] {
        assert!(has(command, "npm publish"), "{command}");
    }
}

#[test]
fn shell_options_before_the_script_are_skipped() {
    for command in [
        "bash -euo pipefail -c 'npm publish'",
        "bash -o pipefail -c 'npm publish'",
        "bash +o posix -c 'npm publish'",
        "bash --norc -c 'npm publish'",
        "bash --rcfile notes -c 'npm publish'",
        "sh -e -c -- 'npm publish'",
    ] {
        assert!(has(command, "npm publish"), "{command}");
    }
    assert!(!spellings("bash -c").complete);
}

#[test]
fn a_comment_does_not_start_a_heredoc_or_quote() {
    for command in [
        "(true) # <<EOF\nnpm publish\nEOF",
        "(true) # <<'E O F'\nnpm publish\nE O F",
    ] {
        assert!(has(command, "npm publish"), "{command:?}");
        assert!(spellings(command).complete, "{command:?}");
    }
    // A quote only the plain reading opens may be real, so the line asks.
    let apostrophe = "(true) # it's done\nnpm publish";
    assert!(has(apostrophe, "npm publish"));
    assert!(!spellings(apostrophe).complete);
}

#[test]
fn mixed_comment_readings_are_not_read_through() {
    let command = "(true); echo ${x:- #'}\n<<END '}  # '\nnpm publish\nEND";
    assert!(!spellings(command).complete, "{command:?}");
}

#[test]
fn arithmetic_that_lists_itself_is_complete() {
    let read = spellings("(( i++ ))");
    assert!(read.complete);
}

#[test]
fn a_hash_inside_an_expansion_is_also_read_as_text() {
    let command = "(true); echo ${x:- #'}\n<<EOF '}\nEOF\nnpm publish\nEOF";
    assert!(has(command, "npm publish"), "{command:?}");
}
