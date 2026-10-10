//! Heredoc scanner regression tests.

use crate::shell_structure::{extract_heredocs, mask_complete_heredocs, mask_heredoc_bodies};

#[test]
fn here_strings_do_not_mask_following_package_commands() {
    for word in ["EOF", "'EOF'", "\"EOF\"", "x"] {
        for prefix in ["cat ", "printf 'é🙂' | cat ", "printf \\é | cat "] {
            let command = format!("{prefix}<<<{word}\nnpm install lodash");
            let heredocs = extract_heredocs(&command);
            assert!(heredocs.is_empty(), "{command}");
            assert_eq!(mask_heredoc_bodies(&command, &heredocs), command);
        }
    }
}

#[test]
fn real_heredocs_mask_bodies_and_preserve_following_commands() {
    for (declaration, quoted, strip_tabs, body, closing) in [
        ("EOF", false, false, "npm install hidden\n", "EOF"),
        ("'EOF'", true, false, "npm install hidden\n", "EOF"),
        ("\"EOF\"", true, false, "npm install hidden\n", "EOF"),
        ("-EOF", false, true, "\tnpm install hidden\n", "\tEOF"),
        ("--END", false, true, "npm install hidden\n", "-END"),
        ("---END", false, true, "npm install hidden\n", "--END"),
    ] {
        for prefix in ["cat ", "printf 'é🙂' | cat ", "printf \\é | cat "] {
            let command = format!("{prefix}<<{declaration}\n{body}{closing}\nnpm install visible");
            let heredocs = extract_heredocs(&command);
            assert_eq!(heredocs.len(), 1, "{command}");
            let heredoc = &heredocs[0];
            assert_eq!(heredoc.body, body);
            assert_eq!(heredoc.quoted, quoted);
            assert_eq!(heredoc.strip_tabs, strip_tabs);
            assert_eq!(heredoc.operator_start, prefix.chars().count());
            assert_eq!(
                heredoc.declaration_end,
                prefix.chars().count() + 2 + declaration.chars().count()
            );
            let masked = mask_heredoc_bodies(&command, &heredocs);
            assert!(!masked.contains("npm install hidden"), "{command}");
            assert!(masked.ends_with("\nnpm install visible"), "{command}");
        }
    }
}

#[test]
fn tab_stripping_heredoc_with_hyphen_delimiter_closes_at_the_bash_delimiter() {
    let command = "cat <<--END\nx\n-END\nnpm install malicious\n--END";
    let heredocs = extract_heredocs(command);
    assert_eq!(heredocs.len(), 1);
    assert_eq!(heredocs[0].delimiter, "-END");
    assert!(heredocs[0].strip_tabs);
    assert!(mask_heredoc_bodies(command, &heredocs).contains("npm install malicious"));
}

#[test]
fn here_string_before_real_heredoc_does_not_consume_its_body() {
    let command =
        "cat <<<x; printf 'é🙂' | cat <<'EOF'\nnpm install hidden\nEOF\nnpm install visible";
    let heredocs = extract_heredocs(command);
    assert_eq!(heredocs.len(), 1);
    assert_eq!(heredocs[0].delimiter, "EOF");
    assert_eq!(heredocs[0].body, "npm install hidden\n");
    let masked = mask_heredoc_bodies(command, &heredocs);
    assert!(masked.starts_with("cat <<<x;"));
    assert!(!masked.contains("npm install hidden"));
    assert!(masked.ends_with("\nnpm install visible"));
}

#[test]
fn delimiter_prefixes_preserve_unmatched_header_suffixes() {
    for (header, delimiter, quoted, strip_tabs, declaration_end, masked_prefix) in [
        ("cat <<EOF-tail", "EOF", false, false, 9, "cat      -tail\n"),
        ("cat <<EOFé", "EOF", false, false, 9, "cat      é\n"),
        ("cat <<_9.name", "_9", false, false, 8, "cat     .name\n"),
        ("cat <<--9-A_.", "-9-A_", false, true, 12, "cat         .\n"),
        ("cat <<---END", "--END", false, true, 12, "cat         \n"),
        ("cat << 'EOF'x", "EOF", true, false, 12, "cat         x\n"),
        ("cat <<\t\"EOF\"", "EOF", true, false, 12, "cat         \n"),
    ] {
        let command = format!("{header}\nprivate\n{delimiter}\nnpm install visible");
        let heredocs = extract_heredocs(&command);
        assert_eq!(heredocs.len(), 1, "{header}");
        let heredoc = &heredocs[0];
        assert_eq!(heredoc.delimiter, delimiter, "{header}");
        assert_eq!(heredoc.body, "private\n", "{header}");
        assert_eq!(heredoc.quoted, quoted, "{header}");
        assert_eq!(heredoc.strip_tabs, strip_tabs, "{header}");
        assert_eq!(heredoc.operator_start, 4, "{header}");
        assert_eq!(heredoc.declaration_end, declaration_end, "{header}");
        let masked = mask_complete_heredocs(&command, &heredocs);
        assert!(masked.starts_with(masked_prefix), "{header}: {masked:?}");
        assert!(!masked.contains("private"), "{header}");
        assert!(masked.ends_with("\nnpm install visible"), "{header}");
    }
}

#[test]
fn invalid_or_nested_declarations_leave_following_commands_visible() {
    for header in [
        "cat <<",
        "cat <<9EOF",
        "cat <<é",
        "cat <<--_END",
        "cat <<--é",
        "cat <<----END",
        "cat <<\u{00a0}EOF",
        "cat <<\rEOF",
        "cat <<'EOF\"",
        "cat <<'EOF",
        "cat <<\"EOF-tail\"",
        "printf '<<EOF'",
        "printf \"<<EOF\"",
        "printf \"$(cat <<EOF)\"",
        "printf \u{0060}cat <<EOF\u{0060}",
        "(cat <<EOF)",
        "cat \\<<EOF",
    ] {
        let command = format!("{header}\nnpm install visible\nEOF\nnpm install after");
        let heredocs = extract_heredocs(&command);
        assert!(heredocs.is_empty(), "{header}");
        assert_eq!(
            mask_heredoc_bodies(&command, &heredocs),
            command,
            "{header}"
        );
    }
}

#[test]
fn quoted_command_substitution_keeps_unicode_character_offsets() {
    let command = "🙂 \"$(cat <<BAD)\" <<E\nx\nE\ny";
    let heredocs = extract_heredocs(command);
    assert_eq!(heredocs.len(), 1);
    let heredoc = &heredocs[0];
    assert_eq!(heredoc.delimiter, "E");
    assert_eq!(heredoc.body, "x\n");
    assert_eq!(heredoc.operator_start, 17);
    assert_eq!(heredoc.declaration_end, 20);
    assert_eq!(heredoc.body_start, 21);
    assert_eq!(heredoc.body_end, 23);
    assert_eq!(heredoc.end, 25);
    assert_eq!(
        mask_heredoc_bodies(command, &heredocs),
        "🙂 \"$(cat <<BAD)\" <<E\n \n \ny"
    );
}
