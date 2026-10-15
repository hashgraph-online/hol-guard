use super::{extract_heredocs, mask_heredoc_bodies};

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
        ("--END", false, false, "npm install hidden\n", "--END"),
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
