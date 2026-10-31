//! A heredoc the shell opens partway through a line is still a heredoc. The
//! delimiter parse ran to the end of the line, so a redirect or a pipe after
//! the delimiter left the shape unparseable, and an unparseable shape has no
//! floor to reach: it blocks outright, with no approval row, while the same
//! text without the redirect reaches an ordinary review.
use super::super::tests::{controls, decision};
use super::{first_heredoc, input_heredoc};

const FAILED: &str = "native_command_extension_evaluation_failed";

#[test]
fn a_delimiter_stops_at_the_word_that_names_it() {
    let heredoc = first_heredoc("sort <<'EOF' > out.txt\nb\na\nEOF").unwrap();
    assert_eq!(heredoc.before, "sort ");
    assert_eq!(heredoc.delimiter, "EOF");
    assert_eq!(heredoc.trailing, " > out.txt");
    assert!(heredoc.quoted);
    let heredoc = first_heredoc("sort <<EOF | head -1\nb\nEOF").unwrap();
    assert_eq!(heredoc.delimiter, "EOF");
    assert_eq!(heredoc.trailing, " | head -1");
    assert!(!heredoc.quoted);
    // `<<-` strips the body's leading tabs. It names the same delimiter.
    let heredoc = first_heredoc("cat <<-'EOF' > f\n\tb\n\tEOF").unwrap();
    assert_eq!(heredoc.delimiter, "EOF");
    assert_eq!(heredoc.trailing, " > f");
    // Punctuation belongs to an unquoted delimiter as much as letters do.
    let heredoc = first_heredoc("cat <<END-OF-FILE\nb\nEND-OF-FILE").unwrap();
    assert_eq!(heredoc.delimiter, "END-OF-FILE");
    assert_eq!(heredoc.trailing, "");
}

#[test]
fn a_line_that_names_no_delimiter_opens_no_heredoc() {
    for text in [
        // A here-string reads a word, not a body.
        "cat <<< \"x\"\nmore",
        // The line never closes the quote it opened.
        "cat <<'EOF > out.txt\nEOF",
        // A second heredoc on the line feeds an input this reading leaves out.
        "cat <<'A' <<'B'\nA\nB",
        // The shell ends these words at `EOFx`, `EOF` and `EOF`, none of
        // which is the text a quote-stripping read of the line would take.
        "cat <<'EOF'x\nEOF\nEOFx",
        "cat <<'EO''F'\nEO\nEOF",
        "cat <<E\\OF\nEOF",
        // The line closes the quote it opened with the other quote.
        "cat <<'EOF\"\nEOF",
    ] {
        assert!(first_heredoc(text).is_none(), "{text}");
    }
}

#[test]
fn a_heredoc_followed_by_a_literal_redirect_or_a_pipe_is_input() {
    for text in [
        "sort <<'EOF' > out.txt\nb\na\nEOF",
        "sort <<'EOF' | head -1\nb\na\nEOF",
        "sort > out.txt <<'EOF'\nb\na\nEOF",
        "grep foo <<'EOF'\nfoo\nEOF",
    ] {
        assert!(input_heredoc(text), "{text}");
    }
}

#[test]
fn the_rest_of_the_line_still_answers_for_what_it_moves() {
    for text in [
        // An assignment outlives the command the heredoc feeds.
        "FOO=1 sort <<'EOF' > out.txt\nb\nEOF",
        "export OUT=out.txt && sort <<'EOF' > out.txt\nb\nEOF",
        // An unquoted delimiter leaves the body free to run a substitution.
        "sort <<EOF > out.txt\n$(id)\nEOF",
        // Nothing closes the body, so the delimiter names no end to it.
        "sort <<'EOF' > out.txt\nb\n",
        "sort <<'EOF' > out.txt\nb\nEOF extra",
    ] {
        assert!(!input_heredoc(text), "{text}");
    }
}

#[test]
fn a_heredoc_with_a_redirect_or_a_pipe_reaches_a_review_and_not_a_dead_end() {
    let controls = controls(serde_json::json!([]), false);
    for command in [
        "sort <<'EOF' > out.txt\nb\na\nEOF",
        "sort <<'EOF' | head -1\nb\na\nEOF",
        "jq . <<'EOF' > parsed.json\n{}\nEOF",
    ] {
        let (action, reason) = decision(&controls, command);
        assert_ne!(reason, FAILED, "{command}");
        assert_ne!(action, "block", "{command}");
    }
}
