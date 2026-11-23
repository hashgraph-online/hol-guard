use super::writes_nothing;

fn step(command: &str, program: &str) -> Option<crate::CommandSegmentV1> {
    let model = crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap();
    model
        .segments
        .into_iter()
        .find(|segment| segment.executable.as_deref() == Some(program))
}

// A listing walks its roots and prints names; where the roots are is a read
// question, not a write one.
#[test]
fn a_listing_find_writes_nothing_wherever_it_walks() {
    for command in [
        r#"find "$HOME/Downloads/widgets-1.4.0" -maxdepth 1 -type f -print | sort"#,
        r#"find "${HOME}/notes" -type f -name '*.md'"#,
        "find /var/tmp/build -maxdepth 2 -type d",
        "find . -name '*.js' -not -path './node_modules/*' 2>/dev/null",
        "find -P src -type f -newer package.json -print",
    ] {
        assert!(
            step(command, "find").is_some_and(|find| writes_nothing(&find)),
            "{command}"
        );
    }
}

// Actions, a file the shell or `find` writes, and words that can reach `find`
// as something other than what is written all keep the review.
#[test]
fn a_find_that_can_write_or_change_its_words_keeps_review() {
    for command in [
        "find . -name '*.tmp' -delete",
        "find . -type f -exec rm {} +",
        "find . -type f -execdir touch {} ;",
        "find . -fprint listing.txt",
        "find . -fls listing.txt",
        "find . -type f -print > listing.txt",
        // A redirect to /dev/nullx is a real file write, not /dev/null.
        "find . -type f -print 2>/dev/nullx",
        "find . -type f -print >/dev/null-output",
        "find . -type f -ok rm {} ;",
        "find . -name {a,-delete}",
        "find * -maxdepth 0 -print",
        "find . -name *.tmp",
        "find $ROOT -print",
        r#"find "$ROOT" -print"#,
        r#"find "$HOMEX/a" -print"#,
        r#"find "$HOME$(id)" -print"#,
        "find `pwd` -print",
        // A quoted copy of a glob does not quote the unquoted one beside it.
        r#"find "'*'" * -print"#,
        // A `$HOME` after a closing quote is unquoted.
        r#"find "a"$HOME/x -print"#,
        r"find \-delete -print",
    ] {
        // `-exec` bodies are modelled as the programs they run, so some of
        // these never reach the proof as a `find` at all.
        assert!(
            step(command, "find").is_none_or(|find| !writes_nothing(&find)),
            "{command}"
        );
    }
}

// A print, substitution or stream edit reads lines and writes standard output.
#[test]
fn a_printing_sed_writes_nothing_wherever_it_reads() {
    for command in [
        r#"sed -n '1,240p' "$HOME/.config/tool/notes.md""#,
        "sed -n '5p;9,12p' /etc/hosts",
        "sed -n '1p' README.md 2>/dev/null",
        "sed -e 's/a/b/' -e 's/c/d/' README.md",
        "sed '1d;$d' data.txt",
        "rg --files | sed -n '1,160p'",
    ] {
        assert!(
            step(command, "sed").is_some_and(|sed| writes_nothing(&sed)),
            "{command}"
        );
    }
}

// In-place edits, the commands and flags that write or run, an option among
// the files and a redirect keep the review.
#[test]
fn a_sed_that_can_write_keeps_review() {
    for command in [
        "sed -i 's/a/b/' README.md",
        "sed -i.bak 's/a/b/' README.md",
        "sed -n '1p' README.md -i",
        "sed 's/a/b/' README.md --in-place",
        "sed -n '1w out.txt' README.md",
        "sed 's/a/b/w out.txt' README.md",
        "sed '1r other.txt' README.md",
        "sed 's/a/date/e' README.md",
        "sed -f script.sed README.md",
        "sed -n '1,5p' README.md > out.txt",
        "sed -n '1p' README.md 2>/dev/nullx",
        "sed -n '1p' README.md >/dev/null-output",
        "sed -n '1,5p' $FILE",
        "sed -n '1,5p' *.md",
    ] {
        assert!(
            step(command, "sed").is_none_or(|sed| !writes_nothing(&sed)),
            "{command}"
        );
    }
}

// A prefix of /dev/null names a different, writable file. The parser keeps no
// step for these, so no proof can start from them; if it ever does, the
// redirect word check still has to refuse it.
#[test]
fn redirection_lookalikes_never_count_as_write_free() {
    for (command, program) in [
        ("find . -type f -print 2>/dev/nullx", "find"),
        ("find . -type f -print >/dev/null-output", "find"),
        ("sed -n '1p' README.md 2>/dev/nullx", "sed"),
        ("sed -n '1p' README.md >/dev/null-output", "sed"),
    ] {
        assert!(
            step(command, program).is_none_or(|segment| !writes_nothing(&segment)),
            "{command}"
        );
    }
    for text in [
        "find . -type f -print 2>/dev/nullx",
        "find . -type f -print >/dev/null-output",
    ] {
        let mut segment = step("find . -type f -print", "find").expect("plain find parses");
        segment.text = text.to_owned();
        assert!(!writes_nothing(&segment), "{text}");
    }
}
