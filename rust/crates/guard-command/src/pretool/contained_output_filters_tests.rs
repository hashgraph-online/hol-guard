//! Which stages of a pipeline the contained route reads as filters.

use super::{
    head_tail_bound, matcher_stage, plain_source, rejoined_stage, rejoined_words, stdin_arguments,
    GREP_SWITCHES, RG_SWITCHES,
};

fn words(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn grep_reading_standard_input_is_a_filter() {
    for arguments in [
        &["FAIL"][..],
        &["-B", "3", "at async createViteServer"],
        &["-E", "FAIL|Error"],
        &["-i", "error"],
        &["-inv", "-A2", "-m", "5", "x"],
        &["-e", "FAIL", "-e", "Error"],
        &["--", "-x"],
    ] {
        assert!(
            stdin_arguments(&words(arguments), GREP_SWITCHES),
            "{arguments:?}"
        );
    }
}

#[test]
fn grep_naming_a_file_or_reading_patterns_is_not_a_filter() {
    for arguments in [
        &[][..],
        &["x", "notes.txt"],
        &["x", "/home/user/.aws/credentials"],
        &["-f", "/home/user/.ssh/id_rsa"],
        &["--file=/home/user/.ssh/id_rsa", "x"],
        &["-r", "x", "/etc"],
        &["-rn", "x"],
        &["-l", "x"],
        &["-P", "x"],
        &["-e", "x", "notes.txt"],
        &["-e"],
        &["-A", "x", "y"],
        &["-B"],
        &["-m", "1234567", "x"],
        &["-iA3", "x"],
        &["-", "x"],
        &["--color=always", "x"],
    ] {
        assert!(
            !stdin_arguments(&words(arguments), GREP_SWITCHES),
            "{arguments:?}"
        );
    }
}

#[test]
fn ripgrep_reading_standard_input_is_a_filter() {
    for arguments in [
        &["FAIL"][..],
        &["-A", "12", "FAIL|AssertionError"],
        &["-n", "FAIL"],
        &["-NU", "-e", "FAIL", "-e", "Error"],
        &["-B2", "-A6", "-i", "error"],
        &["-c", "FAIL"],
    ] {
        assert!(
            stdin_arguments(&words(arguments), RG_SWITCHES),
            "{arguments:?}"
        );
    }
}

#[test]
fn ripgrep_spelling_its_own_valued_options_is_not_a_filter() {
    for arguments in [
        &[][..],
        &["x", "notes.txt"],
        &["-f", "/home/user/.ssh/id_rsa"],
        &["-l", "x"],
        &["-P", "x"],
        &["-z", "x"],
        // `-g` and `-E` take a value in ripgrep, so the word after them
        // is not a pattern and the stage is not a plain filter.
        &["-g", "*.ts", "x"],
        &["-E", "utf-8", "x"],
        &["--files"],
        &["--pre", "cat", "x"],
    ] {
        assert!(
            !stdin_arguments(&words(arguments), RG_SWITCHES),
            "{arguments:?}"
        );
    }
}

#[test]
fn only_plain_quoted_words_are_lexed_alike() {
    for source in [
        "grep FAIL",
        "grep -B 3 \"at async createViteServer\"",
        "grep -E 'FAIL|Error'",
        "grep \"x\\|y\"",
        "head -8",
    ] {
        assert!(plain_source(source), "{source}");
    }
    for source in [
        "grep a[bc]",
        "grep x*",
        "grep ~/.ssh",
        "grep \"$HOME\"",
        "grep '$x'",
        "grep `id`",
        "grep x > out.txt",
        "grep x 2>&1",
        "grep x\\ y",
        "grep 'unterminated",
        "grep {a,b}",
        "grep x;",
        "grep \"a\nb\"",
    ] {
        assert!(!plain_source(source), "{source}");
    }
}

#[test]
fn a_head_or_tail_bound_reads_lines_or_bytes() {
    for (arguments, expected) in [
        (&["-40"][..], (40u32, false)),
        (&["-n", "40"][..], (40, false)),
        (&["-c", "1500"][..], (1500, true)),
        (&["-c1500"][..], (1500, true)),
    ] {
        assert_eq!(
            head_tail_bound(&words(arguments)),
            Some(expected),
            "{arguments:?}"
        );
    }
}

#[test]
fn a_bound_that_names_a_file_or_no_count_is_not_a_filter() {
    for arguments in [
        &[][..],
        &["-c"],
        &["-n"],
        &["-c", "1500", "notes.txt"],
        &["-c", "-1500"],
        &["-c", "1500000000"],
        &["-q", "1500"],
        &["notes.txt"],
    ] {
        assert_eq!(head_tail_bound(&words(arguments)), None, "{arguments:?}");
    }
}

#[test]
fn a_cut_that_only_reshapes_standard_input_is_a_matcher_stage() {
    for arguments in [
        &["-c1-120"][..],
        &["-c", "1-120"],
        &["-d", "(", "-f1"],
        &["-d(", "-f", "1"],
        &["-f1", "-s"],
        &["-b", "1-80", "-n"],
    ] {
        assert!(matcher_stage("cut", &words(arguments)), "{arguments:?}");
    }
}

/// The peel runs each stage itself, so it takes only the stages the
/// runtime can run: a `cut` that opens a file is not one of them, and
/// neither is a `sort` or a `uniq` the rejoin path admits.
#[test]
fn a_stage_the_runtime_cannot_run_over_the_text_is_not_a_matcher_stage() {
    for (program, arguments) in [
        ("cut", &["-f1", "build.log"][..]),
        ("cut", &["-c1-20", "/etc/passwd"]),
        ("cut", &["-c1-20", "-"]),
        // A long option this grammar does not carry; `cut` in the system
        // image has none of them.
        ("cut", &["--fields=1"]),
        ("sort", &["-u"]),
        ("uniq", &["-c"]),
        ("wc", &["-l"]),
        ("tr", &["-d", "\\r"]),
        // The peel runs a matcher itself over the captured text; it has no
        // reading of `cat`, which is why a rejoined `cat` keeps the sibling
        // route's own sink rather than the peel's.
        ("cat", &["-v"]),
        ("awk", &["{print $1}"]),
        ("head", &["-40"]),
    ] {
        assert!(
            !matcher_stage(program, &words(arguments)),
            "{program} {arguments:?}"
        );
    }
}

#[test]
fn a_rejoined_stage_reshapes_what_it_reads_on_standard_input() {
    for (program, arguments) in [
        ("cut", &["-c1-120"][..]),
        ("cut", &["-d", ":", "-f1"]),
        ("cut", &["-d:", "-f", "1", "-s"]),
        ("sort", &[]),
        ("sort", &["-u"]),
        ("sort", &["-rn"]),
        ("sort", &["-k2,2", "-t:"]),
        ("uniq", &["-c"]),
        ("uniq", &["-f", "2", "-w10"]),
        ("wc", &["-l"]),
        // `cat` copies standard input and its switches only respell the bytes.
        ("cat", &[]),
        ("cat", &["-v"]),
        ("cat", &["-A"]),
        ("cat", &["-n"]),
        ("cat", &["-vET"]),
        ("tr", &["-d", "\\r"]),
        ("head", &["-40"]),
        ("tail", &["-n", "15"]),
        ("grep", &["-v", "ok"]),
        ("rg", &["-c", "FAIL"]),
        // `sed` with one script and no file operand reads standard input.
        ("sed", &["-n", "/OUTPUT-BEGIN/,/OUTPUT-END/p"]),
        ("sed", &["-n", "1,5p"]),
        ("sed", &["s/a/b/"]),
        ("sed", &["-E", "s/[0-9]+/N/g"]),
        ("sed", &["-n", "-e", "1p", "-e", "3p"]),
        ("sed", &["--", "1d"]),
    ] {
        assert!(
            rejoined_stage(program, &words(arguments)),
            "{program} {arguments:?}"
        );
    }
}

#[test]
fn a_stage_that_names_a_file_or_runs_a_program_is_not_rejoined() {
    for (program, arguments) in [
        ("head", &["/etc/passwd"][..]),
        ("head", &["-5", "/etc/passwd"]),
        ("tail", &["-f", "/var/log/system.log"]),
        ("cut", &["-f1", "/etc/passwd"]),
        ("sort", &["/etc/passwd"]),
        // `-o`, `-T` and `-S` name a file, a directory and a size.
        ("sort", &["-o", "out.txt"]),
        ("sort", &["-oout.txt"]),
        ("sort", &["--output=out.txt"]),
        ("sort", &["-T", "/tmp"]),
        ("sort", &["-S", "1G"]),
        ("uniq", &["notes.txt"]),
        // Every `cat` operand is a file it opens, `-` included.
        ("cat", &["/etc/passwd"]),
        ("cat", &["-v", "/etc/passwd"]),
        ("cat", &["-"]),
        // A flag `cat` does not take leaves the stage to review.
        ("cat", &["-x"]),
        ("wc", &["-l", "/etc/passwd"]),
        ("grep", &["FAIL", "build.log"]),
        ("sh", &[]),
        ("bash", &["-s"]),
        ("xargs", &["rm"]),
        ("tee", &["out.txt"]),
        ("awk", &["{print $1}"]),
        ("sed", &["-i", "s/a/b/", "notes.txt"]),
        // `-i` edits a file, `-f` reads the script out of one, and a second
        // operand is a file `sed` opens whatever the script says.
        ("sed", &["-i", "s/a/b/"]),
        ("sed", &["-i.bak", "s/a/b/"]),
        ("sed", &["--in-place", "s/a/b/"]),
        ("sed", &["-f", "/tmp/script.sed"]),
        ("sed", &["-n", "1,5p", "notes.txt"]),
        ("sed", &["-n", "-e", "1p", "notes.txt"]),
        ("sed", &["-n", "1p", "-"]),
        ("sed", &[]),
        ("sed", &["-n"]),
    ] {
        assert!(
            !rejoined_stage(program, &words(arguments)),
            "{program} {arguments:?}"
        );
    }
}
#[test]
fn a_quoted_operator_passes_the_source_read_and_fails_the_word_read() {
    assert!(plain_source("tr '|' x"));
    assert!(!rejoined_words("tr", &words(&["|", "x"])));
    assert!(rejoined_words("tr", &words(&["a-z", "A-Z"])));
    assert!(!rejoined_words("grep", &words(&["a;b"])));
    assert!(!rejoined_words("sort", &words(&["-t", "&"])));
}
