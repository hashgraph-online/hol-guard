use super::expanded;

#[test]
fn comma_braces_are_written_out_in_the_order_the_shell_makes_them() {
    let cases = [
        ("wc -l {README.md,AGENTS.md}", "wc -l README.md AGENTS.md"),
        ("ls -la {docs,ci}", "ls -la docs ci"),
        ("cat {README,AGENTS}.md", "cat README.md AGENTS.md"),
        (
            "sed -n 1,5p {README.md,AGENTS.md} 2>/dev/null",
            "sed -n 1,5p README.md AGENTS.md 2>/dev/null",
        ),
        ("ls {a,b}{c,d}", "ls ac ad bc bd"),
        ("cp notes.md{,.bak}", "cp notes.md notes.md.bak"),
        (
            "git status --short && wc -l {src,docs}/*.md | sort -n",
            "git status --short && wc -l src/*.md docs/*.md | sort -n",
        ),
        (
            "head -5 'my file.md' {a,b}.md",
            "head -5 'my file.md' a.md b.md",
        ),
        ("{ ls {a,b}; }", "{ ls a b; }"),
    ];
    for (command, want) in cases {
        assert_eq!(expanded(command).as_deref(), Some(want), "{command}");
    }
}

#[test]
fn words_that_do_not_expand_leave_the_command_alone() {
    for command in [
        "wc -l README.md AGENTS.md",
        "git log -1 HEAD@{1}",
        "find . -name '*.md' -exec wc -l {} +",
        "echo {}",
        "cat '{a,b}.md'",
        "cat \"{a,b}.md\"",
        "cat a{b",
    ] {
        assert_eq!(expanded(command), None, "{command}");
    }
}

#[test]
fn shapes_the_shell_expands_differently_keep_their_review() {
    for command in [
        // Sequences and large expansions are not followed.
        "cat part{1..3}.md",
        "ls {a,b}{c,d}{e,f}{g,h}{i,j}",
        "head -3 docs/{a,b{c,d}}.md",
        // A redirection target is not split; bash calls it ambiguous.
        "cat README.md > {a,b}.txt",
        "wc -l < {a,b}",
        // Assignments and option values with `=` are left to their own proofs.
        "X={a,b} ls",
        "grep -r --include={*.md,*.txt} x .",
        // Quoting, escapes and expansions are not read by this scan.
        "cat \"x\"{a,b}",
        r"cat \{a,b}",
        "cat {a,b} $HOME/x",
        "cat {a,b} `pwd`",
        "cat <<EOF {a,b}\nEOF",
        "[[ -f {a,b} ]]",
        "case {a,b} in a) ls;; esac",
        "ls {a,b} # {c,d}",
        "cat 'unclosed {a,b}",
        "cat {a,b}\u{0}",
    ] {
        assert_eq!(expanded(command), None, "{command}");
    }
}
