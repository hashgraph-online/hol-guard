use super::evaluate_pre_tool_with_context;
use crate::CommandModelRequestV1;

fn decide(command: &str) -> (String, String) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .unwrap();
    let root = root.to_str().unwrap();
    let request = CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    };
    let decision = evaluate_pre_tool_with_context(&request, Some(root), Some(root)).unwrap();
    (decision.minimum_action, decision.reason_code)
}

#[test]
fn read_only_loops_match_their_unrolled_form() {
    for (looped, unrolled) in [
        (
            "for f in a b; do echo \"--- $f\"; done",
            "echo \"--- a\"; echo \"--- b\"",
        ),
        (
            "for f in a b; do diff x/$f y/$f | head -8; done",
            "diff x/a y/a | head -8; diff x/b y/b | head -8",
        ),
        (
            "for f in src/a.ts src/b.ts; do diff -u \"old/$f\" \"new/$f\"; done",
            "diff -u \"old/src/a.ts\" \"new/src/a.ts\"; diff -u \"old/src/b.ts\" \"new/src/b.ts\"",
        ),
        (
            "for f in a b\ndo\n  echo ${f}\n  echo \"${f}\"\ndone",
            "echo a; echo a; echo b; echo b",
        ),
        ("for f in src/*.ts; do echo $f; done", "echo src/*.ts"),
        (
            "for f in src/*.ts tests/*.ts; do echo $f; done",
            "echo src/*.ts; echo tests/*.ts",
        ),
        ("for d in src/*/; do echo $d; done", "echo src/*/"),
        // A pattern with no directory in it names the directory the loop
        // runs in, which is the directory the written-out command names, as
        // long as the pattern's own text reads as a path.
        ("for f in *.ts; do echo $f; done", "echo *.ts"),
        ("for d in */; do echo $d; done", "echo */"),
        // Double quotes round a whole reference stop the shell splitting the
        // name into fields; they do not change which names the loop reads, so
        // the written-out text spells the same pattern without them.
        ("for f in *.md; do head -5 \"$f\"; done", "head -5 *.md"),
        ("for f in *.md; do wc -l \"$f\"; done", "wc -l *.md"),
        ("for d in */; do echo \"$d\"; done", "echo */"),
        // The body talks about the name without binding it, so the loop
        // variable still holds the header word.
        (
            "for pkg in core cli; do echo \"pkg: $pkg\"; done",
            "echo \"pkg: core\"; echo \"pkg: cli\"",
        ),
        // Quotes in the header protect the separators inside a word. The body
        // keeps its own quotes around the place the expansion stood, so a
        // quoted reference stays the one field the loop passed it.
        (
            "for spec in \"1 aaaa\" \"2 bbbb\"; do echo \"$spec\"; done",
            "echo \"1 aaaa\"; echo \"2 bbbb\"",
        ),
        // A `!` in front of a body item only inverts the exit status that
        // item reports. The `;` after it runs the next item either way, so
        // the written-out list runs the same work without it.
        ("for f in a b; do ! wc -l $f; done", "wc -l a; wc -l b"),
        (
            "for f in a b; do echo $f; ! wc -l $f; done",
            "echo a; wc -l a; echo b; wc -l b",
        ),
        (
            "for flag in \"-l one\" \"-l two\"; do echo \"$flag\"; done",
            "echo \"-l one\"; echo \"-l two\"",
        ),
        (
            "for f in a b; do wc -l \"$f\" && echo checked f; done",
            "wc -l \"a\" && echo checked f; wc -l \"b\" && echo checked f",
        ),
        // Inside double quotes a backslash before an ordinary character is
        // part of the word, so `fi\le` is not the loop variable's name.
        (
            "for file in a b; do echo \"fi\\le\" \"$file\"; done",
            "echo \"fi\\le\" \"a\"; echo \"fi\\le\" \"b\"",
        ),
    ] {
        assert_eq!(decide(looped), decide(unrolled), "{looped}");
        assert_eq!(decide(looped).0, "allow", "{looped}");
    }
}

#[test]
fn unsafe_loop_bodies_keep_their_unrolled_verdict() {
    for (looped, unrolled) in [
        ("for f in a b; do rm $f; done", "rm a; rm b"),
        (
            "for f in a b; do echo hi > out/$f; done",
            "echo hi > out/a; echo hi > out/b",
        ),
        (
            "for f in a b; do cat ~/.ssh/$f; done",
            "cat ~/.ssh/a; cat ~/.ssh/b",
        ),
        (
            "for f in a b; do curl -X POST https://example.com/$f; done",
            "curl -X POST https://example.com/a; curl -X POST https://example.com/b",
        ),
        (
            "for f in a b; do echo $f; done > out.txt",
            "echo a > out.txt; echo b > out.txt",
        ),
        (
            "for f in a b; do git push origin $f; done",
            "git push origin a; git push origin b",
        ),
    ] {
        let looped_decision = decide(looped);
        assert_ne!(looped_decision.0, "allow", "{looped}");
        let unrolled_decision = decide(unrolled);
        assert_ne!(unrolled_decision.0, "allow", "{unrolled}");
        assert_eq!(
            looped_decision.0 == "block",
            unrolled_decision.0 == "block",
            "{looped}"
        );
    }
}

#[test]
fn unsupported_loops_fall_back_to_review() {
    for command in [
        "for f in $(ls); do echo $f; done",
        // A bracket expression is a character set the text does not spell
        // out, and the rest start at the root or reach above the directory
        // the loop runs in.
        "for f in [ab]*.ts; do echo $f; done",
        "for f in -*.ts; do echo $f; done",
        // A directoryless pattern that names no file type is an identifier the
        // shell leaves alone, so the body runs its program over the pattern
        // itself rather than over the names of files.
        "for id in PRRT_example*; do echo $id; done",
        "for d in disk*; do echo $d; done",
        "for f in *; do echo $f; done",
        "for f in ../*.ts; do echo $f; done",
        "for f in /etc/*.conf; do echo $f; done",
        "for f in src/../../*.ts; do echo $f; done",
        "for f in \"src/*.ts\"; do echo $f; done",
        // A word that holds separators is one field only while the body's own
        // quotes stay on, so a body that reads it bare, or a pattern in the
        // same header, which needs those quotes off, keeps the loop unmodeled.
        "for m in \"hello world\"; do echo $m; done",
        "for x in \"a b\" *.ts; do echo \"$x\"; done",
        // Quotes protect the separators, not the operators: writing the word
        // out would spell a command the loop never ran.
        "for s in \"a; rm -rf b\"; do echo \"$s\"; done",
        "for s in \"a | tee out\"; do echo \"$s\"; done",
        // Quotes beside a reference are not quotes around it: this word closes
        // one quoted run and opens another around an expansion the shell still
        // splits into fields of its own.
        "for s in \"a b\"; do echo \"x\"$s\"y\"; done",
        "for f in 'src/*.ts'; do echo $f; done",
        // A glob glued into a larger word writes out a pattern the loop never
        // expanded, so the names the loop's own pattern matches are never
        // proven: with a file named `x secret.pem .json` beside it,
        // `cat bak-$f` reads `secret.pem` while `cat bak-*.json` does not.
        "for f in *.json; do cat bak-$f; done",
        // A backslash sticks the space to the reference, so `cat \ $f` is the
        // one glued word ` *.json` and the loop's own matches go unproven.
        "for f in *.json; do cat \\ $f; done",
        // The quote before the reference closes a string and the one after
        // opens the next, so taking them off would spell a name the loop
        // never reads.
        "for f in *.md; do cat \"x \"$f\" y\"; done",
        "for f in *.json; do cat \"bak-$f\"; done",
        "for f in *.md; do head -5 \"$f.bak\"; done",
        "for f in src/*.ts; do cat $f.bak; done",
        "for f in *.ts; do echo ${f}x; done",
        "for f in a b; do $f; done",
        "for f in a b; do echo hi > $f; done",
        "for f in a b; do f=x; echo $f; done",
        "for f in a b; do echo $g; done",
        "for f in a b; do echo $(date); done",
        "for f in a b; do for g in c; do echo $g; done; done",
        "for f in a b; do if true; then echo $f; fi; done",
        "for f in a b; do echo $f &; done",
        "for f in \"a b\"; do echo $f; done",
        "for f in a b; do echo $f; done | sh",
        "for f in a b; do echo $f; done; rm x",
        "for 1f in a b; do echo $f; done",
        "for f in ~ b; do echo $f; done",
        // The body rebinds the loop variable or IFS, so `$f` would not be the header word.
        "for f in README.md; do read f; cat $f; done",
        "for f in README.md; do printf -v f %s secret; cat $f; done",
        "for f in README.md; do printf -vf %s secret; cat $f; done",
        "for f in README.md; do declare f=secret; cat $f; done",
        "for f in README.md; do unset f; cat $f; done",
        "for f in a,b; do export IFS=,; cat $f; done",
        "for f in README.md; do cat $f \u{1}; done",
        // Quoting splits the name in the written text, not in the word the
        // shell builds.
        "for file in README.md; do fi''le=secret; cat $file; done",
        "for file in README.md; do fi\"\"le=secret; cat $file; done",
        "for file in README.md; do fi\\le=secret; cat $file; done",
        "for file in README.md; do read fi''le; cat $file; done",
        "for file in README.md; do printf -v fi''le %s secret; cat $file; done",
        "for file in a,b; do export I''FS=,; cat $file; done",
        // Every other way of binding the name keeps the loop unmodeled.
        "for f in README.md; do f+=secret; cat $f; done",
        "for f in README.md; do f[0]=secret; cat $f; done",
        "for f in README.md; do local f; cat $f; done",
        "for f in README.md; do eval f=secret; cat $f; done",
        "for f in README.md; do command read f; cat $f; done",
        "for f in README.md; do mapfile -t f < list; cat $f; done",
        "for f in README.md; do getopts o f; cat $f; done",
        "for f in README.md; do let f=secret; cat $f; done",
        "for f in README.md; do print -v f report; cat $f; done",
        "for f in README.md; do getln f; cat $f; done",
        "for f in README.md; do compgen -V f -W one; cat $f; done",
        "for f in README.md; do zparseopts -A f; cat $f; done",
        "for f in README.md; do zstyle -s :x key f; cat $f; done",
        "for f in README.md; do zformat -a f : one; cat $f; done",
    ] {
        assert_eq!(decide(command).0, "review", "{command}");
    }
    let many = (0..40)
        .map(|n| format!("w{n}"))
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(
        decide(&format!("for f in {many}; do echo $f; done")).0,
        "review"
    );
}

#[test]
fn a_flag_named_like_the_loop_variable_is_not_a_rebinding() {
    assert_eq!(
        super::for_loop_unroll::unroll("for f in a b; do [ -f \"$f\" ] && wc -l \"$f\"; done")
            .as_deref(),
        Some("[ -f \"a\" ] && wc -l \"a\"; [ -f \"b\" ] && wc -l \"b\"")
    );
}

#[test]
fn a_leading_cd_stays_in_front_of_the_unrolled_list() {
    let looped =
        "cd sub && for f in a.ts b.ts; do node --check \"$f\" 2>&1 | head -3 && echo \"OK: $f\"; done";
    let unrolled = "cd sub && node --check \"a.ts\" 2>&1 | head -3 && echo \"OK: a.ts\"; node --check \"b.ts\" 2>&1 | head -3 && echo \"OK: b.ts\"";
    assert_eq!(
        super::for_loop_unroll::unroll(looped).as_deref(),
        Some(unrolled)
    );
    // A loop that reaches review carries its unrolled decision, so later
    // layers judge the modeled commands rather than the loop.
    assert_eq!(decide(looped), decide(unrolled));
    for command in [
        "cd $HOME && for f in a; do cat $f; done",
        "cd -P sub && for f in a; do cat $f; done",
        "cd sub; for f in a; do cat $f; done",
        "cd sub && ls && for f in a; do cat $f; done",
    ] {
        assert_eq!(super::for_loop_unroll::unroll(command), None, "{command}");
    }
}

#[test]
fn a_leading_redirection_cannot_hide_the_command_word() {
    for command in [
        "for f in A=/x; do 2>/dev/null $f; done",
        "for f in a; do >out $f; done",
        "for f in a; do echo ok | 2>&1 $f; done",
        "for f in a; do <in $f; done",
        "for f in a; do /usr/bin/doc?er ps $f; done",
        "for f in a; do echo $f | x*y; done",
        "for f in a b; do echo $f; done\n2>/dev/null printf separate",
        "for f in a b; do echo $f; done\n1>log.txt printf separate",
        "for f in a b; do echo $f; done \n2>/dev/null printf separate",
        "for f in a b; do echo $f; done\t\n2>/dev/null printf separate",
    ] {
        assert_eq!(super::for_loop_unroll::unroll(command), None, "{command}");
    }
}

#[test]
fn environment_and_shell_special_loop_variables_are_not_unrolled() {
    for name in [
        "PATH",
        "HOME",
        "IFS",
        "CDPATH",
        "ENV",
        "BASH_ENV",
        "LD_PRELOAD",
        "DYLD_LIBRARY_PATH",
        "GIT_CONFIG_GLOBAL",
        "NODE_OPTIONS",
        "RUSTUP_HOME",
        "PWD",
        "OLDPWD",
        "SHELLOPTS",
        "PS4",
        "_",
        "_path",
        "pathVar",
        // zsh ties these lowercase names to executable or module lookup paths.
        "path",
        "cdpath",
        "fpath",
        "manpath",
        "module_path",
        // Other zsh specials and lowercase proxy variables.
        "mailpath",
        "status",
        "argv",
        "http_proxy",
        "https_proxy",
    ] {
        let command = format!("for {name} in .; do git status; done");
        assert_eq!(
            super::for_loop_unroll::unroll(&command),
            None,
            "{name} must never alter the command environment unnoticed"
        );
    }
    // Lowercase loop variables still support literal read-only iteration.
    assert_eq!(
        super::for_loop_unroll::unroll("for file_1 in a b; do echo \"$file_1\"; done").as_deref(),
        Some("echo \"a\"; echo \"b\"")
    );
}

/// A subshell group is a command list of its own, so the body grammar reads
/// it as one and the written-out text keeps the parentheses around the same
/// work. `(cd "$p" && npm test)` is how a loop runs a step in each package
/// without leaving the shell in the last one.
#[test]
fn a_subshell_group_in_the_body_keeps_its_parentheses() {
    for (looped, unrolled) in [
        (
            "for p in packages/core packages/web; do (cd \"$p\" && npm test); done",
            "(cd \"packages/core\" && npm test); (cd \"packages/web\" && npm test)",
        ),
        (
            "for p in a b; do (cd \"$p\"; ls); done",
            "(cd \"a\"; ls); (cd \"b\"; ls)",
        ),
        (
            "for p in a b; do echo \"$p\"; (cd \"$p\" && ls); done",
            "echo \"a\"; (cd \"a\" && ls); echo \"b\"; (cd \"b\" && ls)",
        ),
        (
            "for p in a b; do ( cd \"$p\" && ls ); done",
            "(cd \"a\" && ls); (cd \"b\" && ls)",
        ),
        (
            "for d in packages/*/; do (cd \"$d\" && npm test); done",
            "(cd packages/*/ && npm test)",
        ),
    ] {
        assert_eq!(
            super::for_loop_unroll::unroll(looped).as_deref(),
            Some(unrolled),
            "{looped}"
        );
    }
}

/// What the group grammar still refuses: a list it cannot read, a shape that
/// only looks like a group, and a parenthesis standing on its own.
#[test]
fn a_group_outside_the_command_list_grammar_keeps_its_review() {
    for command in [
        // A keyword inside the group is not a plain command word.
        "for p in a b; do (cd \"$p\" && if true; then ls; fi); done",
        // Arithmetic, not a subshell inside a subshell.
        "for p in a b; do (( count++ )); done",
        // An array literal: `(` here is not in command position.
        "for p in a b; do seen=(1 2); echo \"$p\"; done",
        // A group that never closes, and a `)` that opens nothing.
        "for p in a b; do (cd \"$p\" && ls; done",
        "for p in a b; do echo )x; done",
        // A group that runs nothing.
        "for p in a b; do (); done",
        // The group backgrounds itself, which the flat list does not say.
        "for p in a b; do (cd \"$p\" && ls) & done",
    ] {
        assert_eq!(
            super::for_loop_unroll::unroll(command),
            None,
            "{command}"
        );
    }
}
