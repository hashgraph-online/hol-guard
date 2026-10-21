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
        // The body talks about the name without binding it, so the loop
        // variable still holds the header word.
        (
            "for pkg in core cli; do echo \"pkg: $pkg\"; done",
            "echo \"pkg: core\"; echo \"pkg: cli\"",
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
        "for f in *.ts; do echo $f; done",
        "for f in [ab]*.ts; do echo $f; done",
        "for f in build*; do echo $f; done",
        "for f in ../*.ts; do echo $f; done",
        "for f in /etc/*.conf; do echo $f; done",
        "for f in src/../../*.ts; do echo $f; done",
        "for f in \"src/*.ts\"; do echo $f; done",
        "for f in 'src/*.ts'; do echo $f; done",
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
