use super::spliced;

/// A conditional inside a longer list is replaced by the lists it holds, and
/// the commands around it are kept as written.
#[test]
fn a_conditional_in_a_list_is_written_out_in_place() {
    for (command, expected) in [
        (
            "echo a && if [ -f README.md ]; then echo yes; else echo no; fi && echo b",
            "echo a && [ -f README.md ]; echo yes; echo no && echo b",
        ),
        (
            "if [ -d docs ]; then ls docs; fi; cat README.md",
            "[ -d docs ]; ls docs ; cat README.md",
        ),
        (
            "git status --short; if [ -f .git/MERGE_HEAD ]; then echo merging; fi",
            "git status --short; [ -f .git/MERGE_HEAD ]; echo merging",
        ),
        (
            "if [ -f a ]; then echo a; fi && if [ -f b ]; then echo b; fi",
            "[ -f a ]; echo a && [ -f b ]; echo b",
        ),
        (
            "gh pr view 1 --jq '.x | if . then 1 else 2 end' || if true; then ls; fi",
            "gh pr view 1 --jq '.x | if . then 1 else 2 end' || true; ls",
        ),
    ] {
        assert_eq!(
            spliced(command, None).as_deref(),
            Some(expected),
            "{command}"
        );
    }
}

/// A command with no conditional, one the splice cannot read exactly, or one
/// whose skipped branch could change what later commands see is left alone.
#[test]
fn other_lists_are_not_spliced() {
    for command in [
        "echo a && echo b",
        "echo 'if x; then y; fi'",
        "echo a && if [ -d src ]; then cd src; fi && cat one.ts",
        "echo a && if [ -f env ]; then export A=1; fi",
        "echo a && if [ -f env ]; then A=1; fi && echo $A",
        "echo a && if [ -f env ]; then . ./env; fi",
        "echo a && if [ -f env ]; then printf -v A x; fi",
        "echo a && if [ -d src ]; then echo src | cd src; fi && cat one.ts",
        "echo a && if [ -d src ]; then \"cd\" src; fi && cat one.ts",
        "echo a && if [ -d src ]; then c\\d src; fi && cat one.ts",
        "echo a && if [ -d src ]; then chdir src; fi && cat one.ts",
        "echo a && if [ -f a ]; then let n=1; fi",
        "echo a && if [ -f a ]; then if [ -f b ]; then echo b; fi; fi",
        "cat a | if read x; then echo y; fi",
        "echo a && if [ -f a ]; then echo a; fi | cat",
        "echo a && if [ -f a ]; then echo a; fi > out",
        "echo a && if [ -f a ]; then echo a; fi &",
        "echo $(id) && if [ -f a ]; then echo a; fi",
        "echo \"$(id)\" && if [ -f a ]; then echo a; fi",
        "echo `id` && if [ -f a ]; then echo a; fi",
        "(echo a) && if [ -f a ]; then echo a; fi",
        "{ echo a; } && if [ -f a ]; then echo a; fi",
        "cat <<EOF && if [ -f a ]; then echo a; fi",
        "for f in a; do echo $f; done && if [ -f a ]; then echo a; fi",
        "echo a # && if [ -f a ]; then echo a; fi",
        "echo a && if [ -f a ]; then echo a",
        "echo 'open && if [ -f a ]; then echo a; fi",
    ] {
        assert_eq!(spliced(command, None), None, "{command}");
    }
}

/// A negated item inside a spliced conditional loses the `!` only while the
/// list that follows it inside the construct runs either way. The construct's
/// last item keeps its `!`, because the text after the conditional reads the
/// outcome the construct returns.
#[test]
fn a_negated_item_keeps_the_negation_the_surrounding_list_reads() {
    for (command, expected) in [
        (
            "echo a && if ! npm test; then echo fail; fi",
            "echo a && npm test; echo fail",
        ),
        (
            "if ! pytest -q; then echo fail; fi && echo b",
            "pytest -q; echo fail && echo b",
        ),
        (
            "if [ -f a ]; then ! npm test; fi && echo b",
            "[ -f a ]; ! npm test && echo b",
        ),
    ] {
        assert_eq!(
            spliced(command, None).as_deref(),
            Some(expected),
            "{command}"
        );
    }
}

/// A negated `cd` still changes the directory when it succeeds, and `then`
/// runs when it does not. Splicing that into the surrounding list would check
/// the later command in the wrong directory.
#[test]
fn a_negated_directory_change_is_not_spliced() {
    assert_eq!(
        spliced(
            "git status --short && if ! cd src; then touch ../escape.txt; fi",
            None
        ),
        None
    );
}

/// A loop over literal words inside a longer list is written out in place,
/// once per word, and the commands around it are kept as written.
#[test]
fn a_loop_in_a_list_is_written_out_in_place() {
    for (command, expected) in [
        (
            "echo a; for n in 1 2; do echo $n; done",
            "echo a; echo 1; echo 2",
        ),
        (
            "for n in 1 2; do echo $n; done; echo a",
            "echo 1; echo 2 ; echo a",
        ),
        (
            "echo a && for n in 1 2; do echo $n; done && echo b",
            "echo a && echo 1; echo 2 && echo b",
        ),
        (
            "echo a\nfor n in 1 2; do echo $n; done\necho b",
            "echo a\necho 1; echo 2 \necho b",
        ),
        (
            "gh pr list; for n in 1 2; do gh pr view $n; done; for f in a b; do cat $f; done",
            "gh pr list; gh pr view 1; gh pr view 2 ; cat a; cat b",
        ),
    ] {
        assert_eq!(
            spliced(command, None).as_deref(),
            Some(expected),
            "{command}"
        );
    }
}

/// A loop that is piped into or out of, followed by a redirect or a
/// background `&`, mixed with a conditional, or skipped by `&&`/`||` while its
/// body changes the directory keeps its review. So does a `!` on the body's
/// last command when `&&` or `||` after `done` reads it.
#[test]
fn other_loops_in_a_list_are_not_written_out() {
    for command in [
        "echo a | for n in 1 2; do echo $n; done",
        "echo a; for n in 1 2; do echo $n; done | sh",
        "echo a; for n in 1 2; do echo $n; done > out",
        "echo a; for n in 1 2; do echo $n; done &",
        "echo a; for n in $(ls); do echo $n; done",
        "echo a; for n in 1 2; do echo $n; done; if true; then ls; fi",
        "false || for d in a b; do cd $d; done; rm -f build",
        "false && for d in a; do echo $d; cd $d; done; rm -f build",
        "echo a; for n in 1 2; do ! grep -q $n f; done && rm -f f",
        "echo a; for n in 1 2; do echo $n; done echo b",
        "echo a; for n in 1 2; do echo $n; done;; echo b",
    ] {
        assert_eq!(spliced(command, None), None, "{command}");
    }
}

/// A loop gated by `&&` is written out when a pipe inside a quoted filter is
/// only text, and still keeps its review when a body item changes the shell.
#[test]
fn a_quoted_pipe_does_not_make_a_gated_loop_change_the_shell() {
    let filter = "jq -c '{n:.number,c:[.checks[]?|select(.c!=null)|{n:.name}]}'";
    let command = format!(
        "gh pr view 1 && for n in 1 2; do gh pr view \"$n\" --json number | {filter}; done"
    );
    let written = spliced(&command, None).expect("written out");
    assert_eq!(
        written.matches("--json number | jq -c").count(),
        2,
        "{written}"
    );
    for command in [
        "gh pr view 1 && for n in 1 2; do echo 'a|b' | cd /tmp; done",
        "gh pr view 1 && for n in 1 2; do echo \"a|b\"; cd /tmp; done",
        "gh pr view 1 && for n in 1 2; do gh pr view \"$n\" | jq '.a|.b' | x=1 cat; done",
    ] {
        assert_eq!(spliced(command, None), None, "{command}");
    }
}
