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
        assert_eq!(spliced(command).as_deref(), Some(expected), "{command}");
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
        assert_eq!(spliced(command), None, "{command}");
    }
}
