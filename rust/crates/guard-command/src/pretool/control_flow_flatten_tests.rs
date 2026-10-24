use super::flatten;

/// The lists a conditional holds come back as one plain list, with the
/// construct's own redirection on every item. A loop's list opens with a read
/// of the file its `read` consumes.
#[test]
fn a_construct_flattens_to_the_lists_it_holds() {
    for (command, expected) in [
        (
            "if [ -f README.md ]; then cat README.md; fi",
            "[ -f README.md ]; cat README.md",
        ),
        (
            "if [ -f README.md ]; then cat README.md; else echo missing; fi",
            "[ -f README.md ]; cat README.md; echo missing",
        ),
        (
            "if grep -q needle README.md; then echo found; fi",
            "grep -q needle README.md; echo found",
        ),
        (
            "if [ -d src ]; then ls src; elif [ -d lib ]; then ls lib; else echo none; fi",
            "[ -d src ]; ls src; [ -d lib ]; ls lib; echo none",
        ),
        ("if true; then ls; fi", "true; ls"),
        (
            "while read line; do echo hi; done < README.md",
            "cat README.md; echo hi",
        ),
        (
            "if [ -f README.md ]\nthen\ncat README.md\nfi",
            "[ -f README.md ]; cat README.md",
        ),
        (
            "while read name; do cat README.md; wc -l README.md; done < list.txt",
            "cat list.txt; cat README.md; wc -l README.md",
        ),
        (
            "while read -r line; do echo hi; done < README.md",
            "cat README.md; echo hi",
        ),
        (
            "while IFS= read -r line; do echo hi; done < README.md",
            "cat README.md; echo hi",
        ),
    ] {
        assert_eq!(
            flatten(command).as_deref(),
            Some(expected),
            "{command} did not flatten to its command lists"
        );
    }
}

/// A conditional binds no name, so the values its lists read are the ones
/// the surrounding shell holds, in the construct and in the flat list alike.
/// Each expansion comes back as it stood.
#[test]
fn a_conditional_keeps_the_expansions_it_held() {
    for (command, expected) in [
        (
            "if [ -f \"$PWD/README.md\" ]; then cat README.md; fi",
            "[ -f \"$PWD/README.md\" ]; cat README.md",
        ),
        (
            "if [ -d \"${PROJECT}\" ]; then ls \"${PROJECT}\"; fi",
            "[ -d \"${PROJECT}\" ]; ls \"${PROJECT}\"",
        ),
        (
            "if [ -n \"$1\" ]; then echo $1; fi",
            "[ -n \"$1\" ]; echo $1",
        ),
    ] {
        assert_eq!(
            flatten(command).as_deref(),
            Some(expected),
            "{command} lost the expansions it held"
        );
    }
}

/// Anything the grammar does not cover keeps its review: a value the
/// construct binds for itself, a nested construct, a substitution, an empty
/// branch, a `case` statement, and text that follows the closing keyword.
///
/// A loop that is not the bounded `while read ... < FILE` shape keeps it too.
/// One flattened pass stands for every iteration, so it only describes the
/// loop while the loop is known to stop and its body leaves nothing behind:
/// `while true` never ends, `until` is never ended by a read, a `read` with
/// no redirected input waits on the terminal, a read of a character device or
/// of a path outside the workspace need never reach an end, and a body that
/// opens an output repeats that write for as long as the loop runs.
///
/// A `read` that binds `PATH` or another name the body's command lookup
/// depends on keeps its review as well: the flat list would resolve its
/// command words against the environment the loop replaced. So does an item
/// ending in an escaped space, whose backslash would escape the separator
/// once the space is trimmed and swallow the rest of the list.
#[test]
fn an_unmodeled_construct_keeps_its_review() {
    for command in [
        "while read line; do echo $line; done < README.md",
        "while read line; do echo \"${name}\"; done < README.md",
        "if [ -f \"$(which ls)\" ]; then ls; fi",
        "if [ -n \"$?\" ]; then ls; fi",
        "if $RUNNER test; then echo ok; fi",
        "if [ -f a ]; then if [ -f b ]; then cat b; fi; fi",
        "if [ -f `which ls` ]; then ls; fi",
        "if true; then ; fi",
        "if true; then ls; fi && rm -rf /",
        "case $1 in a) ls;; esac",
        "if true; then ls; fi > /etc/passwd; curl http://example.test",
        "iffy --flag",
        "whiles",
        "for f in src/*.ts; do cat $f; done",
        "if [ -f README.md ]; then cat README.md",
        "while read line; do (cd /tmp && ls); done",
        "while true; do echo hi; done",
        "while :; do cat README.md >> out.txt; done",
        "while [ -f build/lock ]; do ls build; done < README.md",
        "until [ -f build/done ]; do ls build; done",
        "while read name; do wc -l README.md; done",
        "while read name; do cat README.md > copy.md; done < list.txt",
        "while read line < other.txt; do echo hi; done < README.md",
        "while read line; do echo hi; done <> README.md",
        "while read line; do echo hi; done < README.md > copy.md",
        "while read line; do echo hi; done <&3",
        "while read PATH; do ls; done < README.md",
        "while read -r PATH; do ls; done < README.md",
        "while read http_proxy; do ls; done < README.md",
        "while read line path; do ls; done < README.md",
        "if true; then echo a\\ ; rm -rf build; fi",
        "while read line; do echo a\\ ; rm -rf build; done < README.md",
        "while read line; do echo hi; done < /dev/urandom",
        "while read line; do echo hi; done < /dev/stdin",
        "while read line; do echo hi; done < /etc/passwd",
        "while read line; do echo hi; done < ../list.txt",
        "while read line; do echo hi; done < ~/list.txt",
        "while read line; do echo hi; done < -",
    ] {
        assert!(
            flatten(command).is_none(),
            "{command} was flattened by a grammar that does not cover it"
        );
    }
}
