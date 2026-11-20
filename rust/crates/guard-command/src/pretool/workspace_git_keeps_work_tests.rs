use super::keeping_arguments;

fn keeps(command: &str) -> bool {
    let arguments: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
    keeping_arguments(&arguments)
}

#[test]
fn reset_without_a_working_tree_mode_keeps_the_work() {
    assert!(keeps("reset"));
    assert!(keeps("reset --soft HEAD~1"));
    assert!(keeps("reset --mixed HEAD~1"));
    assert!(keeps("reset -q HEAD~1"));
    assert!(keeps("reset HEAD~1 -- src/a.ts"));
    assert!(keeps("reset -- src/a.ts"));
}

#[test]
fn reset_that_writes_the_working_tree_keeps_its_review() {
    assert!(!keeps("reset --hard"));
    assert!(!keeps("reset --hard HEAD"));
    assert!(!keeps("reset --merge HEAD~1"));
    assert!(!keeps("reset --keep HEAD~1"));
    assert!(!keeps("reset --patch"));
    assert!(!keeps("reset --soft --hard HEAD"));
    assert!(!keeps("reset --soft --mixed HEAD"));
    assert!(!keeps("reset -- -src/a.ts"));
}

#[test]
fn restore_staged_keeps_the_work() {
    assert!(keeps("restore --staged src/a.ts"));
    assert!(keeps("restore -S src/a.ts"));
    assert!(keeps("restore --staged -- src/a.ts"));
    assert!(keeps("restore -q --staged src/a.ts"));
}

#[test]
fn restore_that_writes_the_working_tree_keeps_its_review() {
    assert!(!keeps("restore src/a.ts"));
    assert!(!keeps("restore --worktree src/a.ts"));
    assert!(!keeps("restore --staged --worktree src/a.ts"));
    assert!(!keeps("restore --staged --source=HEAD~1 src/a.ts"));
    assert!(!keeps("restore --staged --patch"));
    assert!(!keeps("restore --staged"));
}

#[test]
fn the_existing_branch_and_stash_forms_are_unchanged() {
    assert!(keeps("switch -c feature"));
    assert!(keeps("checkout -b feature"));
    assert!(keeps("stash push -u"));
    assert!(!keeps("checkout main"));
    assert!(!keeps("stash drop"));
}

#[test]
fn stash_push_narrowed_to_pathspecs_keeps_the_work() {
    assert!(keeps("stash push -- src/a.ts"));
    assert!(keeps("stash push src/a.ts src/b.ts"));
    assert!(keeps(
        "stash push -m warm -- Dockerfile __tests__/a.test.ts"
    ));
    assert!(keeps("stash push --message=warm -- Dockerfile"));
    assert!(keeps("stash push -u -q -- src/a.ts"));
    assert!(keeps("stash push --keep-index -- src/a.ts"));
    assert!(keeps("stash push --staged"));
    assert!(keeps("stash -- src/a.ts"));
    assert!(keeps("stash push --"));
}

#[test]
fn a_stash_subcommand_is_not_a_pathspec() {
    assert!(!keeps("stash pop"));
    assert!(!keeps("stash apply"));
    assert!(!keeps("stash clear"));
    assert!(!keeps("stash branch feature"));
    assert!(!keeps("stash drop stash@{0}"));
}

#[test]
fn stash_push_that_asks_for_more_keeps_its_review() {
    assert!(!keeps("stash push -p"));
    assert!(!keeps("stash push --patch -- src/a.ts"));
    assert!(!keeps("stash push --pathspec-from-file=list.txt"));
    assert!(!keeps("stash push -- -src/a.ts"));
    assert!(!keeps("stash push -m"));
}

#[test]
fn switch_creates_a_branch_in_the_attached_spelling_too() {
    assert!(keeps("switch --create feature"));
    assert!(keeps("switch --create=feature"));
    assert!(keeps("switch --create=chore/api-key-refresh"));
    assert!(!keeps("switch --create=../elsewhere"));
    assert!(!keeps("switch --create="));
    assert!(!keeps("switch --force-create=feature"));
    assert!(!keeps("switch -C feature"));
    assert!(!keeps("switch --create=feature main"));
}

fn keeps_under(rule_id: &str, command: &str) -> bool {
    let arguments: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
    super::keeping_form(rule_id).is_some_and(|keeping| keeping(&arguments))
}

#[test]
fn reading_a_reflog_stays_contained() {
    assert!(keeps_under("command.git.reflog", "reflog"));
    assert!(keeps_under("command.git.reflog", "reflog show HEAD"));
    assert!(keeps_under("command.git.reflog", "reflog -n 5"));
    assert!(keeps_under(
        "command.git.reflog",
        "reflog exists refs/heads/main"
    ));
}

#[test]
fn a_reflog_write_keeps_its_review() {
    assert!(!keeps_under(
        "command.git.reflog",
        "reflog expire --expire=now --all"
    ));
    assert!(!keeps_under(
        "command.git.reflog",
        "reflog expire --expire-unreachable=now --all"
    ));
    assert!(!keeps_under("command.git.reflog", "reflog delete HEAD@{0}"));
    assert!(!keeps_under("command.git.reflog", "reflog drop HEAD"));
    assert!(!keeps_under("command.git.reflog", "reflog write"));
    // A leading Git option can point the command at another repository.
    assert!(!keeps_under("command.git.reflog", "-C /other reflog show"));
}

#[test]
fn listing_and_creating_a_tag_stays_contained() {
    assert!(keeps_under("command.git.tag", "tag"));
    assert!(keeps_under("command.git.tag", "tag -l"));
    assert!(keeps_under("command.git.tag", "tag --sort=-creatordate"));
    assert!(keeps_under("command.git.tag", "tag v1.0.0"));
    assert!(keeps_under("command.git.tag", "tag -a v1.0.0 -m release"));
    assert!(keeps_under("command.git.tag", "tag -v v1.0.0"));
}

#[test]
fn a_tag_that_is_dropped_or_moved_keeps_its_review() {
    assert!(!keeps_under("command.git.tag", "tag -d v1.0.0"));
    assert!(!keeps_under("command.git.tag", "tag --delete v1.0.0"));
    assert!(!keeps_under("command.git.tag", "tag -f v1.0.0 HEAD"));
    assert!(!keeps_under("command.git.tag", "tag --force v1.0.0 HEAD"));
    assert!(!keeps_under("command.git.tag", "tag -af v1.0.0 -m release"));
    assert!(!keeps_under("command.git.tag", "-C /other tag -l"));
}

#[test]
fn a_reflog_read_that_writes_a_file_keeps_its_review() {
    // `git reflog show` walks the log, so it takes the log option set, and
    // `--output` points that walk at a file the sandbox leaves writable.
    assert!(!keeps_under(
        "command.git.reflog",
        "reflog show --output=.git/logs/refs/heads/main"
    ));
    assert!(!keeps_under(
        "command.git.reflog",
        "reflog --output=.git/logs/HEAD"
    ));
    // The same abbreviation Git resolves for a tag option it resolves here.
    assert!(!keeps_under(
        "command.git.reflog",
        "reflog show --outp=notes"
    ));
    // A helper option runs a program the review never saw.
    assert!(!keeps_under("command.git.reflog", "reflog show --ext-diff"));
    assert!(!keeps_under(
        "command.git.reflog",
        "reflog show -p --textconv"
    ));
}

#[test]
fn an_ordinary_reflog_option_stays_contained() {
    assert!(keeps_under("command.git.reflog", "reflog show --date=iso"));
    assert!(keeps_under("command.git.reflog", "reflog show --oneline"));
    assert!(keeps_under("command.git.reflog", "reflog show -n 20 HEAD"));
}

#[test]
fn an_abbreviated_tag_deletion_keeps_its_review() {
    // Git resolves any unambiguous prefix of a long option, so the shortened
    // spellings delete and move tags exactly as the full ones do.
    assert!(!keeps_under("command.git.tag", "tag --delet v1.0.0"));
    assert!(!keeps_under("command.git.tag", "tag --del v1.0.0"));
    assert!(!keeps_under("command.git.tag", "tag --d v1.0.0"));
    assert!(!keeps_under("command.git.tag", "tag --forc v1.0.0 HEAD"));
    assert!(!keeps_under("command.git.tag", "tag --fo v1.0.0 HEAD"));
    // A prefix Git itself calls ambiguous is refused rather than read twice.
    assert!(!keeps_under("command.git.tag", "tag --f v1.0.0 HEAD"));
}

#[test]
fn a_listing_option_that_merely_starts_like_one_stays_contained() {
    // `--format` and `--file` share letters with `--force` without being an
    // abbreviation of it, and neither changes a tag.
    assert!(keeps_under("command.git.tag", "tag --format=%(refname)"));
    assert!(keeps_under("command.git.tag", "tag -l --format=%(refname)"));
    assert!(keeps_under(
        "command.git.tag",
        "tag -a v1.0.0 --file=notes.txt"
    ));
    assert!(keeps_under("command.git.tag", "tag --list v1.*"));
    assert!(keeps_under("command.git.tag", "tag --contains HEAD"));
}

#[test]
fn a_rule_this_module_does_not_answer_for_has_no_keeping_form() {
    assert!(super::keeping_form("command.git.hard-reset").is_none());
    assert!(super::keeping_form("command.git.force-clean").is_none());
}
