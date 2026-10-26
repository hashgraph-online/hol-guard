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
