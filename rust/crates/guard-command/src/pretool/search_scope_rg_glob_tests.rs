//! `rg -g` inclusions that hold a `/`. ripgrep matches such a glob against
//! the path from the search root, and an inclusion overrides both the hidden
//! and the ignore rules, so the walk models it against that same path.

use super::{fixture, write};

fn proven(root: &std::path::Path, globs: &[&str], home: &std::path::Path) -> bool {
    super::super::rg_glob_scope_proven(
        &[root.to_str().unwrap()],
        globs,
        home.to_str(),
        root.to_str(),
    )
}

#[test]
fn a_path_shaped_inclusion_proves_its_own_subtree() {
    let (home, project) = fixture();
    assert!(proven(&project, &["src/**"], &home));
    assert!(proven(&project, &["src/*"], &home));
    assert!(proven(&project, &["**/*.py"], &home));
    // A folder the inclusion never reaches leaves nothing to walk.
    assert!(proven(&project, &["docs/**"], &home));
    // Names and paths mix in one command.
    assert!(proven(&project, &["README.md", "src/**", "*test*"], &home));
}

#[test]
fn a_folder_the_inclusions_cannot_reach_past_is_left_alone() {
    let (home, project) = fixture();
    write(
        project.join("vendor/pkg/.npmrc"),
        "//registry:_authToken=canary\n",
    );
    // ripgrep never descends for a glob that cannot match below the folder,
    // so the store beside the subtree does not hold the search.
    assert!(proven(&project, &["src/**"], &home));
    assert!(proven(&project, &["src/*/deep/*.ts"], &home));
    // A glob that can reach it does hold the search.
    assert!(!proven(&project, &["vendor/**"], &home));
    assert!(!proven(&project, &["**/.npmrc"], &home));
}

#[test]
fn an_inclusion_that_reaches_a_secret_keeps_review() {
    let (home, project) = fixture();
    write(project.join("src/.env"), "TOKEN=canary\n");
    // ripgrep enters a hidden file an inclusion selects, so the walk must
    // refuse the scope even though the name starts with a dot.
    assert!(!proven(&project, &["src/**"], &home));
    assert!(!proven(&project, &["**/.env"], &home));
    // A sibling folder's inclusion never reaches it.
    assert!(proven(&project, &["docs/**"], &home));
}

#[test]
fn an_inclusion_overrides_the_ignore_rules_it_reaches_past() {
    let (home, project) = fixture();
    write(project.join(".gitignore"), "node_modules\n.env\n");
    write(project.join("src/.env"), "TOKEN=canary\n");
    // An inclusion that matches a file outranks the ignore rules, so
    // ripgrep reads the ignored secret and the walk refuses the scope.
    assert!(!proven(&project, &["src/**"], &home));

    // A folder no inclusion matches stays pruned by those same rules, so
    // what it holds is out of reach.
    let (home, project) = fixture();
    write(project.join(".gitignore"), "node_modules\n");
    write(
        project.join("node_modules/pkg/.npmrc"),
        "//registry:_authToken=canary\n",
    );
    assert!(proven(&project, &["src/**"], &home));
    assert!(proven(&project, &["node_modules/**"], &home));
}

#[test]
fn only_an_inclusion_that_selects_git_reaches_it() {
    let (home, project) = fixture();
    write(
        project.join(".git/config"),
        "[remote]\n\turl = https://x@example.test\n",
    );
    // The walk passes over `.git`, as ripgrep's hidden rule does.
    assert!(proven(&project, &["src/**"], &home));
    assert!(proven(&project, &["**/*.py"], &home));
    // A name-shaped glob that could select `.git` has no path to model it
    // with, so no proof is claimed.
    assert!(!proven(&project, &["*"], &home));
    assert!(!proven(&project, &["**"], &home));
    assert!(!proven(&project, &["{src,.git}"], &home));
}

#[test]
fn a_glob_whose_base_is_unmodeled_claims_no_proof() {
    let (home, project) = fixture();
    for glob in [
        "/src/**",
        "src/",
        "../**",
        "src/../**",
        "src//**",
        "src\\**",
    ] {
        assert!(
            !proven(&project, &[glob], &home),
            "{glob} must stay unproven"
        );
    }
}

#[test]
fn an_inclusion_that_selects_git_does_not_outrank_the_metadata_check() {
    let (home, project) = fixture();
    write(
        project.join(".git/config"),
        "[remote \"origin\"]\n\turl = https://token@example.test/x.git\n",
    );
    // A path-shaped inclusion that matches `.git` itself takes the walk
    // inside it, where a content search prints the remote URL's token. A
    // recursive `grep` over the same checkout is refused that file, and an
    // inclusion cannot win more.
    assert!(!proven(&project, &["**/*"], &home));
    // An inclusion that only names paths *below* `.git` never reaches it:
    // ripgrep prunes the directory unless a glob matches the directory
    // itself, so `-g '.git/**'` lists nothing from a checkout.
    assert!(proven(&project, &[".git/**"], &home));

    // The same inclusion over a configuration that carries no credential
    // keeps its proof: the screen reads what the file holds, and refusing
    // every checkout's `.git` would hold an ordinary repository-wide search.
    let (home, project) = fixture();
    write(
        project.join(".git/config"),
        "[remote \"origin\"]\n\turl = https://example.test/x.git\n",
    );
    assert!(proven(&project, &["**/*"], &home));
}
