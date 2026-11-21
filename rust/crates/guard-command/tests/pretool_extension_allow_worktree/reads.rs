//! `git fetch origin main; git worktree add <path> origin/main; ls <path>`:
//! the ordinary reads an agent runs beside a refresh and an add, under the
//! user's Git and GitHub Allow.
//!
//! A refresh the whole-command proof cannot settle (an origin it will not
//! vouch for, a hook in the repository) leaves the user's Allow to cover the
//! two Git steps, and the read after them has to stand on its own. The add
//! writes only into a checkout that does not exist yet, so a read of any
//! other path opens a file the add never touches, and a listing of the
//! checkout prints the names the add just wrote there. Opening a file in the
//! new checkout keeps its review: the ref decides whether a name is a file
//! or a link out of the checkout, and a fetch in the same command can move
//! that ref.

use super::*;

const HARNESSES: [&str; 4] = ["omp", "zcode", "claude-code", "codex"];

/// A refresh of the repository's origin.
const FETCH: &str = "git fetch origin main";

/// `org/app` with an origin on a self-hosted host. The whole-command proof
/// vouches for a fetch only from GitHub, so the refresh here is a step the
/// user's Allow covers and nothing else does -- the shape in which the add
/// and the read after it have to stand on their own.
fn self_hosted_repository(name: &str) -> (FixtureCleanup, PathBuf, PathBuf) {
    let (cleanup, home, checkout) = repository(name);
    git(
        &home,
        &checkout,
        &[
            "remote",
            "set-url",
            "origin",
            "https://git.example.invalid/example-org/app-portal.git",
        ],
    );
    (cleanup, home, checkout)
}

/// `org/app` with an origin that is a path on this filesystem, the shape the
/// Gauntlet's git ALLOW lane builds so its refresh runs offline. The proof
/// vouches for no such origin either, so the refresh is again a step only the
/// user's Allow covers.
fn filesystem_origin_repository(name: &str) -> (FixtureCleanup, PathBuf, PathBuf) {
    let (cleanup, home, checkout) = repository(name);
    let origin = home.join("origin.git");
    git(
        &home,
        &checkout,
        &["remote", "set-url", "origin", &origin.display().to_string()],
    );
    (cleanup, home, checkout)
}

fn allowed(home: &Path, checkout: &Path, commands: &[String]) {
    let controls = git_github("enabled", &[]);
    let mut failures = Vec::new();
    for harness in HARNESSES {
        for command in commands {
            let result = evaluate(home, checkout, harness, command, &controls);
            if result.minimum_action != "allow" {
                failures.push(format!(
                    "{harness}: {command}: {} {}",
                    result.minimum_action, result.reason_code
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn reads_beside_the_add_run_under_the_allow() {
    let (_cleanup, home, checkout) = repository("reads-beside");
    let outside = home.join("org/app-taken");
    let outside = outside.display();
    allowed(
        &home,
        &checkout,
        &[
            format!("{ADD} && ls ../app-taken"),
            format!("{ADD} && ls {outside}"),
            format!("{ADD}; ls ../app-taken"),
            format!("{ADD} && cat README.md"),
            format!("{ADD} && head -5 README.md"),
            format!("{ADD} && tail -5 README.md"),
            format!("{ADD} && wc -l README.md"),
            format!("{ADD} && ls ../app-taken && cat README.md"),
            format!("{FETCH}; {ADD}; ls ../app-taken"),
            format!("{FETCH}; {ADD}; cat README.md"),
        ],
    );
}

/// The reported false positive: a refresh, an add and a listing of the
/// checkout it creates, with the output of each Git step trimmed.
#[test]
fn listings_of_the_new_checkout_run_under_the_allow() {
    let (_cleanup, home, checkout) = self_hosted_repository("reads-inside");
    let inside = home.join("org/app-review");
    let inside = inside.display();
    allowed(
        &home,
        &checkout,
        &[
            format!("{FETCH}; {ADD}; ls ../app-review"),
            format!("{FETCH}; {ADD}; ls {inside}"),
            format!("{FETCH}; {ADD}; ls -la ../app-review"),
            format!("{FETCH} 2>&1 | tail -2; {ADD} 2>&1 | tail -3; ls ../app-review"),
            format!("{FETCH} 2>&1 | tail -2; {ADD} 2>&1 | tail -3; ls {inside}"),
            // The spelling the Gauntlet's git ALLOW lane runs.
            format!("{FETCH} && {ADD} && ls ../app-review"),
            "git fetch origin main && git worktree add -b read-lane ../app-review HEAD && ls ../app-review"
                .to_string(),
        ],
    );
}

/// The Gauntlet git ALLOW lane's own shape: a refresh from a bare origin
/// beside the checkout, an add, and a listing of the checkout it creates.
#[test]
fn listings_of_the_new_checkout_run_under_the_allow_against_a_filesystem_origin() {
    let (_cleanup, home, checkout) = filesystem_origin_repository("reads-local-origin");
    allowed(
        &home,
        &checkout,
        &[
            format!("{FETCH} && {ADD} && ls ../app-review"),
            format!("{FETCH}; {ADD}; ls -1 ../app-review"),
        ],
    );
}

/// Opening a file of the new checkout, and reads the proof answers for
/// nowhere. The ref decides the mode of every name it writes into the
/// checkout, so no file there is opened under the Allow, and a path the
/// proof refuses in the repository is refused in the checkout too.
#[test]
fn reads_of_the_new_checkout_keep_their_review() {
    let (_cleanup, home, checkout) = self_hosted_repository("reads-refused");
    let controls = git_github("enabled", &[]);
    let inside = home.join("org/app-review");
    let inside = inside.display();
    for command in [
        format!("{FETCH}; {ADD}; cat ../app-review/README.md"),
        format!("{FETCH}; {ADD}; head -5 {inside}/README.md"),
        format!("{FETCH}; {ADD}; grep -r token ../app-review"),
        format!("{FETCH}; {ADD}; ls ../app-review/docs"),
        format!("{FETCH}; {ADD}; cat ../app-review/.env"),
        format!("{FETCH}; {ADD}; cat {inside}/.env"),
        format!("{FETCH}; {ADD}; cat ../app-review/secrets/id_rsa"),
        format!("{FETCH}; {ADD}; cat ~/.ssh/id_rsa"),
        format!("{FETCH}; {ADD}; cat ../app-review/README.md ../app-taken/README.md"),
    ] {
        let result = evaluate(&home, &checkout, "omp", &command, &controls);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

#[test]
fn the_reads_wait_without_an_allow() {
    let (_cleanup, home, checkout) = self_hosted_repository("reads-default");
    let controls = fixture::github_controls("default");
    for command in [
        format!("{FETCH}; {ADD}; ls ../app-review"),
        format!("{FETCH}; {ADD}; ls ../app-taken"),
    ] {
        let result = evaluate(&home, &checkout, "omp", &command, &controls);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

/// A name the ref turns into a link out of the checkout, while the
/// repository's own working tree holds an ordinary file of that name.
///
/// `origin/main` carries `notes.txt` as a symbolic link to a file beside the
/// repository; `main`, which the working tree is on, carries `notes.txt` as a
/// plain file. The repository's copy therefore says nothing about what a read
/// of the checkout would open.
fn linked_name_repository(name: &str) -> (FixtureCleanup, PathBuf, PathBuf) {
    let (cleanup, home, checkout) = self_hosted_repository(name);
    let planted = home.join("org/app-taken/vault-token.txt");
    std::fs::write(&planted, "SYNTHETIC-VALUE-NOT-A-SECRET\n").unwrap();
    std::fs::write(checkout.join("notes.txt"), "ordinary notes\n").unwrap();
    git(&home, &checkout, &["add", "notes.txt"]);
    git(&home, &checkout, &["commit", "--quiet", "-m", "notes"]);
    git(
        &home,
        &checkout,
        &["checkout", "--quiet", "-b", "link-lane"],
    );
    std::fs::remove_file(checkout.join("notes.txt")).unwrap();
    std::os::unix::fs::symlink(&planted, checkout.join("notes.txt")).unwrap();
    git(&home, &checkout, &["add", "-A"]);
    git(&home, &checkout, &["commit", "--quiet", "-m", "link"]);
    git(
        &home,
        &checkout,
        &["update-ref", "refs/remotes/origin/main", "link-lane"],
    );
    git(&home, &checkout, &["checkout", "--quiet", "main"]);
    (cleanup, home, checkout)
}

/// The read the surrogate proof would have got wrong: `notes.txt` is a plain
/// file in the repository and a link out of the checkout at the ref the add
/// names, so only the listing of the checkout runs under the Allow.
#[test]
fn a_name_the_ref_links_out_of_the_checkout_keeps_its_review() {
    let (_cleanup, home, checkout) = linked_name_repository("reads-linked");
    let controls = git_github("enabled", &[]);
    assert_eq!(
        std::fs::read_to_string(checkout.join("notes.txt")).unwrap(),
        "ordinary notes\n",
        "the repository's own copy is an ordinary file"
    );
    for command in [
        format!("{FETCH}; {ADD}; cat ../app-review/notes.txt"),
        format!("{ADD} && cat ../app-review/notes.txt"),
        format!("{ADD} && head -5 ../app-review/notes.txt"),
    ] {
        let result = evaluate(&home, &checkout, "omp", &command, &controls);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
    allowed(
        &home,
        &checkout,
        &[
            format!("{FETCH}; {ADD}; ls ../app-review"),
            format!("{ADD} && ls ../app-taken"),
        ],
    );
}

/// A fetch in the same command moves the reference the add names, so the
/// tree the add checks out is not the one a proof of the add on its own
/// reads.
///
/// The home here configures a filter Git would run while writing the new
/// checkout, which the proof settles by reading the attributes of the commit
/// the reference points at. Behind a fetch that commit can be gone by the
/// time the add runs, so the add is no longer proven and the listing beside
/// it keeps its review. The same add with nothing before it still runs under
/// the Allow.
#[test]
fn a_fetch_before_the_add_holds_the_listing() {
    let (_cleanup, home, checkout) = self_hosted_repository("reads-filtered");
    git(
        &home,
        &checkout,
        &[
            "config",
            "--global",
            "filter.example.smudge",
            "/opt/example/smudge %f",
        ],
    );
    allowed(&home, &checkout, &[format!("{ADD} && ls ../app-review")]);
    let controls = git_github("enabled", &[]);
    for command in [
        format!("{FETCH}; {ADD}; ls ../app-review"),
        format!("{FETCH} && {ADD} && ls ../app-review"),
    ] {
        let result = evaluate(&home, &checkout, "omp", &command, &controls);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

/// A listing that walks the new checkout, or follows the links in it, reads
/// what the ref supplies rather than the names the add writes. The flags are
/// screened against the repository the checkout comes from, which answers for
/// neither, so every recursive and dereferencing spelling keeps its review.
#[test]
fn a_walking_or_dereferencing_listing_keeps_its_review() {
    let (_cleanup, home, checkout) = self_hosted_repository("reads-walking");
    let controls = git_github("enabled", &[]);
    for command in [
        format!("{FETCH}; {ADD}; ls -R ../app-review"),
        format!("{FETCH}; {ADD}; ls --recursive ../app-review"),
        format!("{FETCH}; {ADD}; ls --rec ../app-review"),
        format!("{FETCH}; {ADD}; ls -L --rec ../app-review"),
        format!("{FETCH}; {ADD}; ls -L ../app-review"),
        format!("{FETCH}; {ADD}; ls -H ../app-review"),
        format!("{FETCH}; {ADD}; ls --dereference ../app-review"),
    ] {
        let result = evaluate(&home, &checkout, "omp", &command, &controls);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

/// A step named on a directory that holds the new checkout. The add writes
/// below it, so a recursive read of it walks the tree the ref supplies even
/// though the directory itself was there all along.
#[test]
fn a_recursive_read_of_a_directory_holding_the_checkout_keeps_its_review() {
    let (_cleanup, home, checkout) = self_hosted_repository("reads-ancestor");
    let controls = git_github("enabled", &[]);
    let nested = "git worktree add -b review sub/app-review origin/main";
    for command in [
        format!("{FETCH}; {nested}; grep -R --regexp=token ."),
        format!("{FETCH}; {nested}; grep -R --regexp=token sub"),
        format!("{FETCH} && {nested} && grep -R --regexp=token ."),
    ] {
        let result = evaluate(&home, &checkout, "omp", &command, &controls);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}
