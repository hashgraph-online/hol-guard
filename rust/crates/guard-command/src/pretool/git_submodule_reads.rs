//! The one `git submodule` spelling that only prints: `submodule status`.
//!
//! Every other submodule verb moves work. `add`, `init`, `deinit`, `update`,
//! `sync`, `set-url`, `set-branch` and `absorbgitdirs` write configuration,
//! refs or the worktree, and `foreach` runs whatever command it is handed, so
//! none of them belongs here. `summary` prints a diff, so it would need the
//! diff machinery's own proof rather than this one.
//!
//! `status` prints one line per submodule: the recorded object id, the path,
//! and the ref it describes. Git reaches that answer from the superproject —
//! it reads the superproject index, so a configured `core.fsmonitor` there can
//! still start, which the configuration probe clears — and then runs `git
//! describe` inside each submodule against the recorded id. A describe of a
//! named object pages nothing, converts nothing and refreshes no index.
//!
//! `--recursive` is the line this grammar will not cross. It re-enters each
//! submodule with `submodule--helper status --recursive`, which reads that
//! submodule's own index under that submodule's own configuration. A
//! `core.fsmonitor` set in a submodule executes under `--recursive` and does
//! not under the plain form, and the superproject-rooted configuration probe
//! never reads it, so the recursive walk keeps its review.
//!
//! Bare `git submodule` is `git submodule status`, and is admitted as one.
//! So is `--quiet`, the shared option Git's synopsis places before the verb:
//! it chooses how much the listing prints and names no path.
//!
//! `--cached` is the other line this grammar will not cross. The plain
//! listing describes each submodule's own `HEAD`, an object that submodule
//! holds by definition. `--cached` describes the id the superproject's index
//! records instead, which a partial-clone submodule need not have: `git
//! describe` then pages it in through that submodule's promisor remote,
//! running its transport and whatever credential helper it names and writing
//! the objects it brings back. Nothing in the superproject-rooted probe sees
//! that remote, so the cached listing keeps its review.

/// Whether `arguments`, the tokens after the `submodule` subcommand, name the
/// printing form.
pub(crate) fn read_form(arguments: &[String]) -> bool {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    // Git's synopsis puts the shared options before the verb: `git submodule
    // [--quiet] [--cached] <command>`. `--quiet` only chooses how much the
    // listing prints and names no path, so a leading one leaves the form
    // unchanged; `--cached` changes which object is described and is refused
    // wherever it stands.
    let rest = match words
        .iter()
        .position(|word| !matches!(*word, "-q" | "--quiet"))
    {
        // Bare `git submodule`, and `--quiet` alone, run `status`.
        None => return true,
        Some(index) => &words[index..],
    };
    match rest.split_first() {
        Some((&"status", rest)) => status(rest),
        _ => false,
    }
}

/// `submodule status` with the options that only choose how much it prints,
/// and plain path operands. Every other option, `--recursive` above all,
/// keeps its review.
fn status(rest: &[&str]) -> bool {
    let mut operands = false;
    rest.iter().all(|argument| match *argument {
        _ if operands => operand(argument),
        "-q" | "--quiet" => true,
        "--" => {
            operands = true;
            true
        }
        _ => operand(argument),
    })
}

/// A submodule path as `status` takes it: a plain name, never an option and
/// never a magic pathspec.
fn operand(value: &str) -> bool {
    !value.is_empty() && !value.starts_with('-') && !value.starts_with(':')
}

#[cfg(test)]
mod tests {
    use super::read_form;

    fn form(arguments: &[&str]) -> bool {
        read_form(
            &arguments
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn printing_forms_are_read_forms() {
        assert!(form(&[]));
        assert!(form(&["status"]));
        assert!(form(&["status", "-q"]));
        assert!(form(&["status", "--quiet"]));
        assert!(form(&["status", "vendor/lib"]));
        assert!(form(&["status", "--", "vendor/lib"]));
    }

    /// Git's synopsis is `git submodule [--quiet] <command>`, so `--quiet`
    /// may stand before the verb, and alone it still runs `status`.
    #[test]
    fn shared_options_may_precede_the_verb() {
        assert!(form(&["-q", "status"]));
        assert!(form(&["--quiet", "status"]));
        assert!(form(&["--quiet", "status", "vendor/lib"]));
        assert!(form(&["-q"]));
        assert!(form(&["--quiet"]));
        // The verb still decides: a leading option admits nothing else.
        assert!(!form(&["--quiet", "foreach", "git", "status"]));
        assert!(!form(&["-q", "update"]));
        assert!(!form(&["--quiet", "status", "--recursive"]));
    }

    #[test]
    fn a_recursive_walk_keeps_its_review() {
        // It reads each submodule's own configuration, which the
        // superproject-rooted probe never saw.
        assert!(!form(&["status", "--recursive"]));
        assert!(!form(&["status", "--recursive", "vendor/lib"]));
    }

    /// `--cached` describes the id the superproject records rather than the
    /// submodule's own `HEAD`. A partial-clone submodule may not hold that
    /// object, and `git describe` fetches it through the submodule's promisor
    /// remote, so the cached listing keeps its review wherever the option
    /// stands.
    #[test]
    fn the_cached_listing_keeps_its_review() {
        assert!(!form(&["status", "--cached"]));
        assert!(!form(&["--cached", "status"]));
        assert!(!form(&["--cached"]));
        assert!(!form(&["--quiet", "--cached", "status"]));
        assert!(!form(&["status", "--cached", "--", "vendor/lib"]));
    }

    #[test]
    fn verbs_that_move_work_keep_their_review() {
        for verb in [
            "add",
            "init",
            "deinit",
            "update",
            "sync",
            "foreach",
            "set-url",
            "set-branch",
            "absorbgitdirs",
            "summary",
        ] {
            assert!(!form(&[verb]), "{verb} is not a read form");
        }
        assert!(!form(&["foreach", "git", "status"]));
    }

    #[test]
    fn unknown_options_and_magic_pathspecs_keep_their_review() {
        assert!(!form(&["status", "--unknown"]));
        assert!(!form(&["status", ":(glob)**/id_rsa"]));
        assert!(!form(&["status", "--", "--recursive"]));
        assert!(!form(&["status", "--", ":/"]));
    }
}
