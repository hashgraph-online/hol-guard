//! A `cat` stage after a sibling `cd`, which respells the run's output
//! without opening anything.
use super::{contained, fixture, host, reason};

/// `| cat -v` after a sibling run is the same work the pipeline spelled.
///
/// An agent reaching into a checkout beside the session runs its suite and
/// pipes the output through `cat` to make escape codes legible. `cat` with no
/// operand reads standard input and copies it, so the sandbox's own shell runs
/// the stage in the root the `cd` named, exactly as `| cut` already did. The
/// stage was not a rejoined filter, so the whole run was reviewed instead.
#[test]
fn a_cat_that_only_respells_the_output_stays_contained() {
    let (home, main, _tree) = fixture();
    let projects = main.parent().unwrap();
    for stage in ["cat -v", "cat -A | head -30", "cat -n", "cat"] {
        let command = format!(
            "cd {}/other && npm run build 2>&1 | {stage}",
            projects.display()
        );
        assert_eq!(
            contained(&reason("omp", &home, &main, &command)),
            host(),
            "{command}"
        );
    }
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}

/// A `cat` given a file opens it, which no containment proof screened.
#[test]
fn a_cat_that_opens_a_file_keeps_its_review() {
    let (home, main, _tree) = fixture();
    let projects = main.parent().unwrap();
    let command = format!(
        "cd {}/other && npm run build 2>&1 | cat {}/.ssh/id_rsa",
        projects.display(),
        home.display()
    );
    assert!(
        !contained(&reason("omp", &home, &main, &command)),
        "{command}"
    );
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}
