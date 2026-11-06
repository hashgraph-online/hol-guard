//! Two or more runs joined by `&&` after a `cd` below a sibling root.
use super::{contained, fixture, host, reason, worktree_packages};

/// A checkout's own runs, one after another, stay contained below its root.
///
/// An agent steps into a package inside a checkout beside the session and
/// runs that package's test files one after another. The peel recovers a
/// single core, so the list had none and the whole run was reviewed, while
/// the same list after a `cd` to the root itself ran. Both are rejoined and
/// run from the directory the `cd` named, with the sandbox rooted at the
/// repository either way.
#[test]
fn a_list_of_runs_below_a_sibling_root_stays_contained() {
    let (home, main, tree) = fixture();
    let projects = main.parent().unwrap().to_path_buf();
    worktree_packages(&main, &tree);
    for command in [
        format!("cd {0}/scripts && ./report.sh && ls", tree.display()),
        format!(
            "cd {0}/app-report/scripts && node report.mjs && cat out.md",
            projects.display()
        ),
        format!(
            "cd {0}/scripts && ./report.sh && ./report.sh",
            tree.display()
        ),
        format!(
            "cd {0}/web && ./node_modules/.bin/report build && ./node_modules/.bin/vite build",
            tree.display()
        ),
        // Each run may bound its own output, which is all the sink leaves in
        // the text the root runs.
        format!(
            "cd {0}/scripts && ./report.sh 2>&1 | head -20 && ./report.sh | tail -5",
            tree.display()
        ),
    ] {
        assert_eq!(
            contained(&reason("omp", &home, &main, &command)),
            host(),
            "{command}"
        );
    }
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}

/// The list keeps the narrower grammar the root's own list keeps.
///
/// A stage that is not a bound applies to the one run it follows while the
/// rest of the list still runs, so it is not the work the proof screened. A
/// run naming a path outside the trees the sandbox mounts, a redirection the
/// sink hands no shell, or a second `cd` moving the rest of the list
/// somewhere else, keeps its review too.
#[test]
fn a_list_outside_that_grammar_keeps_its_review() {
    let (home, main, tree) = fixture();
    worktree_packages(&main, &tree);
    let projects = main.parent().unwrap().to_path_buf();
    for command in [
        format!(
            "cd {0}/scripts && ./report.sh 2>&1 | cut -c1-80 && ./report.sh",
            tree.display()
        ),
        format!(
            "cd {0}/scripts && ./report.sh && ./report.sh {1}/plain",
            tree.display(),
            projects.display()
        ),
        format!(
            "cd {0}/scripts && ./report.sh > out.txt && ./report.sh",
            tree.display()
        ),
        format!(
            "cd {0}/scripts && ./report.sh && ./report.sh >> out.txt",
            tree.display()
        ),
        format!(
            "cd {0}/scripts && ./report.sh && cd {1}/plain",
            tree.display(),
            projects.display()
        ),
    ] {
        assert!(
            !contained(&reason("omp", &home, &main, &command)),
            "{command}"
        );
    }
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}
