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
        // A run may drop its standard error, as long as a bound follows it.
        format!(
            "cd {0}/scripts && ./report.sh 2>/dev/null | head -20 && ./report.sh",
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
        // The sink rejoins a dropped standard error only under a bound, so a
        // run holding one with no stage after it keeps its review. The parse
        // leaves this redirect out of the segment's words, so the grammar
        // reads it from the segment's own text.
        format!(
            "cd {0}/scripts && ./report.sh 2>/dev/null && ./report.sh",
            tree.display()
        ),
        format!(
            "cd {0}/scripts && ./report.sh && ./report.sh 2>/dev/null",
            tree.display()
        ),
    ] {
        assert!(
            !contained(&reason("omp", &home, &main, &command)),
            "{command}"
        );
    }
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}

/// Two or more runs after a sibling `cd`, the later ones written after a
/// `;`, stay contained below the root.
///
/// An agent that steps into a checkout beside the session and reads two
/// things from it writes the second read after a `;`, so it runs whatever
/// the first one reported. That list had no core and went to review, while
/// the same two steps joined by `&&` ran contained. The sink runs this shape
/// as the text spelled it, `cd` included, with the sandbox rooted at the
/// repository, so a step after the `;` runs there whether or not the `cd`
/// arrived -- and every path it names is read against the root as well as
/// the `cd` target.
#[test]
fn a_sequenced_list_after_a_sibling_cd_stays_contained() {
    let (home, main, tree) = fixture();
    worktree_packages(&main, &tree);
    for command in [
        format!("cd {0}/scripts && ./report.sh; ./report.sh", tree.display()),
        format!("cd {0}/scripts; ./report.sh; ./report.sh", tree.display()),
        format!(
            "cd {0}/scripts && ./report.sh | head; ./report.sh | head -5",
            tree.display()
        ),
        format!(
            "cd {0}/scripts && ./report.sh 2>&1 | head -20; ./report.sh | tail -5",
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

/// A sequenced list keeps the grammar the joined one keeps.
///
/// The `;` buys nothing else: a step naming a path outside the trees the
/// sandbox mounts, a redirection the sink hands no shell, a stage that is
/// not a bound, a second `cd`, or a `||` arm that runs exactly when the step
/// before it failed, all keep their review.
#[test]
fn a_sequenced_list_outside_that_grammar_keeps_its_review() {
    let (home, main, tree) = fixture();
    worktree_packages(&main, &tree);
    let projects = main.parent().unwrap().to_path_buf();
    for command in [
        format!(
            "cd {0}/scripts && ./report.sh; ./report.sh {1}/plain",
            tree.display(),
            projects.display()
        ),
        format!(
            "cd {0}/scripts && ./report.sh; ./report.sh > out.txt",
            tree.display()
        ),
        format!(
            "cd {0}/scripts && ./report.sh; ./report.sh | head | tail -2",
            tree.display()
        ),
        format!(
            "cd {0}/scripts && ./report.sh; cd {1}/plain && ./report.sh",
            tree.display(),
            projects.display()
        ),
        format!(
            "cd {0}/scripts && ./report.sh; ./report.sh || ./report.sh",
            tree.display()
        ),
    ] {
        assert!(
            !contained(&reason("omp", &home, &main, &command)),
            "{command}"
        );
    }
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}

