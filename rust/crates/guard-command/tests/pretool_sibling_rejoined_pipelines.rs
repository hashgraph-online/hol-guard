//! A sibling checkout's runner piped through filters the peel has no grammar
//! for: the sink rejoins the list and the root's own shell runs the pipeline.
#![cfg(unix)]

use crate::pretool_contained_wrappers::{classify, fixture, package};

/// A sibling checkout's runner may end in a filter the peel has no grammar
/// for. The sink rejoins the whole list instead of peeling the filter out, and
/// the sandbox's own shell runs the pipeline in that root, so `| cut` or
/// `| sort` bounds the output exactly as `| tail` does. A stage that would run
/// a program of its own is not a filter and keeps its review.
#[test]
fn rejoined_sibling_pipelines_reach_containment() {
    let root = fixture();
    let sibling = root.join("sibling-worktree");
    std::fs::create_dir_all(sibling.join("dashboard")).unwrap();
    // A linked worktree marks its root with a `.git` file.
    std::fs::write(sibling.join(".git"), "gitdir: /nonexistent\n").unwrap();
    package(&sibling);
    let sibling = sibling.to_str().unwrap();
    let runner = format!("cd {sibling} && ./node_modules/.bin/vite build");
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for command in [
            format!("{runner} 2>&1 | cut -c1-120"),
            format!("{runner} | cut -c1-120"),
            format!("{runner} 2>&1 | sort -u | head -40"),
            format!("{runner} 2>/dev/null | cut -d: -f1 | sort | uniq -c | sort -rn"),
            format!("{runner} 2>&1 | wc -l"),
        ] {
            let result = classify(&root, harness, &command);
            assert_eq!(result.decision, "deny", "{harness}: {command}");
            if cfg!(target_os = "macos") {
                assert_eq!(
                    result.minimum_action, "sandbox-required",
                    "{harness}: {command}"
                );
            }
        }
        for command in [
            format!("{runner} 2>&1 | sh"),
            format!("{runner} 2>&1 | xargs rm"),
            format!("{runner} 2>&1 | cut -c1-120 | bash -s"),
            // A rejoined stage reads standard input and nothing else: an
            // operand is a file the containment proof never screened, and
            // `sort -o` writes one.
            format!("{runner} 2>&1 | head /etc/passwd"),
            format!("{runner} 2>&1 | head -5 /etc/passwd"),
            format!("{runner} 2>&1 | cut -f1 /etc/passwd"),
            format!("{runner} 2>&1 | sort /etc/passwd"),
            format!("{runner} 2>&1 | sort -o {sibling}/out.txt"),
            format!("{runner} 2>&1 | sort -o{sibling}/out.txt"),
            format!("{runner} 2>&1 | sort --output={sibling}/out.txt"),
            format!("{runner} 2>&1 | wc -l /etc/passwd"),
        ] {
            let result = classify(&root, harness, &command);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
            assert_ne!(
                result.minimum_action, "sandbox-required",
                "{harness}: {command}"
            );
        }
    }
}
