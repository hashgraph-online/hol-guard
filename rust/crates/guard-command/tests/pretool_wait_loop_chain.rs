//! Two read-only wait loops written one after the other settle like one loop:
//! the agent waits for a lock to appear and then for it to clear. Each loop's
//! test and body are read-only probes and sleeps, so the chain is too.
#![cfg(unix)]

use crate::pretool_contained_wrappers::{classify, fixture};

#[test]
fn chained_read_only_wait_loops_are_allowed() {
    let root = fixture();
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for command in [
            "until test -e build/lock.d/pid; do sleep 60; done; until ! test -e build/lock.d/pid; do sleep 30; done",
            "until test -f build/ready; do sleep 2; done\nwhile test -e build/lock.d/pid; do sleep 5; done; echo finished",
            "until test -d .; do sleep 1; done; until ! test -e build/lock.d/pid; do sleep 1; done; echo \"lock cleared\"",
        ] {
            let result = classify(&root, harness, command);
            assert_eq!(result.decision, "allow", "{harness}: {command}");
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_chained_loop_that_writes_or_reads_the_first_outcome_keeps_its_review() {
    let root = fixture();
    for harness in ["omp", "codex"] {
        for command in [
            "until test -e build/lock.d/pid; do sleep 60; done; until ! test -e build/lock.d/pid; do rm -rf build; done",
            "until test -e build/lock.d/pid; do sleep 60; done && until ! test -e build/lock.d/pid; do sleep 30; done",
            "until test -e build/lock.d/pid; do sleep 60; done; until ! test -e build/lock.d/pid; do sleep 30; done > wait.log",
        ] {
            let result = classify(&root, harness, command);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}
