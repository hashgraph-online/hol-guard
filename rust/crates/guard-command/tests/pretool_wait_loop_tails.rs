#![cfg(unix)]

//! A wait loop that holds the next step until a process exits.
//!
//! `while kill -0 PID 2>/dev/null; do sleep 15; done; echo done; date` is how
//! a developer waits for a build they started earlier and then reports that
//! it finished. The wait reading refused it twice over: the test's inert
//! redirect to the null device counted as a file the next pass would reach
//! again, and the command list after `done` counted as a redirection opened
//! once and written through on every pass. Neither is what those two pieces
//! of text say, so the whole command went to review.
//!
//! The null sink holds nothing, and the list after `done` runs once when the
//! wait is over, so the flat list carries both and every command in it still
//! faces the ordinary proofs. A redirection after `done`, a join that reads
//! the loop's own outcome, and a continuation that is not read-only all keep
//! their review.
//!
//! The question the wait asks had no read-only proof of its own either, so
//! the flat list reported `kill` as an unproven step. Signal 0 is delivered
//! to nothing: the kernel performs the permission check and returns, which
//! is the same answer `ps -p PID` already prints here. Every other signal,
//! an operand that is not one named process, and an expansion standing in
//! for one all keep their review.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn a_wait_for_a_process_reports_when_it_is_over() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/wait-loop-tail-fixtures")
        .join(format!("fixture-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    for harness in ["omp", "zcode"] {
        for (command, allowed) in [
            ("while kill -0 4821 2>/dev/null; do sleep 15; done", true),
            (
                "while kill -0 4821 2>/dev/null; do sleep 15; done; echo \"build finished\"; date -u +%H:%M:%SZ",
                true,
            ),
            ("until kill -0 4821; do sleep 5; done; echo gone", true),
            // The loop's own redirection is opened once and written through
            // on every pass.
            (
                "while kill -0 4821 2>/dev/null; do sleep 15; done > wait.log",
                false,
            ),
            // A join that reads the loop's outcome, or backgrounds it, is not
            // the list that runs once after the wait.
            (
                "while kill -0 4821 2>/dev/null; do sleep 15; done && echo done",
                false,
            ),
            (
                "while kill -0 4821 2>/dev/null; do sleep 15; done & echo done",
                false,
            ),
            // The continuation faces the ordinary proofs, so one that is not
            // read-only keeps the whole command in review.
            (
                "while kill -0 4821 2>/dev/null; do sleep 15; done; rm -rf build",
                false,
            ),
            // A sink that is not the whole of what the test opens.
            (
                "while kill -0 4821 2>/dev/null > wait.log; do sleep 15; done",
                false,
            ),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                None,
                None,
                root.to_str(),
                root.to_str(),
            );
            assert_eq!(
                result.minimum_action == "allow",
                allowed,
                "{harness}: {command} -> {} {}",
                result.minimum_action,
                result.reason
            );
        }
    }
}

#[test]
fn asking_whether_a_process_is_alive_reads_it() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/wait-loop-tail-fixtures")
        .join(format!("liveness-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    for harness in ["omp", "zcode"] {
        for (command, allowed) in [
            ("kill -0 4821", true),
            ("kill -0 4821 2>/dev/null", true),
            ("kill -s 0 4821", true),
            ("kill -n 0 4821 4822", true),
            ("echo waiting; kill -0 4821 2>/dev/null; echo asked", true),
            // Every other signal reaches the process it names.
            ("kill -9 4821", false),
            ("kill 4821", false),
            ("kill -s TERM 4821", false),
            // An operand that is not one named process surveys the host.
            ("kill -0 -1", false),
            ("kill -0 0", false),
            // The words the caller wrote are the ones this form reads.
            ("kill -0 $BUILD_PID", false),
            ("kill -0 $((-1))", false),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                None,
                None,
                root.to_str(),
                root.to_str(),
            );
            assert_eq!(
                result.minimum_action == "allow",
                allowed,
                "{harness}: {command} -> {} {}",
                result.minimum_action,
                result.reason
            );
        }
    }
}

/// `>/dev/null 2>&1` is the usual way a wait silences both streams of its
/// probe. The duplication opens nothing of its own, so the test still opens
/// no file, and the probe faces the ordinary proofs in the flat list. A real
/// file, a duplication onto another descriptor and an input redirect each
/// keep their review.
#[test]
fn a_wait_that_silences_both_streams_reads_its_probe() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/wait-loop-tail-fixtures")
        .join(format!("silenced-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    for harness in ["omp", "zcode", "claude-code"] {
        for (command, allowed) in [
            ("until kill -0 4821 >/dev/null 2>&1; do sleep 5; done", true),
            ("while kill -0 4821 > /dev/null 2>&1; do sleep 15; done; echo done", true),
            (
                "until hol-guard approvals wait 0123456789abcdef --json >/dev/null 2>&1; do sleep 60; done",
                true,
            ),
            ("until kill -0 4821 2>&1; do sleep 5; done", true),
            ("until kill -0 4821 2>/dev/null >/dev/null; do sleep 5; done", true),
            // A real file still grows on every pass.
            ("until kill -0 4821 >wait.log 2>&1; do sleep 5; done", false),
            ("until kill -0 4821 2>&1 >wait.log; do sleep 5; done", false),
            // A duplication onto another descriptor, or an input, is not inert.
            ("until kill -0 4821 >/dev/null 2>&3; do sleep 5; done", false),
            ("until kill -0 4821 </dev/tty 2>&1; do sleep 5; done", false),
            // The probe still faces the ordinary proofs.
            ("until rm -rf build >/dev/null 2>&1; do sleep 5; done", false),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                None,
                None,
                root.to_str(),
                root.to_str(),
            );
            assert_eq!(
                result.minimum_action == "allow",
                allowed,
                "{harness}: {command} -> {} {}",
                result.minimum_action,
                result.reason
            );
        }
    }
}
