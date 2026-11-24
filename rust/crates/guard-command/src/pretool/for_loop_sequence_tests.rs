//! A `for` loop over a brace sequence such as `{1..60}`, the usual way to
//! wait on something a bounded number of times.

use super::for_loop_tests::decide;

#[test]
fn a_sequence_header_unrolls_to_its_numbers() {
    for (looped, unrolled) in [
        (
            "for n in {1..3}; do echo $n; done",
            "echo 1; echo 2; echo 3",
        ),
        (
            "for n in {3..1}; do echo $n; done",
            "echo 3; echo 2; echo 1",
        ),
        (
            "for n in {0..20..10}; do echo $n; done",
            "echo 0; echo 10; echo 20",
        ),
        (
            "for n in a {1..2} b; do echo $n; done",
            "echo a; echo 1; echo 2; echo b",
        ),
    ] {
        assert_eq!(
            super::for_loop_unroll::unroll(looped).as_deref(),
            Some(unrolled),
            "{looped}"
        );
    }
}

/// A body that never reads the loop variable is the same text on every pass,
/// so one pass is written out however long the sequence is.
#[test]
fn a_body_that_ignores_the_variable_is_written_out_once() {
    for (looped, unrolled) in [
        ("for n in {1..135}; do sleep 20; done", "sleep 20"),
        (
            "for n in {1..135}; do if ! ps -p 4242 >/dev/null 2>&1; then break; fi; sleep 20; done",
            "if ! ps -p 4242 >/dev/null 2>&1; then break; fi; sleep 20",
        ),
    ] {
        assert_eq!(
            super::for_loop_unroll::unroll(looped).as_deref(),
            Some(unrolled),
            "{looped}"
        );
    }
}

#[test]
fn a_read_only_wait_loop_over_a_sequence_is_allowed() {
    for command in [
        "for n in {1..135}; do if ! ps -p 4242 >/dev/null 2>&1; then break; fi; sleep 20; done",
        "for n in {1..30}; do sleep 2; done; date '+%Y-%m-%d %H:%M:%S %z'",
        "for i in {1..5}; do echo \"pass $i\"; done",
    ] {
        let (action, reason) = decide(command);
        assert_ne!(action, "review", "{command}: {reason}");
        assert_ne!(action, "block", "{command}: {reason}");
    }
}

/// The loop proves nothing its body would not: a write in the body keeps its
/// own verdict however the header is written.
#[test]
fn a_sequence_keeps_the_body_verdict() {
    for command in [
        "for n in {1..3}; do rm -rf build$n; done",
        "for n in {1..135}; do rm -rf build; done",
        "for n in {1..3}; do cat .env; done",
    ] {
        assert_eq!(
            decide(command),
            decide(
                &command
                    .replacen("{1..3}", "1 2 3", 1)
                    .replacen("{1..135}", "1", 1)
            ),
            "{command}"
        );
        assert_ne!(decide(command).0, "allow", "{command}");
    }
}

#[test]
fn other_brace_words_keep_their_review() {
    for looped in [
        // A referenced variable over more numbers than the word bound.
        "for n in {1..135}; do echo $n; done",
        // Padding, signs, letters, a zero step and glued text are not read.
        "for n in {01..10}; do echo $n; done",
        "for n in {-1..1}; do echo $n; done",
        "for n in {a..c}; do echo $n; done",
        "for n in {1..5..0}; do echo $n; done",
        "for n in {1..3}x; do echo $n; done",
        "for n in x{1..3}; do echo $n; done",
        "for n in {1,2}; do echo $n; done",
        "for n in {1..3; do echo $n; done",
        "for n in {1234567..1234568}; do echo $n; done",
    ] {
        assert_eq!(super::for_loop_unroll::unroll(looped), None, "{looped}");
    }
}
