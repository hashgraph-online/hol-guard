//! Words that end a step the shell is already running.
//!
//! `exit`, `break` and `continue` decide which later step runs. They name no
//! program, open no file and run no code of their own, so each one is read
//! here on its own operand rather than through the executable proofs.

/// `exit` with no operand or a literal status ends the shell running the
/// command and touches nothing else. In `rg -n TODO notes.md && exit 1 || true`
/// it only decides which later step runs, and each of those steps carries its
/// own proof.
pub(super) fn safe_exit_arguments(arguments: &[String]) -> bool {
    match arguments {
        [] => true,
        [status] => {
            (1..=3).contains(&status.len()) && status.bytes().all(|byte| byte.is_ascii_digit())
        }
        _ => false,
    }
}

/// `break` and `continue` end or restart the iteration the shell is already
/// running and reach nothing outside it.
///
/// A retry writes them: `for i in 1 2 3; do curl -sf "$URL" && break; sleep 1;
/// done` asks a question until it answers and then stops asking. The question
/// carries its own proof, and the word that stops the loop names no program,
/// opens no file and runs no code of its own -- outside a loop the shell
/// either refuses it or does nothing at all.
///
/// The optional operand is the number of enclosing loops to leave. It is a
/// literal count, so an expansion or any other word is some other reading.
/// `0` is not a count: `break 0` is an error in every shell this models.
pub(super) fn safe_loop_control_arguments(arguments: &[String]) -> bool {
    match arguments {
        [] => true,
        [level] => {
            (1..=2).contains(&level.len())
                && level.bytes().all(|byte| byte.is_ascii_digit())
                && !level.starts_with('0')
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn a_bare_or_literal_status_exit_is_inert() {
        for values in [&[][..], &["0"], &["1"], &["255"]] {
            assert!(super::safe_exit_arguments(&arguments(values)), "{values:?}");
        }
    }

    #[test]
    fn an_exit_operand_that_is_not_a_literal_status_stays_reviewed() {
        for values in [
            &["$STATUS"][..],
            &["$(rm -rf build)"],
            &["-1"],
            &["1000"],
            &[""],
            &["1", "2"],
        ] {
            assert!(
                !super::safe_exit_arguments(&arguments(values)),
                "{values:?}"
            );
        }
    }

    #[test]
    fn a_bare_or_counted_loop_control_is_inert() {
        for values in [&[][..], &["1"], &["2"], &["99"]] {
            assert!(
                super::safe_loop_control_arguments(&arguments(values)),
                "{values:?}"
            );
        }
    }

    #[test]
    fn a_loop_control_operand_that_is_not_a_literal_count_stays_reviewed() {
        for values in [
            &["$LEVEL"][..],
            &["$(rm -rf build)"],
            &["0"],
            &["01"],
            &["-1"],
            &["100"],
            &[""],
            &["1", "2"],
        ] {
            assert!(
                !super::safe_loop_control_arguments(&arguments(values)),
                "{values:?}"
            );
        }
    }
}
