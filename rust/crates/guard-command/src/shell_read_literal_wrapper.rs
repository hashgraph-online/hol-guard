//! Separate a bounded literal shell payload from a mutable script-file launch
//! (`runtime/shell_read_literal_wrapper.py`, 32 lines — verbatim).

use crate::shell_tokens;

/// Parser-supported transparent shells — not command permission grants.
const TRANSPARENT_SHELLS: &[&str] = &["sh", "bash", "dash", "ash", "zsh"];
const MAX_WRAPPER_BYTES: usize = 8192;

/// `literal_shell_read_payload` (:12-32). Unwrap one exact literal invocation;
/// retain ambiguous launches for review. The caller still classifies every
/// payload operation — no command receives an allow decision here. Extra shell
/// options, positional args, env changes, expansions keep the raw floor.
pub fn literal_shell_read_payload(command_text: &str) -> String {
    if command_text.len() > MAX_WRAPPER_BYTES
        || command_text
            .chars()
            .any(|c| c == '$' || c == '`' || c == '\n' || c == '\r')
    {
        return command_text.to_owned();
    }
    // `shlex.split(posix=True, comments=False)`; error → keep original.
    let tokens = match shell_tokens(command_text, false) {
        Ok(tokens) => tokens,
        Err(_) => return command_text.to_owned(),
    };
    // Login shells (`-lc`) run startup files before the payload; keep the
    // original invocation for review.
    if tokens.len() != 3 || !TRANSPARENT_SHELLS.contains(&tokens[0].as_str()) || tokens[1] != "-c" {
        return command_text.to_owned();
    }
    tokens[2].clone()
}

#[cfg(test)]
mod tests {
    use super::literal_shell_read_payload;

    #[test]
    fn unwraps_exact_literal() {
        // Payload must be a single shell token (quoted); a bare `cat x` is a
        // 4-token invocation and stays unwrapped, matching python.
        assert_eq!(literal_shell_read_payload("sh -c 'a b'"), "a b");
        assert_eq!(literal_shell_read_payload("sh -c \"cat x\""), "cat x");
    }

    #[test]
    fn retains_ambiguous() {
        assert_eq!(literal_shell_read_payload("bash -lc x"), "bash -lc x");
        assert_eq!(literal_shell_read_payload("bash -c a b"), "bash -c a b");
        assert_eq!(literal_shell_read_payload("cat $x"), "cat $x");
        assert_eq!(literal_shell_read_payload("cat `id`"), "cat `id`");
    }
}
