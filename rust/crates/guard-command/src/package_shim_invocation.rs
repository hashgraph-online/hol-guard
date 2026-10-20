//! Whether a command is a bare invocation of one named executable.
//!
//! The package-request path asks this before it will treat a verified
//! package-manager shim as the owner of an external-archive approval: the
//! shim can only own the download it performs itself, so a command that
//! reaches a second program -- through a substitution, a pipeline, a
//! redirection or a command separator -- is not the launch the shim would
//! bind a digest to. The question is about shell structure, so the parse
//! that answers it belongs here and not beside the caller.

use crate::codex_output_shlex::shell_split;

/// Tokens made entirely of these are the lexer's punctuation runs: the
/// separators, redirections and pipelines that reach a second program.
const OPERATOR_CHARACTERS: &str = "();<>|&";

/// True when `command` runs exactly `executable` and nothing else.
///
/// Substitutions are rejected before the lexer sees them: the tokenizer is
/// a word splitter, not an evaluator, so a `$(...)` or a backtick would be
/// carried into a token rather than recognized as another program. Line
/// breaks are rejected for the same reason -- the lexer joins them into the
/// token stream and the second line would disappear into the first command.
pub fn command_invokes_executable(command: &str, executable: &str) -> bool {
    if command.contains('`')
        || command.contains("$(")
        || command.contains('\n')
        || command.contains('\r')
    {
        return false;
    }
    let Some(tokens) = shell_split(command) else {
        return false;
    };
    if tokens.first().map(String::as_str) != Some(executable) {
        return false;
    }
    !tokens
        .iter()
        .any(|token| !token.is_empty() && token.chars().all(|c| OPERATOR_CHARACTERS.contains(c)))
}
