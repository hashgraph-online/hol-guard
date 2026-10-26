//! Stopping the dev server an agent started from a script in this workspace,
//! as `pkill -f 'node server.js' || true` does before it starts the server
//! again.
//!
//! Admitted: `pkill -f` with at most one `TERM` or `INT` signal option
//! (`-TERM`, `-INT`, `-15`, `-2`, `-SIGTERM`, `-SIGINT`) and a pattern that is
//! exactly an interpreter and a relative script that exists below the working
//! directory, such as `node server.js` or `python3 app/main.py`. Those are
//! the signals a server shuts down on.
//!
//! `pkill -f` matches the pattern as an unanchored regex against every
//! command line the user owns, so the stop also reaches the same command run
//! from another directory, a near name such as `node serverXjs`, and a shell
//! whose arguments quote the pattern, the agent's own `bash -c` included. The
//! script check bounds what the agent asked for, not what pkill matches. That
//! is accepted: the user's own processes get a polite TERM or INT they can
//! handle, the same stop the agent would send by hand, and a pattern that
//! names Guard or a harness is refused.
//!
//! Still reviewed: `pkill` without `-f`, a bare program such as `pkill node`
//! or `pkill -f python`, any other option (`-u`, `-U`, `-g`, `-P`, `-t`, `-n`,
//! `-x`, ...), any other signal, a pattern with regex syntax, an absolute or
//! parent path, a script that does not exist, a pattern naming Guard or an
//! agent harness, and `kill` or `killall`.

use std::path::Path;

const INTERPRETERS: &[&str] = &["node", "nodejs", "bun", "tsx", "python", "python3", "ruby"];
const SIGNALS: &[&str] = &["-TERM", "-INT", "-15", "-2", "-SIGTERM", "-SIGINT"];
/// Words that name Guard or an agent harness, whose processes a pattern must
/// never be written to reach.
const PROTECTED: &[&str] = &["guard", "hol", "codex", "claude", "omp"];

pub(super) fn safe_pkill_arguments(arguments: &[String], context: super::PathContext<'_>) -> bool {
    let Some((pattern, options)) = arguments.split_last() else {
        return false;
    };
    let full = options.iter().filter(|option| *option == "-f").count();
    let signals = options
        .iter()
        .filter(|option| SIGNALS.contains(&option.as_str()))
        .count();
    full == 1
        && signals <= 1
        && full + signals == options.len()
        && workspace_launch(pattern, context)
}

/// `<interpreter> <script>`, with the script an existing file below the
/// working directory, named by a plain relative path.
fn workspace_launch(pattern: &str, context: super::PathContext<'_>) -> bool {
    let words: Vec<&str> = pattern.split(' ').collect();
    let [interpreter, script] = words.as_slice() else {
        return false;
    };
    let plain =
        |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'/' | b'-');
    if !INTERPRETERS.contains(interpreter)
        || script.is_empty()
        || script.len() > 255
        || !script.bytes().all(plain)
        || script.starts_with(['/', '-', '.'])
        || script
            .split('/')
            .any(|part| part.is_empty() || part == "..")
        || script
            .split(['/', '.', '_', '-'])
            .any(|token| PROTECTED.contains(&token.to_ascii_lowercase().as_str()))
    {
        return false;
    }
    let Some(cwd) = context.cwd.and_then(|cwd| std::fs::canonicalize(cwd).ok()) else {
        return false;
    };
    std::fs::canonicalize(cwd.join(Path::new(script)))
        .is_ok_and(|path| path.starts_with(&cwd) && path.is_file())
}

#[cfg(test)]
#[path = "process_stops_tests.rs"]
mod tests;
