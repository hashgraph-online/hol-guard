//! Keep the policy generation lock in the process that writes the approval.

use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use guard_contracts::HOOK_AUTHORITY_STATE_MAX_BYTES;

use crate::hook_authority_state_op::{save_locked_question, QuestionWrite};
use crate::policy_integrity_generation::lock::{acquire, LOCK_TIMEOUT};
use crate::{claude_hook_bridge, claude_session_start};

pub(crate) const FEATURE: &str = "claude-question-save-locked-v2";
const INVALID: &str = "native_claude_question_save_invalid";
const TIMED_OUT: &str = "native_claude_question_save_expired";
const PIPE: &str = "native_claude_question_save_pipe";

pub(super) fn route(args: &[String]) -> Option<Result<(), String>> {
    match args {
        [command, mode, marker, config]
            if command == "claude-hook-bridge"
                && mode == claude_session_start::SESSION_START_MODE
                && marker == claude_session_start::SESSION_START_MARKER =>
        {
            std::process::exit(claude_session_start::run(config))
        }
        [command, marker, config]
            if command == "claude-hook-bridge" && marker == claude_hook_bridge::BRIDGE_MARKER =>
        {
            Some(claude_hook_bridge::run(config))
        }
        [command, home, milliseconds] if command == "claude-question-save" => {
            Some(run(home, milliseconds))
        }
        _ => None,
    }
}

fn run(home: &str, milliseconds: &str) -> Result<(), String> {
    let home = Path::new(home);
    if !home.is_absolute() {
        return Err(INVALID.to_owned());
    }
    let wait = Duration::from_millis(milliseconds.parse().map_err(|_| INVALID)?).min(LOCK_TIMEOUT);
    let expires = Instant::now().checked_add(wait).ok_or(INVALID)?;
    let _lock = acquire(home, wait).ok_or(TIMED_OUT)?;
    if Instant::now() >= expires {
        return Err(TIMED_OUT.to_owned());
    }
    let mut output = io::stdout().lock();
    output
        .write_all(b"locked\n")
        .and_then(|_| output.flush())
        .map_err(|_| PIPE)?;

    // The host prepares the secret-store generation only after this handshake.
    let limit = HOOK_AUTHORITY_STATE_MAX_BYTES * 2;
    let mut input = Vec::new();
    let mut stdin = io::stdin().lock();
    stdin
        .by_ref()
        .take((limit + 1) as u64)
        .read_until(b'\n', &mut input)
        .map_err(|_| PIPE)?;
    if input.len() > limit || input.pop() != Some(b'\n') {
        return Err(INVALID.to_owned());
    }
    let request: QuestionWrite =
        crate::strict_json::from_value(crate::strict_json::parse(&input)?).map_err(|_| INVALID)?;
    let remaining = expires.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(TIMED_OUT.to_owned());
    }
    let answer = save_locked_question(home, request, remaining)?;
    serde_json::to_writer(&mut output, &answer).map_err(|_| PIPE)?;
    output
        .write_all(b"\n")
        .and_then(|_| output.flush())
        .map_err(|_| PIPE)?;
    // Hold the lock through secret-store finalization. EOF also releases it
    // if the host exits before it can finish.
    if stdin.read(&mut [0]).map_err(|_| PIPE)? != 0 {
        return Err(INVALID.to_owned());
    }
    Ok(())
}
