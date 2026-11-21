//! Keep the policy generation lock in the process that writes the approval.

use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use guard_contracts::HOOK_AUTHORITY_STATE_MAX_BYTES;

use crate::hook_authority_state_op::{save_locked_question, QuestionWrite};
use crate::policy_generation_lock::{acquire, LOCK_TIMEOUT};

pub(crate) const COMMAND: &str = "claude-question-save";
pub(crate) const FEATURE: &str = "claude-question-save-locked-v1";
const INVALID: &str = "native_claude_question_save_invalid";
const TIMED_OUT: &str = "native_claude_question_save_expired";
const PIPE: &str = "native_claude_question_save_pipe";

pub(crate) fn run(home: &str, milliseconds: &str) -> Result<(), String> {
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
    // A closed pipe means it abandoned the save. Keep the lock until it
    // finishes preparation and sends the request, or closes the pipe.
    let limit = HOOK_AUTHORITY_STATE_MAX_BYTES * 2;
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take((limit + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| PIPE)?;
    if input.len() > limit {
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
    output.flush().map_err(|_| PIPE)?;
    Ok(())
}
