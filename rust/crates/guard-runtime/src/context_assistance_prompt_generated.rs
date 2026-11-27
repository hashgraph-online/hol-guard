//! Turns the app writes itself, not the person or agent at the keyboard.
//!
//! Claude Code sends some of its own messages through the prompt hook: a
//! background task finishing, a stop hook's feedback, a goal check-in, a
//! reminder block, and the summary that continues a compacted session. None
//! of them asks for code. In real sessions the agent opened a file from a note
//! on these turns about once in a hundred, and every note stays in the
//! conversation, sent again with each later request. CIGAR leaves them alone.
//!
//! Two more kinds read like a person's turn but are not one. A command run in
//! Claude Code's shell mode (`!`) comes back as its input and output, and no
//! model reads that turn, so a note on it is only paid for later. A CI
//! watcher's event wraps GitHub text other people wrote in the watcher's own
//! fixed wording, so a note on it was ranked on that wording.

/// How each of those messages starts.
const OPENINGS: [&str; 9] = [
    "<task-notification>",
    "<system-reminder>",
    "Stop hook feedback:",
    "Goal check-in:",
    "This session is being continued from a previous conversation",
    "<bash-input>",
    "<bash-stdout>",
    "<bash-stderr>",
    "<ci-monitor-event>",
];

/// Whether the app, not a person or agent, wrote this prompt.
pub(crate) fn by_app(prompt: &str) -> bool {
    let start = prompt.trim_start();
    OPENINGS.iter().any(|opening| start.starts_with(opening))
}

#[cfg(test)]
#[path = "context_assistance_prompt_generated_tests.rs"]
mod tests;
