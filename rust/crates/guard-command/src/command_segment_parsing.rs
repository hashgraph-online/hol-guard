//! Shared token helpers for canonical command segments
//! (`runtime/command_segment_parsing.py`, 24 lines — verbatim).

use crate::command_structure::CommandRedirect;
use crate::command_tokens::shell_tokens;

/// `shell_tokens_without_redirects` (:9-24). `source_offset` is a char offset.
pub fn shell_tokens_without_redirects(
    command: &str,
    source_offset: usize,
    redirects: &[CommandRedirect],
) -> Vec<String> {
    let mut masked: Vec<char> = command.chars().collect();
    for redirect in redirects {
        let Some(local_start) = redirect.start.checked_sub(source_offset) else {
            continue;
        };
        let Some(local_end) = redirect.end.checked_sub(source_offset) else {
            continue;
        };
        if local_start > local_end || local_end > masked.len() {
            continue;
        }
        for slot in masked[local_start..local_end].iter_mut() {
            *slot = ' ';
        }
    }
    shell_tokens(&masked.iter().collect::<String>()).0
}
