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
        let local_start = redirect.start as isize - source_offset as isize;
        let local_end = redirect.end as isize - source_offset as isize;
        if local_start < 0 || local_end > masked.len() as isize {
            continue;
        }
        for slot in masked[local_start as usize..local_end as usize].iter_mut() {
            *slot = ' ';
        }
    }
    shell_tokens(&masked.iter().collect::<String>()).0
}
