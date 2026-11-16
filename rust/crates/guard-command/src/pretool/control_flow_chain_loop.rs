//! A `for` loop written as one item of a longer command list, as in
//! `gh pr list --limit 5; for n in 1 2; do gh pr view $n; done`.
//!
//! `for_loop_unroll` reads a command that is one loop on its own. Here each
//! loop over literal words is written out in its place, so the list above
//! becomes `gh pr list --limit 5; gh pr view 1; gh pr view 2`. The loop runs
//! its body once per word every time it runs, so the written-out list is the
//! same work, and each command in it still faces the ordinary proofs. The
//! rules about where a loop may stand and what it may hold live in
//! `for_loop_unroll::unroll_in_list`; anything else returns `None` and keeps
//! the existing review.
//!
//! The written-out list may grow to the longest command Guard parses, the
//! same limit a loop standing alone gets, so moving a long loop after another
//! step does not change its verdict.

use super::super::for_loop_unroll::unroll_in_list;
use super::next_construct;

const MAX_SPLICED_BYTES: usize = crate::MAX_COMMAND_BYTES;

/// The command list with each top-level `for` loop written out, or `None`
/// when the command holds no such loop or anything around one is outside the
/// plain list grammar.
pub(super) fn spliced_loops(command: &str, home_dir: Option<&str>) -> Option<String> {
    if command
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return None;
    }
    let mut rest = command.trim();
    let mut out = String::new();
    let mut spliced_any = false;
    while let Some(start) = next_construct(rest, "for")? {
        let (before, construct) = rest.split_at(start);
        let joined = before.trim_end();
        let gated = joined.ends_with("&&") || joined.ends_with("||");
        let (unrolled, tail) = unroll_in_list(construct, home_dir, gated)?;
        out.push_str(before);
        out.push_str(&unrolled);
        if !tail.is_empty() {
            out.push(' ');
        }
        if out.len() > MAX_SPLICED_BYTES {
            return None;
        }
        spliced_any = true;
        rest = tail;
    }
    out.push_str(rest);
    (spliced_any && out.len() <= MAX_SPLICED_BYTES).then_some(out)
}
