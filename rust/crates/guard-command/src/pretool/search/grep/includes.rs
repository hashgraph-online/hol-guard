//! `--include` globs the name screen cannot clear, held for a scope proof.
//!
//! A wildcard such as `*.md` names no file the screen can read, and refusing
//! it there kept a review for `grep -rn TODO --include '*.md' docs`, which
//! opens nothing but Markdown. An include can only narrow what `grep` opens,
//! so the files it selects below the searched directory decide the reading.

use super::{unsafe_search_value, ReadContext, SearchValueRole};

/// Takes an `--include` value off the name screen and holds the globs it
/// refuses in `held`. False for every other option value, which its caller
/// screens as before.
pub(super) fn held(
    role: SearchValueRole,
    value: &str,
    context: ReadContext<'_>,
    held: &mut Vec<String>,
) -> bool {
    if !matches!(role, SearchValueRole::Glob) {
        return false;
    }
    if unsafe_search_value(role, value, context) {
        held.push(value.to_owned());
    }
    true
}

/// True while every held glob selects no sensitive file below the operands.
///
/// With no operand there is no tree for a glob to select from: `grep` reads
/// stdin, and a recursive search with no root is refused by the walk its
/// caller runs whatever the include says.
pub(super) fn scope_proven(held: &[String], targets: &[&str], context: ReadContext<'_>) -> bool {
    if held.is_empty() || targets.is_empty() {
        return true;
    }
    let globs: Vec<&str> = held.iter().map(String::as_str).collect();
    crate::pretool::search_scope::grep_include_scope_proven(
        targets,
        &globs,
        context.home_dir,
        context.cwd,
    )
}
