//! The `--include` globs a line carries, held for the proofs they decide.
//!
//! A wildcard such as `*.md` names no file the screen can read, and refusing
//! it there kept a review for `grep -rn TODO --include '*.md' docs`, which
//! opens nothing but Markdown. An include can only narrow what `grep` opens,
//! so the files the globs select below the searched directory decide both
//! readings: whether a glob the screen refused reaches a secret, and whether
//! the recursive walk reads anything the globs never select.

use super::{unsafe_search_value, ReadContext, SearchValueRole};

/// The include globs, split by what the name screen made of them.
#[derive(Default)]
pub(super) struct Includes {
    /// Every glob, in the order the line gives them. Together they are the
    /// whole of what `grep` opens below a root, so a narrowing proof needs
    /// all of them -- a glob the screen cleared still selects files.
    all: Vec<String>,
    /// The globs the screen refuses, which need a scope proof of their own.
    unscreened: Vec<String>,
}

impl Includes {
    /// Takes an `--include` value off the name screen, recording it. False
    /// for every other option value, which its caller screens as before.
    pub(super) fn held(
        &mut self,
        role: SearchValueRole,
        value: &str,
        context: ReadContext<'_>,
    ) -> bool {
        if !matches!(role, SearchValueRole::Glob) {
            return false;
        }
        if unsafe_search_value(role, value, context) {
            self.unscreened.push(value.to_owned());
        }
        self.all.push(value.to_owned());
        true
    }

    /// True while every glob the screen refused selects no sensitive file
    /// below the operands.
    ///
    /// With no operand there is no tree for a glob to select from: `grep`
    /// reads stdin, and a recursive search with no root is refused by the
    /// walk its caller runs whatever the include says.
    pub(super) fn scope_proven(&self, targets: &[&str], context: ReadContext<'_>) -> bool {
        if self.unscreened.is_empty() || targets.is_empty() {
            return true;
        }
        let globs: Vec<&str> = self.unscreened.iter().map(String::as_str).collect();
        crate::pretool::search_scope::grep_include_scope_proven(
            targets,
            &globs,
            context.home_dir,
            context.cwd,
        )
    }

    /// True when the includes narrow the recursive walk of `target` to files
    /// that hold nothing sensitive.
    ///
    /// The walk below a root is otherwise refused by any secret it reaches,
    /// which is the right reading for `grep -rn KEY docs` but not for
    /// `grep -rn KEY --include '*.md' docs`: the globs are the only files
    /// that search opens, and a file it never selects cannot be printed.
    pub(super) fn narrows(&self, target: &str, context: ReadContext<'_>) -> bool {
        if self.all.is_empty() {
            return false;
        }
        let globs: Vec<&str> = self.all.iter().map(String::as_str).collect();
        crate::pretool::search_scope::grep_include_walk_proven(
            target,
            &globs,
            context.home_dir,
            context.cwd,
        )
    }
}
