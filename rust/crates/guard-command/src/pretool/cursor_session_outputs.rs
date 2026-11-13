//! Cursor saves the output of the shells it runs and of tool calls too large
//! to return inline under `~/.cursor/projects/<workspace slug>/terminals/`
//! and `.../agent-tools/`, then tells the agent to read the file back. Agents
//! often do that from the shell (`jq '.checks' <file>`, `grep -n FAIL
//! <file>`), and a review there stalls the session on output Cursor just
//! showed it.
//!
//! While a Cursor call is evaluated, a shell read of one of those `.txt`
//! files is admitted for the project directory named after the session's own
//! workspace. Every other harness keeps its review: the files echo command
//! output, which can hold secrets, and only Cursor has already seen it.

use std::cell::RefCell;
use std::path::{Component, Path};

thread_local! {
    /// The project directory names of the session's own workspace while a
    /// Cursor call is evaluated, `None` otherwise.
    static SESSION: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
}

/// Marks the evaluation on this thread as a Cursor call for the workspace
/// `cwd` until the guard drops. The workspace is fixed here, from the
/// session's directory, so a `cd` inside the command cannot name another
/// workspace's directory as its own. A nested scope restores the outer one.
pub(in crate::pretool) fn scope(harness: &str, cwd: Option<&str>) -> Scope {
    let slugs = (harness == "cursor")
        .then(|| super::generic::cursor_project_reads::workspace_slugs(cwd))
        .filter(|slugs| !slugs.is_empty());
    Scope(SESSION.with(|session| session.replace(slugs)))
}

#[must_use]
pub(in crate::pretool) struct Scope(Option<Vec<String>>);

impl Drop for Scope {
    fn drop(&mut self) {
        let outer = self.0.take();
        let _ = SESSION.try_with(|session| session.replace(outer));
    }
}

/// Whether `canonical`, a resolved regular file, is shell or tool output that
/// Cursor saved for the session's own workspace, read during a Cursor call.
pub(in crate::pretool) fn own_output(canonical: &Path, home_dir: Option<&str>) -> bool {
    let Some(own) = SESSION.with(|session| session.borrow().clone()) else {
        return false;
    };
    if !canonical.is_file() {
        return false;
    }
    let Some(home) = home_dir.and_then(|home| std::fs::canonicalize(home).ok()) else {
        return false;
    };
    // A linked `~/.cursor` or `projects` could dress another tree as
    // Cursor's own, so both must resolve to themselves.
    let projects = home.join(".cursor").join("projects");
    if [home.join(".cursor"), projects.clone()]
        .iter()
        .any(|root| std::fs::canonicalize(root).ok().as_ref() != Some(root))
    {
        return false;
    }
    let Ok(relative) = canonical.strip_prefix(&projects) else {
        return false;
    };
    let parts = relative
        .components()
        .map(|component| match component {
            Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>();
    let Some([slug, "terminals" | "agent-tools", leaf]) = parts.as_deref() else {
        return false;
    };
    !leaf.starts_with('.') && leaf.ends_with(".txt") && own.iter().any(|own| own == slug)
}
