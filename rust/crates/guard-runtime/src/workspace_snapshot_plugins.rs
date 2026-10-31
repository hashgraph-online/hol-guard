//! Agent plugins a project ships, checked over the bytes a workspace snapshot
//! hashed.
//!
//! A Claude Code or Codex plugin (`.claude-plugin/plugin.json`,
//! `.codex-plugin/plugin.json`) or a Gemini CLI extension
//! (`gemini-extension.json`) can sit at any depth of a worktree, as in a
//! plugin marketplace repository. Once a developer installs it, its hooks run
//! on their own at session start or around each tool call, and its MCP
//! servers start with the agent. Every hook command runs the shared
//! `hook_config_risk` rules and every MCP server the shared `mcp_config_risk`
//! rules. A finding carries the rule's fixed wording, the root-relative path
//! of the file that holds the hook or server, and the hook event or server
//! name, never the command, its arguments or a URL.
//!
//! A plugin's hooks are its manifest's inline `hooks`, the files that field
//! names and `hooks/hooks.json` at the plugin root. Its MCP servers are the
//! manifest's inline `mcpServers`, the files that field names and `.mcp.json`
//! at the plugin root. A `.mcp.json` at the worktree root is the project MCP
//! configuration the MCP check already reads, so it is left to that check.
//!
//! A manifest or referenced file the scan could not read in full leaves it
//! incomplete, as does a reference that leaves the plugin root, a reference
//! to a file the scan does not keep (anything but a `hooks/*.json` or a
//! `.mcp.json`) or to one on disk the walk did not reach (under a skipped
//! directory such as `dist`, or through a linked directory), or a link or
//! special file where a plugin could be. Plugins listed inline in a
//! marketplace file are not read.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::skills::walked;

#[path = "workspace_snapshot_plugin_checks.rs"]
mod checks;

use checks::Run;

pub(super) const RESULT_SCHEMA: &str = "guard.workspace-plugins.v1";
/// Moves whenever the files read or a rule set changes, so a stored result
/// names what produced it.
pub(super) const DETECTOR_VERSION: &str = "plugin-manifest-v1";
pub(super) const MAX_PLUGIN_FINDINGS: usize = 200;
/// Larger than any hand-written manifest or plugin configuration.
const MAX_FILE_BYTES: usize = 1024 * 1024;
/// Plugin configuration files kept from one walk. Manifests have their own
/// budget, so unrelated `.mcp.json` and `hooks/*.json` files met earlier in
/// the walk cannot crowd out a plugin.
const MAX_KEPT_FILES: usize = 512;
const MAX_KEPT_BYTES: usize = 8 * 1024 * 1024;
const MAX_PLUGINS: usize = 256;
const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MANIFEST_DIRECTORIES: [&str; 2] = [".claude-plugin", ".codex-plugin"];
const MANIFEST_FILE: &str = "plugin.json";
const EXTENSION_FILE: &str = "gemini-extension.json";
const HOOKS_DIRECTORY: &str = "hooks";
const DEFAULT_HOOKS: &str = "hooks/hooks.json";
const MCP_FILE: &str = ".mcp.json";

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Hook,
    McpServer,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Hook => "hook",
            Kind::McpServer => "mcp_server",
        }
    }
}

/// A manifest or plugin configuration file as the walk left it.
enum Kept {
    Text(String),
    Oversize,
    NotText,
    Unread,
}

/// The files and bytes one class of kept file has taken.
#[derive(Default)]
struct Budget {
    files: usize,
    bytes: usize,
    hit: bool,
}

#[derive(Default)]
pub(super) struct PluginScan {
    worktree_key: String,
    /// The worktree root as requested and as resolved, for link targets.
    roots: Vec<PathBuf>,
    kept: BTreeMap<String, Kept>,
    manifests: Budget,
    files: Budget,
    linked: usize,
    path_too_long: bool,
}

impl PluginScan {
    pub(super) fn new(worktree_key: &str, roots: &[&Path]) -> Self {
        Self {
            worktree_key: worktree_key.to_owned(),
            roots: roots.iter().map(|root| root.to_path_buf()).collect(),
            ..Self::default()
        }
    }

    /// Whether `relative` is a manifest or plugin configuration file this
    /// scan must keep.
    pub(super) fn admits(&mut self, relative: &str) -> bool {
        if !is_kept(relative) {
            return false;
        }
        if relative.len() > super::secrets::MAX_PATH_BYTES {
            self.path_too_long = true;
            return false;
        }
        true
    }

    /// The snapshot left an admitted file unread (oversize, byte budget,
    /// unreadable or unstable).
    pub(super) fn left_unread(&mut self, relative: &str) {
        self.keep(relative, Kept::Unread);
    }

    /// The snapshot did not follow a special file at `relative`.
    pub(super) fn left_special(&mut self, relative: &str) {
        if may_hold_plugin(relative) {
            self.linked += 1;
        }
    }

    /// The snapshot did not follow the symlink at `relative` to `target`.
    /// Plugins nest at any depth, so a link the walk cannot see through could
    /// hide one too.
    pub(super) fn left_link(&mut self, relative: &str, target: Option<&Path>) {
        if may_hold_plugin(relative)
            || !target.is_some_and(|target| walked(&self.roots, relative, target))
        {
            self.linked += 1;
        }
    }

    /// Keep the exact bytes hashed for `relative` until the walk ends, when
    /// every plugin's manifest and the files it names are known.
    pub(super) fn observe(&mut self, relative: &str, content: &[u8]) {
        let (budget, _, max_bytes) = self.budget(relative);
        let kept = if content.len() > MAX_FILE_BYTES {
            Kept::Oversize
        } else if budget.bytes + content.len() > max_bytes {
            Kept::Unread
        } else {
            match std::str::from_utf8(content) {
                Ok(text) => Kept::Text(text.to_owned()),
                Err(_) => Kept::NotText,
            }
        };
        let text = matches!(kept, Kept::Text(_));
        if self.keep(relative, kept) && text {
            self.budget(relative).0.bytes += content.len();
        }
    }

    fn keep(&mut self, relative: &str, kept: Kept) -> bool {
        let (budget, max_files, _) = self.budget(relative);
        if budget.files >= max_files {
            budget.hit = true;
            return false;
        }
        budget.files += 1;
        self.kept.insert(relative.to_owned(), kept);
        true
    }

    fn budget(&mut self, relative: &str) -> (&mut Budget, usize, usize) {
        if plugin_root(relative).is_some() {
            (&mut self.manifests, MAX_PLUGINS, MAX_MANIFEST_BYTES)
        } else {
            (&mut self.files, MAX_KEPT_FILES, MAX_KEPT_BYTES)
        }
    }

    /// Whether `relative` is on disk though the walk did not keep it.
    fn present(&self, relative: &str) -> bool {
        self.roots
            .first()
            .is_some_and(|root| root.join(relative).symlink_metadata().is_ok())
    }

    /// `incomplete_reasons` names the snapshot limits that may have hidden a
    /// plugin from the walk; the scan is incomplete under any of them.
    pub(super) fn report(&self, incomplete_reasons: &[&str]) -> Value {
        let mut run = Run::new(
            &self.worktree_key,
            incomplete_reasons.iter().copied().collect(),
        );
        for (hit, reason) in [
            (self.manifests.hit, "max_plugins"),
            (self.files.hit, "plugin_file_cap"),
            (self.linked > 0, "plugin_linked"),
            (self.path_too_long, "path_too_long"),
        ] {
            if hit {
                run.truncation.insert(reason);
            }
        }
        let mut checked: BTreeSet<(String, Kind)> = BTreeSet::new();
        for (path, kept) in &self.kept {
            let Some(root) = plugin_root(path) else {
                continue;
            };
            let Some(manifest) = run.document(kept) else {
                continue;
            };
            run.plugins_scanned += 1;
            let mut targets = vec![(join(root, DEFAULT_HOOKS), Kind::Hook, false)];
            if !root.is_empty() {
                targets.push((join(root, MCP_FILE), Kind::McpServer, false));
            }
            for (field, kind) in [("hooks", Kind::Hook), ("mcpServers", Kind::McpServer)] {
                let references = match manifest.get(field) {
                    Some(inline @ Value::Object(_)) => {
                        run.check(path, kind, inline);
                        continue;
                    }
                    Some(Value::String(reference)) => vec![reference.as_str()],
                    Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
                    _ => continue,
                };
                for reference in references {
                    match resolve(root, reference) {
                        Some(target) => targets.push((target, kind, true)),
                        None => {
                            run.truncation.insert("plugin_reference_outside");
                        }
                    }
                }
            }
            for (target, kind, named) in targets {
                // The worktree's own `.mcp.json` belongs to the MCP check.
                if target == MCP_FILE || !checked.insert((target.clone(), kind)) {
                    continue;
                }
                match self.kept.get(&target) {
                    Some(kept) => {
                        if let Some(document) = run.document(kept) {
                            run.check(&target, kind, &document);
                        }
                    }
                    None if named && (!is_kept(&target) || self.present(&target)) => {
                        run.truncation.insert("plugin_reference_unread");
                    }
                    None => {}
                }
            }
        }
        run.into_value()
    }
}

/// The plugin root a manifest at `path` describes, or `None` when `path` is
/// not a manifest.
fn plugin_root(path: &str) -> Option<&str> {
    if let Some(directory) = path.strip_suffix(EXTENSION_FILE) {
        return (directory.is_empty() || directory.ends_with('/'))
            .then(|| directory.trim_end_matches('/'));
    }
    let directory = path.strip_suffix(MANIFEST_FILE)?.strip_suffix('/')?;
    let (root, name) = directory.rsplit_once('/').unwrap_or(("", directory));
    MANIFEST_DIRECTORIES.contains(&name).then_some(root)
}

/// Manifests, every `.mcp.json` below the worktree root and every JSON file
/// directly in a `hooks` directory: the files a plugin can hold hooks or MCP
/// servers in by default.
fn is_kept(path: &str) -> bool {
    plugin_root(path).is_some()
        || path.rsplit_once('/').is_some_and(|(directory, name)| {
            name == MCP_FILE
                || (name.ends_with(".json")
                    && (directory == HOOKS_DIRECTORY
                        || directory.ends_with(&format!("/{HOOKS_DIRECTORY}"))))
        })
}

/// Whether a link or special file at `relative` could stand in for a
/// manifest, a plugin configuration file or a directory that holds one.
fn may_hold_plugin(relative: &str) -> bool {
    let name = relative.rsplit('/').next().unwrap_or(relative);
    is_kept(relative) || MANIFEST_DIRECTORIES.contains(&name) || name == HOOKS_DIRECTORY
}

fn join(root: &str, relative: &str) -> String {
    if root.is_empty() {
        relative.to_owned()
    } else {
        format!("{root}/{relative}")
    }
}

/// The root-relative path a manifest reference names, or `None` when it is
/// absolute or leaves the plugin root.
fn resolve(root: &str, reference: &str) -> Option<String> {
    if reference.starts_with('/') || reference.contains('\\') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in reference.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            part => parts.push(part),
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(join(root, &parts.join("/")))
}
