//! Installed plugins, read from each agent runtime's own install folders.
//!
//! Only the manifest's name, version and repository are read; a plugin is
//! matched to a listing by its repository alone, never its homepage. Walks are
//! bounded in depth and in folders visited, symlinks are not followed, and a
//! manifest larger than `MAX_MANIFEST_BYTES` is skipped.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::report::normalize_repository_url;
use crate::valid_version;

const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_DIRS_VISITED: usize = 5_000;
const MAX_INSTALLED: usize = 1_000;

/// The runtime homes to read, as resolved by Guard (for example `~/.claude`
/// or `$CLAUDE_CONFIG_DIR`). A missing home is skipped.
#[derive(Debug, Default, Clone)]
pub struct RuntimeHomes {
    pub claude: Option<PathBuf>,
    pub codex: Option<PathBuf>,
    pub gemini: Option<PathBuf>,
    pub cursor: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledPlugin {
    /// The runtime id the portal accepts: `claude-code`, `codex`, `gemini` or `cursor`.
    pub runtime: &'static str,
    pub name: Option<String>,
    pub version: Option<String>,
    /// Normalized `https://github.com/owner/repo`, or None.
    pub repository: Option<String>,
}

/// Every plugin installed under the given homes, in a stable order.
pub fn discover(homes: &RuntimeHomes) -> Vec<InstalledPlugin> {
    let mut found = Vec::new();
    if let Some(home) = &homes.claude {
        walk_manifests(
            &home.join("plugins").join("cache"),
            4,
            ".claude-plugin/plugin.json",
            "claude-code",
            false,
            &mut found,
        );
    }
    if let Some(home) = &homes.codex {
        walk_manifests(
            &home.join("plugins").join("cache"),
            4,
            ".codex-plugin/plugin.json",
            "codex",
            false,
            &mut found,
        );
    }
    if let Some(home) = &homes.cursor {
        walk_manifests(
            &home.join("plugins"),
            4,
            ".cursor-plugin/plugin.json",
            "cursor",
            false,
            &mut found,
        );
    }
    if let Some(home) = &homes.gemini {
        walk_manifests(
            &home.join("extensions"),
            1,
            "gemini-extension.json",
            "gemini",
            true,
            &mut found,
        );
    }
    found.sort_by(|a, b| {
        (a.runtime, &a.repository, &a.name, &a.version).cmp(&(
            b.runtime,
            &b.repository,
            &b.name,
            &b.version,
        ))
    });
    found.dedup();
    found.truncate(MAX_INSTALLED);
    found
}

/// Breadth-first walk of `root` to `max_depth`, reading `manifest` (a path
/// relative to each folder) wherever it exists. Hidden folders are skipped,
/// except directly under `root` when `hidden_top_level` is set: Gemini
/// installs extensions in folders whose names can start with a dot.
fn walk_manifests(
    root: &Path,
    max_depth: usize,
    manifest: &str,
    runtime: &'static str,
    hidden_top_level: bool,
    out: &mut Vec<InstalledPlugin>,
) {
    let mut queue = vec![(root.to_path_buf(), 0usize)];
    let mut visited = 0usize;
    while let Some((dir, depth)) = queue.pop() {
        visited += 1;
        if visited > MAX_DIRS_VISITED {
            return;
        }
        let Ok(meta) = fs::symlink_metadata(&dir) else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        if depth > 0 {
            if let Some(plugin) = read_manifest(&dir.join(manifest), runtime) {
                out.push(plugin);
                continue;
            }
        }
        if depth >= max_depth {
            continue;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with('.') && !(hidden_top_level && depth == 0) {
                continue;
            }
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                queue.push((entry.path(), depth + 1));
            }
        }
    }
}

fn read_manifest(path: &Path, runtime: &'static str) -> Option<InstalledPlugin> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_MANIFEST_BYTES {
        return None;
    }
    let value: Value = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    let text = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };
    let repository = match value.get("repository") {
        Some(Value::String(url)) => normalize_repository_url(url),
        Some(Value::Object(object)) => object
            .get("url")
            .and_then(Value::as_str)
            .and_then(normalize_repository_url),
        _ => None,
    };
    Some(InstalledPlugin {
        runtime,
        name: text("name")
            .filter(|name| name.len() <= 200)
            .map(str::to_owned),
        version: text("version")
            .filter(|version| valid_version(version, 64))
            .map(str::to_owned),
        repository,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, body: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    fn temp_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "guard-plugin-telemetry-{tag}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn reads_each_runtime_layout() {
        let root = temp_root("layouts");
        write(
            &root.join("claude/plugins/cache/market/pdf/1.0.0/.claude-plugin/plugin.json"),
            r#"{"name":"pdf","version":"1.0.0","repository":"https://github.com/Octo/PDF.git"}"#,
        );
        write(
            &root.join("codex/plugins/cache/market/lint/2.1.0/.codex-plugin/plugin.json"),
            r#"{"name":"lint","version":"2.1.0","repository":{"url":"git+https://github.com/octo/lint"}}"#,
        );
        write(
            &root.join("gemini/extensions/notes/gemini-extension.json"),
            r#"{"name":"notes","version":"bad version","homepage":"https://github.com/octo/notes"}"#,
        );
        let found = discover(&RuntimeHomes {
            claude: Some(root.join("claude")),
            codex: Some(root.join("codex")),
            gemini: Some(root.join("gemini")),
            cursor: Some(root.join("missing")),
        });
        let _ = fs::remove_dir_all(&root);
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].runtime, "claude-code");
        assert_eq!(
            found[0].repository.as_deref(),
            Some("https://github.com/octo/pdf")
        );
        assert_eq!(
            found[1].repository.as_deref(),
            Some("https://github.com/octo/lint")
        );
        assert_eq!(found[2].runtime, "gemini");
        assert_eq!(found[2].version, None);
        assert_eq!(
            found[2].repository, None,
            "a homepage is never a repository"
        );
    }

    #[test]
    fn reads_hidden_gemini_extension_folders() {
        let root = temp_root("gemini-hidden");
        write(
            &root.join("extensions/.notes/gemini-extension.json"),
            r#"{"name":"notes","version":"1.0.0","repository":"https://github.com/octo/notes"}"#,
        );
        write(
            &root.join("extensions/.notes/.cache/gemini-extension.json"),
            r#"{"name":"nested","version":"1.0.0"}"#,
        );
        let found = discover(&RuntimeHomes {
            gemini: Some(root.clone()),
            ..RuntimeHomes::default()
        });
        let _ = fs::remove_dir_all(&root);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name.as_deref(), Some("notes"));
    }

    #[test]
    fn skips_oversized_and_malformed_manifests() {
        let root = temp_root("bad");
        write(
            &root.join("plugins/cache/m/a/1/.codex-plugin/plugin.json"),
            "{not json",
        );
        write(
            &root.join("plugins/cache/m/b/1/.codex-plugin/plugin.json"),
            &format!(r#"{{"name":"{}"}}"#, "x".repeat(300 * 1024)),
        );
        let found = discover(&RuntimeHomes {
            codex: Some(root.clone()),
            ..RuntimeHomes::default()
        });
        let _ = fs::remove_dir_all(&root);
        assert!(found.is_empty());
    }
}
