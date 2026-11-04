//! What Claude Code recorded about its plugins and marketplaces, and the
//! commit a marketplace checkout is at.
//!
//! `plugin install` and `plugin verify` hold these against what HOL scanned.
//! Everything is read from Claude Code's own files under its config folder
//! and from the checkout's `.git` files; no command runs. A record that is
//! missing reads as empty, but one that exists and cannot be read is reported
//! as unreadable, so a caller never mistakes it for "nothing installed".

use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

const INSTALLED: &str = "installed_plugins.json";
const MARKETPLACES: &str = "known_marketplaces.json";
const GITHUB: &str = "https://github.com/";

/// Claude Code's record of installed plugins: `None` when it exists but
/// cannot be read, empty when it does not exist yet.
fn installed_plugins(home: &Path) -> Option<Map<String, Value>> {
    let bytes = match fs::read(home.join("plugins").join(INSTALLED)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Some(Map::new()),
        Err(_) => return None,
    };
    let text = String::from_utf8(bytes).ok()?;
    match serde_json::from_str::<Value>(&text).ok()? {
        Value::Object(mut data) => match data.remove("plugins") {
            None => Some(Map::new()),
            Some(Value::Object(plugins)) => Some(plugins),
            Some(_) => None,
        },
        _ => None,
    }
}

/// A JSON file's value, or `None` for anything that cannot be read or parsed.
fn read_json(path: &Path) -> Option<Value> {
    let text = String::from_utf8(fs::read(path).ok()?).ok()?;
    serde_json::from_str(&text).ok()
}

fn text(value: Option<&Value>) -> Value {
    value
        .and_then(Value::as_str)
        .map_or(Value::Null, |text| Value::String(text.to_owned()))
}

fn entries<'a>(
    plugins: &'a Map<String, Value>,
    id: &str,
) -> impl Iterator<Item = &'a Map<String, Value>> {
    plugins
        .get(id)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
}

fn user_scope(entry: &Map<String, Value>) -> bool {
    entry.get("scope").and_then(Value::as_str) == Some("user")
}

/// The GitHub `owner/repo` a marketplace URL names, lowercased, or `""` for
/// any other URL.
fn github_repository(url: &str) -> String {
    let Some(rest) = url.strip_prefix(GITHUB) else {
        return String::new();
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let Some((owner, repo)) = rest.split_once('/') else {
        return String::new();
    };
    let repo = match repo.strip_suffix(".git") {
        Some(stripped) if !stripped.is_empty() => stripped,
        _ => repo,
    };
    if owner.is_empty() || repo.is_empty() || repo.contains('/') {
        return String::new();
    }
    format!("{owner}/{repo}").to_lowercase()
}

/// The repository a known marketplace comes from: its GitHub `owner/repo`,
/// or `""` for any other source.
fn marketplace_source(entry: &Map<String, Value>) -> String {
    let Some(source) = entry.get("source").and_then(Value::as_object) else {
        return String::new();
    };
    if let Some(repo) = source.get("repo").and_then(Value::as_str) {
        return repo.to_lowercase();
    }
    source
        .get("url")
        .and_then(Value::as_str)
        .map(github_repository)
        .unwrap_or_default()
}

/// The install command the marketplace checkout declares for the plugin.
fn checkout_command(root: &Path, plugin_id: &str) -> Value {
    let catalog = read_json(&root.join(".claude-plugin").join("marketplace.json"));
    let name = plugin_id
        .rsplit_once('@')
        .map_or(plugin_id, |(name, _)| name);
    let plugins = catalog
        .as_ref()
        .and_then(|catalog| catalog.get("plugins"))
        .and_then(Value::as_array);
    for plugin in plugins.into_iter().flatten().filter_map(Value::as_object) {
        if plugin.get("name").and_then(Value::as_str) != Some(name) {
            continue;
        }
        let source = plugin.get("source").and_then(Value::as_object);
        if let Some(source) =
            source.filter(|source| source.get("source").and_then(Value::as_str) == Some("command"))
        {
            return text(source.get("command"));
        }
    }
    Value::Null
}

fn marketplace(home: &Path, name: &str, plugin_id: Option<&str>) -> Value {
    let known = read_json(&home.join("plugins").join(MARKETPLACES));
    let Some(entry) = known
        .as_ref()
        .and_then(|known| known.get(name))
        .and_then(Value::as_object)
    else {
        return Value::Null;
    };
    let root = entry
        .get("installLocation")
        .and_then(Value::as_str)
        .map(Path::new)
        .filter(|root| root.is_absolute());
    let head = root
        .and_then(head_commit)
        .map_or(Value::Null, Value::String);
    let command = match (root, plugin_id) {
        (Some(root), Some(plugin_id)) => checkout_command(root, plugin_id),
        _ => Value::Null,
    };
    json!({"source": marketplace_source(entry), "head": head, "command": command})
}

/// Claude Code's state for one install: the plugins its record lists, the
/// user's entry for `plugin_id` and the known marketplace named `marketplace`.
pub fn state(
    home: &str,
    plugin_id: Option<&str>,
    marketplace_name: Option<&str>,
) -> Result<Value, String> {
    let home = Path::new(home);
    if !home.is_absolute() {
        return Err("plugin_kit_claude_home_invalid".to_owned());
    }
    let marketplace =
        marketplace_name.map_or(Value::Null, |name| self::marketplace(home, name, plugin_id));
    let Some(plugins) = installed_plugins(home) else {
        return Ok(
            json!({"record": "unreadable", "user_plugins": null, "plugins": null, "entry": null, "marketplace": marketplace}),
        );
    };
    let mut user = BTreeSet::new();
    let mut any = BTreeSet::new();
    for id in plugins.keys() {
        let mut listed = entries(&plugins, id).peekable();
        if listed.peek().is_some() {
            any.insert(id.clone());
        }
        if listed.any(user_scope) {
            user.insert(id.clone());
        }
    }
    let entry = plugin_id
        .and_then(|id| entries(&plugins, id).find(|entry| user_scope(entry)))
        .map_or(Value::Null, |entry| {
            json!({
                "commit": text(entry.get("gitCommitSha")),
                "version": text(entry.get("version")),
                "source_command": text(entry.get("sourceCommand")),
            })
        });
    Ok(
        json!({"record": "read", "user_plugins": user, "plugins": any, "entry": entry, "marketplace": marketplace}),
    )
}

fn is_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Python's `str.strip()`: Unicode whitespace and the four separator controls.
fn strip(value: &str) -> &str {
    value.trim_matches(|c: char| c.is_whitespace() || ('\x1c'..='\x1f').contains(&c))
}

fn read_text(path: &Path) -> Option<String> {
    String::from_utf8(fs::read(path).ok()?).ok()
}

/// The commit a checkout is at, read from its `.git` files without running
/// git: a detached `HEAD`, or the branch it names as a loose or packed ref.
pub fn head_commit(root: &Path) -> Option<String> {
    let mut git: PathBuf = root.join(".git");
    if git.is_file() {
        let pointer = read_text(&git)?;
        let target = strip(&pointer).strip_prefix("gitdir:")?;
        git = fs::canonicalize(root.join(strip(target))).ok()?;
    }
    let head = read_text(&git.join("HEAD"))?;
    let head = strip(&head);
    if is_commit(head) {
        return Some(head.to_owned());
    }
    if !head.starts_with("ref: refs/") || head.contains("..") {
        return None;
    }
    let reference = &head["ref: ".len()..];
    let loose = git.join(reference);
    if loose.is_file() {
        let commit = read_text(&loose)?;
        let commit = strip(&commit);
        return is_commit(commit).then(|| commit.to_owned());
    }
    let packed = read_text(&git.join("packed-refs"))?;
    packed
        .split(|c: char| {
            matches!(
                c,
                '\n' | '\r'
                    | '\x0b'
                    | '\x0c'
                    | '\x1c'
                    | '\x1d'
                    | '\x1e'
                    | '\u{85}'
                    | '\u{2028}'
                    | '\u{2029}'
            )
        })
        .filter_map(|line| line.split_once(' '))
        .find(|(commit, name)| *name == reference && is_commit(commit))
        .map(|(commit, _)| commit.to_owned())
}

/// `{"commit": ...}` for an absolute checkout path; anything else has none.
pub fn git_head(root: &str) -> Value {
    let root = Path::new(root);
    let commit = if root.is_absolute() {
        head_commit(root)
    } else {
        None
    };
    json!({ "commit": commit })
}
