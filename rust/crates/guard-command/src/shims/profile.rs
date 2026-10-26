//! Shell-profile PATH blocks and path-export hints.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use super::pyfs::ReadError;
use super::values::{py_is_space, py_splitlines, py_strip};
use super::{ShimContext, ShimFacts, ShimResult, GUARD_PROFILE_MARKER, PACKAGE_PROFILE_MARKER};
use crate::command_launcher_floors::shlex_quote;

/// Path fragments that mark an ephemeral shim directory; such paths must not
/// be written into a long-lived shell profile.
const TRANSIENT_PATH_FRAGMENTS: [&str; 6] = [
    "/var/folders/",
    "/private/var/folders/",
    "/tmp/",
    "/private/tmp/",
    "/temp/",
    "pytest-of-",
];

pub(crate) fn posix_path_export(shim_dir: &str) -> String {
    format!("export PATH={}:$PATH", shlex_quote(shim_dir))
}

pub(crate) fn fish_path_prepend(shim_dir: &str) -> String {
    format!("fish_add_path --prepend -- {}", shlex_quote(shim_dir))
}

/// `_path_export_hint`.
pub(crate) fn path_export_hint(facts: &ShimFacts, shim_dir: &str) -> String {
    if facts.windows {
        format!("set PATH={shim_dir};%PATH%")
    } else {
        posix_path_export(shim_dir)
    }
}

/// `_path_export_hints`.
pub(crate) fn path_export_hints(shim_dir: &str) -> Value {
    let posix_hint = posix_path_export(shim_dir);
    json!({
        "bash": posix_hint,
        "zsh": posix_hint,
        "fish": fish_path_prepend(shim_dir),
        "powershell": format!("$env:Path = \"{shim_dir};$env:Path\""),
    })
}

/// `_is_transient_path`.
pub(crate) fn is_transient_path(facts: &ShimFacts, path: &str) -> bool {
    if TRANSIENT_PATH_FRAGMENTS
        .iter()
        .any(|fragment| path.contains(fragment))
    {
        return true;
    }
    for name in ["TMPDIR", "TEMP", "TMP"] {
        let value = facts.environ.get(name).map_or("", |value| py_strip(value));
        if value.is_empty() {
            continue;
        }
        let inside = facts.resolve(path).and_then(|resolved| {
            facts
                .expanduser(value)
                .and_then(|expanded| facts.resolve(&expanded))
                .map(|root| facts.is_within(&resolved, &root))
        });
        match inside {
            Ok(true) => return true,
            Ok(false) => {}
            Err(_) => {
                if path.starts_with(value) {
                    return true;
                }
            }
        }
    }
    false
}

fn shell_name(facts: &ShimFacts) -> String {
    facts.name(facts.environ.get("SHELL").map_or("", String::as_str))
}

fn primary_target(facts: &ShimFacts, home: &str, shim_dir: &str) -> (String, String) {
    let marker = PACKAGE_PROFILE_MARKER;
    match shell_name(facts).as_str() {
        "fish" => (
            facts.join(
                &facts.join(&facts.join(home, ".config"), "fish"),
                "config.fish",
            ),
            format!("{marker}\n{}", fish_path_prepend(shim_dir)),
        ),
        "bash" => (
            facts.join(home, ".bashrc"),
            format!("{marker}\n{}", posix_path_export(shim_dir)),
        ),
        _ => (
            facts.join(home, ".zshrc"),
            format!("{marker}\n{}", posix_path_export(shim_dir)),
        ),
    }
}

/// `_bash_login_profile_path`.
fn bash_login_profile_path(facts: &ShimFacts, home: &str) -> String {
    for name in [".bash_profile", ".bash_login"] {
        let candidate = facts.join(home, name);
        if facts.exists(&candidate) {
            return candidate;
        }
    }
    facts.join(home, ".profile")
}

/// `_package_shim_profile_targets`.
pub(crate) fn profile_targets(
    facts: &ShimFacts,
    home: &str,
    shim_dir: &str,
) -> Vec<(String, String)> {
    let bash_export = format!("{PACKAGE_PROFILE_MARKER}\n{}", posix_path_export(shim_dir));
    let candidates = [
        primary_target(facts, home, shim_dir),
        (facts.join(home, ".bashrc"), bash_export.clone()),
        (bash_login_profile_path(facts, home), bash_export),
    ];
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut targets = Vec::new();
    for (path, export_line) in candidates {
        if seen.insert(path.clone()) {
            targets.push((path, export_line));
        }
    }
    targets
}

/// `_profile_already_references_path`.
fn profile_already_references_path(content: &str, shim_dir: &str) -> bool {
    let expected = [posix_path_export(shim_dir), fish_path_prepend(shim_dir)];
    py_splitlines(content)
        .iter()
        .filter(|line| !line.trim_start_matches(py_is_space).starts_with('#'))
        .any(|line| {
            expected.iter().any(|item| item == py_strip(line))
                || (line.contains(shim_dir) && line.contains("PATH"))
                || (line.contains(shim_dir) && line.contains("fish_add_path"))
        })
}

/// `_package_shim_profile_status`.
pub(crate) fn profile_status(context: &ShimContext) -> ShimResult<Map<String, Value>> {
    let facts = &context.facts;
    let shim_dir = context.shim_dir();
    let mut status = Map::new();
    let Some(home) = &context.home_dir else {
        status.insert("shell_profile_configured".into(), json!(false));
        status.insert("shell_profile_path".into(), Value::Null);
        status.insert("shell_profile_paths".into(), json!([]));
        status.insert("shell_profile_missing_paths".into(), json!([]));
        return Ok(status);
    };
    let targets = profile_targets(facts, home, &shim_dir);
    let mut configured: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for (path, _export_line) in &targets {
        let existing = if facts.exists(path) {
            match facts.read_text(path) {
                Ok(text) => text,
                Err(ReadError::Io(_)) => String::new(),
                Err(error) => return Err(error.message(path)),
            }
        } else {
            String::new()
        };
        if profile_already_references_path(&existing, &shim_dir) {
            configured.push(path.clone());
        } else {
            missing.push(path.clone());
        }
    }
    status.insert(
        "shell_profile_configured".into(),
        json!(!targets.is_empty() && missing.is_empty()),
    );
    status.insert(
        "shell_profile_path".into(),
        targets.first().map_or(Value::Null, |(path, _)| json!(path)),
    );
    status.insert("shell_profile_paths".into(), json!(configured));
    status.insert("shell_profile_missing_paths".into(), json!(missing));
    Ok(status)
}

/// `_strip_managed_marker_blocks`.
pub fn strip_managed_marker_blocks(content: &str, marker: &str) -> String {
    if content.is_empty() {
        return String::new();
    }
    let marker_stripped = py_strip(marker);
    let lines = py_splitlines(content);
    let mut drop: BTreeSet<usize> = BTreeSet::new();
    for (index, line) in lines.iter().enumerate() {
        if py_strip(line) == marker_stripped && index + 1 < lines.len() {
            drop.insert(index);
            drop.insert(index + 1);
        }
    }
    if drop.is_empty() {
        return if content.ends_with('\n') {
            content.to_owned()
        } else {
            format!("{content}\n")
        };
    }
    let mut keep: Vec<&str> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if drop.contains(&index) {
            continue;
        }
        if py_strip(line).is_empty() {
            let previous_blank = keep.last().is_some_and(|kept| py_strip(kept).is_empty());
            let previous_dropped = index > 0 && drop.contains(&(index - 1));
            let next_dropped = drop.contains(&(index + 1));
            if (previous_dropped || next_dropped) && !previous_blank {
                continue;
            }
        }
        keep.push(line);
    }
    let mut cleaned = keep.join("\n");
    if !cleaned.is_empty() && !cleaned.ends_with('\n') {
        cleaned.push('\n');
    }
    cleaned
}

/// `_managed_profile_content`.
fn managed_profile_content(existing: &str, export_line: &str, marker: &str) -> String {
    let mut export_line = export_line.trim_end_matches('\n').to_owned();
    let marker_line = export_line.split('\n').next().unwrap_or("");
    if py_strip(marker_line) != py_strip(marker) {
        export_line = format!("{marker}\n{export_line}");
    }
    let desired = format!("{export_line}\n");
    if existing == desired {
        return existing.to_owned();
    }
    let cleaned = strip_managed_marker_blocks(existing, marker);
    if cleaned.is_empty() {
        desired
    } else {
        let prefix = if cleaned.ends_with('\n') { "" } else { "\n" };
        format!("{cleaned}{prefix}{desired}")
    }
}

/// `_upsert_managed_profile_block`: whether the file changed.
fn upsert_managed_profile_block(
    facts: &ShimFacts,
    profile_path: &str,
    export_line: &str,
    marker: &str,
) -> ShimResult<bool> {
    facts.mkdir_parents(&facts.parent(profile_path))?;
    let existing = if facts.exists(profile_path) {
        facts
            .read_text(profile_path)
            .map_err(|error| error.message(profile_path))?
    } else {
        String::new()
    };
    let content = managed_profile_content(&existing, export_line, marker);
    if content == existing {
        return Ok(false);
    }
    facts.write_text(profile_path, &content)?;
    Ok(true)
}

/// `ensure_package_shim_path_in_shell_profile`.
pub fn ensure_package_shim_path_in_shell_profile(context: &ShimContext) -> ShimResult<Value> {
    let facts = &context.facts;
    let shim_dir = context.shim_dir();
    // Honor the caller's `_is_transient_path` judgment when it sent one.
    // Vector runs and any request that omits the bit still use the resident check.
    let transient = facts
        .shim_dir_transient
        .unwrap_or_else(|| is_transient_path(facts, &shim_dir));
    if facts.windows || transient {
        return Ok(json!({
            "changed": false,
            "profile_path": null,
            "shim_dir": shim_dir,
            "restart_shell_required": false,
            "manual_path_required": true,
        }));
    }
    let home = context
        .home_dir
        .as_deref()
        .ok_or_else(|| "home_dir is required to update a shell profile".to_owned())?;
    let targets = profile_targets(facts, home, &shim_dir);
    let mut changed_paths: Vec<String> = Vec::new();
    for (path, export_line) in &targets {
        if upsert_managed_profile_block(facts, path, export_line, PACKAGE_PROFILE_MARKER)? {
            changed_paths.push(path.clone());
        }
    }
    Ok(json!({
        "changed": !changed_paths.is_empty(),
        "changed_paths": changed_paths,
        "profile_path": targets.first().map(|(path, _)| path.clone()),
        "profile_paths": targets.iter().map(|(path, _)| path.clone()).collect::<Vec<_>>(),
        "shim_dir": shim_dir,
        "restart_shell_required": true,
    }))
}

/// `remove_guard_profile_blocks` (`shell_profile_cleanup.py`).
pub fn remove_guard_profile_blocks(context: &ShimContext) -> ShimResult<Value> {
    let facts = &context.facts;
    let markers = json!([GUARD_PROFILE_MARKER, PACKAGE_PROFILE_MARKER]);
    if facts.windows {
        return Ok(json!({
            "changed": false,
            "changed_paths": [],
            "removed_paths": [],
            "markers_removed": markers,
        }));
    }
    let home = context
        .home_dir
        .as_deref()
        .ok_or_else(|| "home_dir is required to clean shell profiles".to_owned())?;
    let mut changed_paths: Vec<String> = Vec::new();
    let mut removed_paths: Vec<String> = Vec::new();
    let candidates = [
        facts.join(home, ".bashrc"),
        facts.join(home, ".bash_profile"),
        facts.join(home, ".bash_login"),
        facts.join(home, ".profile"),
        facts.join(home, ".zshrc"),
        facts.join(
            &facts.join(&facts.join(home, ".config"), "fish"),
            "config.fish",
        ),
    ];
    for path in candidates {
        if !facts.exists(&path) {
            continue;
        }
        let existing = facts
            .read_text(&path)
            .map_err(|error| error.message(&path))?;
        if !existing.contains(GUARD_PROFILE_MARKER) && !existing.contains(PACKAGE_PROFILE_MARKER) {
            continue;
        }
        let mut cleaned = existing.clone();
        if cleaned.contains(GUARD_PROFILE_MARKER) {
            cleaned = strip_managed_marker_blocks(&cleaned, GUARD_PROFILE_MARKER);
        }
        if cleaned.contains(PACKAGE_PROFILE_MARKER) {
            cleaned = strip_managed_marker_blocks(&cleaned, PACKAGE_PROFILE_MARKER);
        }
        if cleaned == existing {
            continue;
        }
        if cleaned.is_empty() {
            facts.unlink(&path)?;
            removed_paths.push(path.clone());
        } else {
            facts.write_text(&path, &cleaned)?;
        }
        changed_paths.push(path);
    }
    Ok(json!({
        "changed": !changed_paths.is_empty(),
        "changed_paths": changed_paths,
        "removed_paths": removed_paths,
        "markers_removed": markers,
    }))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use super::super::{ShimContext, ShimFacts};
    use super::{ensure_package_shim_path_in_shell_profile, is_transient_path};

    fn facts(shim_dir_transient: Option<bool>) -> ShimFacts {
        ShimFacts {
            environ: BTreeMap::from([
                ("SHELL".to_owned(), "/bin/zsh".to_owned()),
                ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
            ]),
            home: "/Users/home".to_owned(),
            cwd: "/Users/work".to_owned(),
            executable: "/usr/bin/python3".to_owned(),
            frozen: false,
            frozen_cli: String::new(),
            trusted_frozen_cli_paths: Vec::new(),
            python_version: (3, 12),
            import_root: "/Users/src".to_owned(),
            argv0: None,
            windows: false,
            sqlite_connect_timeout_seconds: 30.0,
            now: "2026-01-01T00:00:00+00:00".to_owned(),
            shim_dir_transient,
        }
    }

    fn context(guard_home: &str, home_dir: &str, shim_dir_transient: Option<bool>) -> ShimContext {
        ShimContext::new(guard_home, Some(home_dir), None, facts(shim_dir_transient))
    }

    #[test]
    fn caller_transient_bit_governs_profile_writes_without_changing_the_path_check() {
        let stamp = crate::unique_nanos::unique_nanos();
        let home = std::env::temp_dir().join(format!("hol-guard-shim-profile-{stamp}"));
        let profile = home.join(".zshrc");
        let transient_home = format!("/tmp/hol-guard-shim-profile-{stamp}");
        let durable_home = format!("/Users/hol-guard-shim-profile-{stamp}");
        fs::create_dir_all(&home).expect("home");

        let transient_context = context(&transient_home, home.to_str().expect("utf8"), None);
        let shim_dir = transient_context.shim_dir();
        assert!(is_transient_path(&transient_context.facts, &shim_dir));

        let refused =
            ensure_package_shim_path_in_shell_profile(&transient_context).expect("refuse");
        assert_eq!(refused["changed"], false);
        assert_eq!(refused["manual_path_required"], true);
        assert!(!profile.exists());

        let allowed = ensure_package_shim_path_in_shell_profile(&context(
            &transient_home,
            home.to_str().expect("utf8"),
            Some(false),
        ))
        .expect("allow");
        assert_eq!(allowed["changed"], true);
        let written = fs::read_to_string(&profile).expect("profile");
        assert!(written.contains(&shim_dir));

        fs::remove_file(&profile).expect("cleanup profile");
        let caller_refused = ensure_package_shim_path_in_shell_profile(&context(
            &durable_home,
            home.to_str().expect("utf8"),
            Some(true),
        ))
        .expect("caller refuse");
        assert_eq!(caller_refused["changed"], false);
        assert_eq!(caller_refused["manual_path_required"], true);
        assert!(!is_transient_path(
            &facts(Some(true)),
            &format!("{durable_home}/package-shims/bin")
        ));
        assert!(!profile.exists());
        fs::remove_dir_all(&home).expect("cleanup home");
    }
}
