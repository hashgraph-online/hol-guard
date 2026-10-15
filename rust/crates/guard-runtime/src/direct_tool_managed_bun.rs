//! Exact installed Bun-shim proof using the caller's launcher identity.
//! The template is the current public shim program; no request supplies bytes
//! or digests, and the resident never uses its own Python or build-tree path.

use std::path::{Path, PathBuf};

use guard_contracts::RequestContextDirectFactsV1;
use serde_json::Value;

use crate::git_execution_safety_binary as binary;
use crate::request_context_op::Budget;

const TEMPLATE: &str = include_str!("direct_tool_bun_template.txt");
const LAUNCHER: &str = include_str!("direct_tool_cli_launcher.txt");

fn repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control() => {
                let n = c as u32;
                out.push_str(&if n <= 255 {
                    format!("\\x{n:02x}")
                } else {
                    format!("\\u{n:04x}")
                });
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

fn shell_quote(text: &str) -> String {
    if !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c))
    {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', "'\"'\"'"))
    }
}

fn expected_source(facts: &RequestContextDirectFactsV1, shim_dir: &Path) -> String {
    let launcher = &facts.launcher;
    let import_root = guard_command::hook_adapter_paths::safe_resolve(
        &launcher.import_root,
        &guard_command::hook_adapter_paths::PathEnv {
            cwd: Some(facts.cwd.clone()),
            default_home: Some(facts.caller_home.clone()),
            tilde_home: Some(facts.caller_home.clone()),
        },
    )
    .unwrap_or_else(|_| launcher.import_root.clone());
    let guard_home = Path::new(&facts.home_dir).join(".hol-guard");
    let mut args = if launcher.frozen {
        vec![launcher.interpreter.clone()]
    } else {
        let mut args = vec![launcher.python_executable.clone(), "-I".into()];
        if launcher.python_version >= [3, 11] {
            args.push("-P".into());
        }
        args.extend([
            "-c".into(),
            LAUNCHER.trim_end_matches('\n').into(),
            import_root.clone(),
            "codex_plugin_scanner.cli".into(),
            "guard".into(),
        ]);
        args
    };
    args.extend([
        "protect".into(),
        "--package-shim-ui".into(),
        "--guard-home".into(),
        guard_home.to_string_lossy().into_owned(),
        "--home".into(),
        facts.home_dir.clone(),
    ]);
    let replacements = [
        ("#!{{interpreter}}", format!("#!{}", launcher.interpreter)),
        (
            "base_command = {{base_command}}",
            format!(
                "base_command = [{}]",
                args.iter().map(|s| repr(s)).collect::<Vec<_>>().join(", ")
            ),
        ),
        (
            "guard_cli_cwd = {{import_root}}",
            format!("guard_cli_cwd = {}", repr(&import_root)),
        ),
        (
            "guard_home = {{guard_home}}",
            format!("guard_home = {}", repr(&guard_home.to_string_lossy())),
        ),
        (
            "shim_dir = {{shim_dir}}",
            format!("shim_dir = {}", repr(&path_text(shim_dir))),
        ),
    ];
    // Replace whole template lines, never caller-controlled substrings.
    let mut out = String::new();
    for line in TEMPLATE.lines() {
        out.push_str(
            replacements
                .iter()
                .find(|(key, _)| *key == line)
                .map_or(line, |(_, value)| value),
        );
        out.push('\n');
    }
    out
}

fn read(path: &Path) -> Option<Vec<u8>> {
    guard_secure_fs::read_bounded(path, 256 * 1024)
        .ok()
        .map(|v| v.bytes)
}

fn path_text(path: &Path) -> String {
    let text = path.to_string_lossy();
    #[cfg(windows)]
    {
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{rest}");
        }
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            return rest.to_owned();
        }
    }
    text.into_owned()
}

fn proof(
    facts: &RequestContextDirectFactsV1,
    resolved: &Path,
    cwd: &Path,
    budget: &Budget,
) -> Option<()> {
    budget.check().ok()?;
    let directory = Path::new(&facts.home_dir).join(".hol-guard/package-shims");
    let shim_dir = directory.join("bin").canonicalize().ok()?;
    if resolved != shim_dir.join("bun") || !binary::executable_file(resolved) {
        return None;
    }
    let manifest: Value = serde_json::from_slice(&read(
        &directory.join("manifest.json").canonicalize().ok()?,
    )?)
    .ok()?;
    let managers = manifest.get("installed_managers")?.as_array()?;
    const KNOWN: &[&str] = &[
        "brew", "bun", "bunx", "bundle", "cargo", "composer", "go", "gradle", "mvn", "npm", "npx",
        "pip", "pip3", "pipenv", "pipx", "pnpm", "poetry", "uv", "uvx", "yarn",
    ];
    if !managers
        .iter()
        .all(|m| m.as_str().is_some_and(|s| KNOWN.contains(&s)))
        || !managers.iter().any(|m| m.as_str() == Some("bun"))
    {
        return None;
    }
    if !binary::executable_file(Path::new(&facts.launcher.interpreter)) {
        return None;
    }
    let source = expected_source(facts, &shim_dir);
    let installed = read(resolved)?;
    if facts.launcher.frozen || facts.launcher.python_executable.contains(' ') {
        let sidecar = shim_dir.join(".bun.py");
        let wrapper = format!(
            "#!/bin/sh\nexec {} {} \"$@\"\n",
            shell_quote(&facts.launcher.interpreter),
            shell_quote(&path_text(&sidecar))
        );
        if installed != wrapper.as_bytes() || read(&sidecar)? != source.as_bytes() {
            return None;
        }
    } else if installed != source.as_bytes() {
        return None;
    }
    let configured = facts.environment.get("PATH")?;
    let entries: Vec<PathBuf> = std::env::split_paths(configured)
        .filter(|p| {
            let expanded = if p.starts_with("~") {
                let home = facts.environment.get("HOME").unwrap_or(&facts.caller_home);
                if p == Path::new("~") {
                    PathBuf::from(home)
                } else if let Ok(rest) = p.strip_prefix("~") {
                    Path::new(home).join(rest)
                } else {
                    p.clone()
                }
            } else if p.is_absolute() {
                p.clone()
            } else {
                cwd.join(p)
            };
            expanded.canonicalize().ok().as_deref() != Some(shim_dir.as_path())
        })
        .collect();
    let filtered = std::env::join_paths(entries).ok()?.into_string().ok()?;
    if filtered.is_empty() {
        return None;
    }
    let mut environment = facts.environment.clone();
    environment.insert("PATH".into(), filtered);
    binary::which_for_cwd("bun", cwd, &environment, Path::new(&facts.caller_home))?;
    budget.check().ok()?;
    Some(())
}

pub(crate) fn trusted(
    facts: &RequestContextDirectFactsV1,
    resolved: &Path,
    cwd: &Path,
    budget: &Budget,
) -> bool {
    proof(facts, resolved, cwd, budget).is_some()
}
