//! Process-environment secret reads, including bounded local interpreter files.

use crate::hook_adapter_pytext::{compile_fancy, py_strip};
use crate::runtime_read_paths::{
    canonicalize_text, read_small_runtime_text_file, resolved_runtime_path, runtime_read_roots,
};
use crate::sfrs_gh_bindings::py_pattern;
use crate::sfrs_shell_tokens::{
    iter_shell_command_segments, shell_segment_primary_command, split_shell_parts,
};
use fancy_regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

const INVALID: &str = "native_context_component_invalid";
static SENSITIVE_NAME: LazyLock<Regex> = LazyLock::new(|| {
    compile_fancy(
        r"(?i)(?:^|[_-])(?:api[_-]?key|auth|credential|credentials|key|password|private[_-]?key|secret|token)(?:[_-]|$)",
    )
});
static ENV_EXPANSION: LazyLock<Regex> = LazyLock::new(|| {
    compile_fancy(
        r"(?<!\\)\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)[^}]*\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))",
    )
});
static ENV_LOOKUPS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
    r#"(?i)os\.environ\s*\[\s*['"](?P<name>[^'"]+)['"]\s*\]"#,
    r"(?i)os\.environ\s*\[\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\]",
    r#"(?i)os\.environ\.get\(\s*['"](?P<name>[^'"]+)['"]"#,
    r#"(?i)os\.getenv\(\s*['"](?P<name>[^'"]+)['"]"#,
    r#"process\.env(?:\.\s*(?P<dot>[A-Za-z_][A-Za-z0-9_]*)|\[\s*['"](?P<bracket>[^'"]+)['"]\s*\])"#,
    r#"ENV\[\s*['"](?P<name>[^'"]+)['"]\s*\]"#,
    r#"(?i)System\.getenv\(\s*['"](?P<name>[^'"]+)['"]\s*\)"#,
].into_iter().map(compile_python_pattern).collect()
});
static ENV_DUMPS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"\bos\.environ\b(?!\s*(?:\[|\.get\b|\.setdefault\b))",
        r"\bos\.environ\s*\.\s*(?:items|keys|values|copy|update)\s*\(",
        r"\bprocess\.env\b(?!\s*[.\[])",
        r#"\bprocess\.env\s*\[\s*(?!['"])"#,
    ]
    .into_iter()
    .map(compile_python_pattern)
    .collect()
});
static PYTHON_NAME: LazyLock<Regex> =
    LazyLock::new(|| compile_fancy(r"^pythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?$"));
static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| compile_fancy(r"^[A-Za-z_][A-Za-z0-9_]*=.*"));

fn matches(pattern: &Regex, text: &str) -> Result<bool, &'static str> {
    pattern.is_match(text).map_err(|_| INVALID)
}
fn compile_python_pattern(pattern: &str) -> Regex {
    let mut pattern = py_pattern(pattern);
    if pattern.starts_with("(?i)") {
        pattern = pattern
            .replace("environ", r"env[i\u{0130}\u{0131}]ron")
            .replace("[A-Za-z_]", r"[A-Za-z_\u{0130}\u{0131}]")
            .replace("[A-Za-z0-9_]", r"[A-Za-z0-9_\u{0130}\u{0131}]");
    }
    compile_fancy(&pattern)
}
fn sensitive_name(name: &str) -> Result<bool, &'static str> {
    // Python IGNORECASE also folds dotted and dotless I to ASCII i. Rust's
    // Unicode simple folding already covers Python's Kelvin sign and long s.
    let name = py_strip(name);
    if name.contains('\u{0130}') || name.contains('\u{0131}') {
        matches(
            &SENSITIVE_NAME,
            &name.replace(['\u{0130}', '\u{0131}'], "i"),
        )
    } else {
        matches(&SENSITIVE_NAME, name)
    }
}
/// Whether `text` runs `printenv` in a way that could print a secret: with no
/// variable named, with an option, or naming a credential-like variable.
/// `printenv PATH HOME` prints only the values asked for.
pub fn printenv_may_print_secret(text: &str) -> bool {
    text.match_indices("printenv").any(|(start, _)| {
        let mut names = text[start + "printenv".len()..]
            .split([';', '&', '|', '>', '<', '\n', ')', '`'])
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .peekable();
        names.peek().is_none()
            || names.any(|name| {
                !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                    || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    || sensitive_name(name).unwrap_or(true)
            })
    })
}
fn script_reads_secrets(script: &str) -> Result<bool, &'static str> {
    for pattern in ENV_DUMPS.iter() {
        if matches(pattern, script)? {
            return Ok(true);
        }
    }
    for captures in ENV_EXPANSION.captures_iter(script) {
        let captures = captures.map_err(|_| INVALID)?;
        if sensitive_name(
            captures
                .name("braced")
                .or_else(|| captures.name("plain"))
                .map_or("", |value| value.as_str()),
        )? {
            return Ok(true);
        }
    }
    for pattern in ENV_LOOKUPS.iter() {
        for captures in pattern.captures_iter(script) {
            let captures = captures.map_err(|_| INVALID)?;
            for name in ["name", "dot", "bracket"] {
                if let Some(value) = captures.name(name) {
                    if sensitive_name(value.as_str())? {
                        return Ok(true);
                    }
                }
            }
        }
    }
    Ok(false)
}
fn env_utility_dumps_secrets(command: &str, args: &[String]) -> Result<bool, &'static str> {
    let mut leftover = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        if matches!(token.as_str(), "-u" | "--unset") && index + 1 < args.len() {
            index += 2;
            continue;
        }
        if !token.starts_with('-') && !matches(&ASSIGNMENT, token)? {
            leftover.push(token);
        }
        index += 1;
    }
    if leftover.is_empty() {
        return Ok(true);
    }
    if command == "printenv" {
        for name in leftover {
            if sensitive_name(name)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
fn inline_script(args: &[String]) -> Option<&str> {
    for (index, token) in args.iter().enumerate() {
        if matches!(token.as_str(), "-c" | "-e") {
            if let Some(next) = args.get(index + 1) {
                return Some(next);
            }
        }
        if (token.starts_with("-c") || token.starts_with("-e")) && token.len() > 2 {
            return Some(&token[2..]);
        }
    }
    None
}
fn file_operand(args: &[String]) -> Option<&str> {
    for token in args {
        if token.starts_with("-c") || token.starts_with("-e") || token == "-m" {
            return None;
        }
        if !token.starts_with('-') {
            return Some(token);
        }
    }
    None
}
/// Whether an `echo` or `printf` segment's text expands a credential-named
/// variable such as `$GITHUB_TOKEN`. Printing one shows the secret to the
/// agent, or writes it where any later command can read it. Fails closed.
pub fn printer_expands_secret(text: &str) -> bool {
    script_reads_secrets(text).unwrap_or(true)
}
fn segment_reads_secrets(
    segment: &[String],
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    fallback_cwd: Option<&Path>,
) -> Result<bool, &'static str> {
    let (Some(command), Some(index)) = shell_segment_primary_command(segment) else {
        return Ok(false);
    };
    let args = &segment[index + 1..];
    if matches!(command.as_str(), "env" | "printenv") {
        return env_utility_dumps_secrets(&command, args);
    }
    if matches!(command.as_str(), "echo" | "printf") {
        return script_reads_secrets(&args.join(" "));
    }
    let inline_interpreter = command.starts_with("python")
        || matches!(
            command.as_str(),
            "node" | "nodejs" | "perl" | "php" | "ruby"
        );
    if inline_interpreter {
        if let Some(script) = inline_script(args) {
            if script_reads_secrets(script)? {
                return Ok(true);
            }
        } else if args.iter().any(|arg| arg == "-")
            && args.iter().any(|arg| arg.starts_with("<<"))
            && script_reads_secrets(&args.join(" "))?
        {
            return Ok(true);
        }
    }
    if matches(&PYTHON_NAME, &command)? || matches!(command.as_str(), "node" | "nodejs") {
        if let Some(operand) = file_operand(args) {
            let roots = runtime_read_roots(cwd, home_dir);
            // Python resolves the operand before containment, including links
            // whose targets remain inside the allowed roots. The bounded reader
            // still verifies the resolved entry and opens it without following.
            let stripped = py_strip(operand).trim_matches('\'').trim_matches('"');
            let expanded = crate::home_path_text::expand_home(stripped, home_dir);
            let normalized = crate::home_path_text::normalize_path(&expanded, cwd.or(fallback_cwd));
            let canonical = canonicalize_text(Path::new(&normalized)).ok();
            if let Some(path) = canonical.and_then(|path| {
                resolved_runtime_path(&path.to_string_lossy(), cwd, home_dir, Some(&roots))
            }) {
                if let Some(script) = read_small_runtime_text_file(&path, &roots) {
                    return script_reads_secrets(&script);
                }
            }
        }
    }
    Ok(false)
}
/// Rust observes bounded local files itself; callers supply no risk verdicts.
pub fn command_reads_environment_secrets(
    command: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> Result<bool, &'static str> {
    command_reads_environment_secrets_with_caller_cwd(command, cwd, home_dir, None)
}

/// The caller's implicit cwd resolves operands without adding an allowed root.
pub fn command_reads_environment_secrets_with_caller_cwd(
    command: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    fallback_cwd: Option<&Path>,
) -> Result<bool, &'static str> {
    for segment in iter_shell_command_segments(&split_shell_parts(command)) {
        if segment_reads_secrets(&segment, cwd, home_dir, fallback_cwd)? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
#[path = "environment_secret_dump_tests.rs"]
mod tests;
