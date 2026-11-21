//! Rust port of `runtime/persistence_rules.py` — persistence mechanism
//! detection for Guard runtime shell actions.
//!
//! Python `re` semantics are reproduced with `fancy_regex` (lookbehind) plus
//! [`py_regex`], which rewrites `\b`, `\s`, `\S`, `\w` and the
//! `IGNORECASE` quirks of Python's `str` patterns (see its docs).

use std::sync::LazyLock;

use fancy_regex::{Regex, RegexBuilder};

use crate::detectors::{PersistenceMatchView, PersistenceRulesApi};

const WORD_CLASS: &str = r"[\p{L}\p{N}_]";
const BOUNDARY: &str =
    r"(?:(?<=[\p{L}\p{N}_])(?![\p{L}\p{N}_])|(?<![\p{L}\p{N}_])(?=[\p{L}\p{N}_]))";

/// Rewrite a Python `re` pattern (str mode) into an equivalent
/// `fancy_regex` pattern.
///
/// * `\b`/`\w` use Python's alphanumeric word definition (`L*`, `N*`, `_`)
///   instead of Rust's (which adds marks and connectors).
/// * `\s`/`\S` additionally cover `\x1c`-`\x1f`, which Python treats as
///   whitespace.
/// * With `IGNORECASE`, Python also folds `i` with U+0130/U+0131; Rust's
///   simple case folding does not, so those are added explicitly.
pub(crate) fn translate_py_pattern(pattern: &str, ignorecase: bool) -> String {
    let mut out = String::with_capacity(pattern.len() * 2);
    let mut chars = pattern.chars();
    let mut in_class = false;
    let mut class_src = String::new();
    let mut class_insert = 0usize;
    while let Some(c) = chars.next() {
        if c == '\\' {
            let next = chars.next().unwrap_or('\\');
            let rep: String = match (next, in_class) {
                ('b', false) => BOUNDARY.to_string(),
                ('s', false) => r"[\s\x1c-\x1f]".to_string(),
                ('S', false) => r"[^\s\x1c-\x1f]".to_string(),
                ('w', false) => WORD_CLASS.to_string(),
                ('s', true) => r"\s\x1c-\x1f".to_string(),
                ('w', true) => r"\p{L}\p{N}_".to_string(),
                _ => format!("\\{next}"),
            };
            out.push_str(&rep);
            if in_class {
                class_src.push('\\');
                class_src.push(next);
            }
            continue;
        }
        if in_class {
            if c == ']' {
                if ignorecase && (class_src.contains("a-z") || class_src.contains("A-Z")) {
                    // Insert at the class start so a trailing `-` is never
                    // turned into a range.
                    out.insert_str(class_insert, r"\x{130}\x{131}");
                }
                in_class = false;
            } else {
                if c == '^' && class_src.is_empty() && out.len() == class_insert {
                    class_insert += 1;
                }
                class_src.push(c);
            }
            out.push(c);
            continue;
        }
        match c {
            '[' => {
                in_class = true;
                class_src.clear();
                out.push(c);
                class_insert = out.len();
            }
            'i' | 'I' if ignorecase => out.push_str(r"[iI\x{130}\x{131}]"),
            _ => out.push(c),
        }
    }
    out
}

/// Compile a Python-semantics pattern. `flags` is a subset of `ims`.
pub(crate) fn py_regex(pattern: &str, flags: &str) -> Regex {
    let translated = translate_py_pattern(pattern, flags.contains('i'));
    let full = if flags.is_empty() {
        translated
    } else {
        format!("(?{flags}){translated}")
    };
    RegexBuilder::new(&full)
        .backtrack_limit(100_000_000)
        .build()
        .unwrap_or_else(|err| panic!("invalid pattern {full}: {err}"))
}

/// A match that runs past the backtrack budget counts as a hit: every caller
/// treats a match as risk, so crafted input cannot hide behind a stalled search.
pub(crate) fn re_search(re: &Regex, text: &str) -> bool {
    re.is_match(text).unwrap_or(true)
}

static GIT_HOOK_PATHS: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"(?<![A-Za-z0-9_.-])\.git/hooks/(?:pre-commit|post-commit|pre-push|post-merge|post-checkout|pre-receive|post-receive|update|commit-msg|prepare-commit-msg)(?![A-Za-z0-9_.-])",
        "i",
    )
});

static CRON_WRITE: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r#"(?:^|[\s;&|])(?:crontab\s+(?:-u\s+\S+\s+)?(?:-e\b|-\s*$|[^-\r\n\s][^\r\n;&|]{0,100})|crontab\s*<\s*\S+|(?:echo|printf|cat|tee)\b[^\r\n;&|]{0,200}(?:>|\|\s*tee)\s*/(?:var/spool/cron|etc/cron[^'"]*?))"#,
        "i",
    )
});

static LAUNCH_AGENT_PATHS: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r#"(?<![A-Za-z0-9_.-])(?:~/Library/LaunchAgents/|/Library/LaunchAgents/|/Library/LaunchDaemons/|/System/Library/LaunchAgents/|/System/Library/LaunchDaemons/)[^'"\s\\]{3,}\.plist(?![A-Za-z0-9_.-])"#,
        "i",
    )
});

static SYSTEMD_WRITE: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r#"(?<![A-Za-z0-9_.-])(?:/etc/systemd/system/|/usr/lib/systemd/system/|/run/systemd/system/|~?/\.config/systemd/user/|(?:/home/[^/\s]+|\$HOME)/\.config/systemd/user/)[^'"\s\\]{3,}\.(?:service|timer|socket|path|mount|target)(?![A-Za-z0-9_.-])"#,
        "i",
    )
});

static VSCODE_TASKS: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"(?<![A-Za-z0-9_.-])\.vscode/(?:tasks|launch|settings)\.json(?![A-Za-z0-9_.-])",
        "i",
    )
});

static REGISTRY_WRITE: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"(?:^|[\s;&|])(?:reg\s+(?:add|import|copy)|regini)\b", "i"));

static AT_JOB_WRITE: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"(?:^|[\s;&|])(?:at\s+(?:-f\s+\S+\s+)?(?:now|midnight|noon|tomorrow|\d+(?::\d+)?(?:am|pm)?)\b|(?:echo|printf)\b[^\r\n;&|]{0,200}\|\s*at\b)",
        "i",
    )
});

static SHELL_PROFILE_WRITE: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"(?:^|[\s;&|])(?:echo|printf|cat|tee|append|heredoc)\b[^\r\n;&|]{0,300}(?:>>|>\s*>?|\|\s*(?:tee\s+(?:-a\s+)?)?)\s*~?/?(?:\.bashrc|\.bash_profile|\.bash_login|\.profile|\.zshrc|\.zprofile|\.zlogin|\.zshenv|\.kshrc|\.config/fish/config\.fish)",
        "i",
    )
});

static WRITE_OPERATION: LazyLock<Regex> = LazyLock::new(|| {
    py_regex(
        r"(?:>>?|tee\b|\bcp\b|\bmv\b|\binstall\b|\bwrite\b|\bcat\s*>)",
        "i",
    )
});

fn is_write_operation(command: &str) -> bool {
    re_search(&WRITE_OPERATION, command)
}

fn view(
    mechanism: &'static str,
    plain_reason: &'static str,
    false_positive_hint: &'static str,
) -> PersistenceMatchView<'static> {
    PersistenceMatchView {
        mechanism,
        plain_reason,
        false_positive_hint,
    }
}

/// `detect_persistence_mechanisms(command)`.
pub fn detect_persistence_mechanisms(command: &str) -> Vec<PersistenceMatchView<'static>> {
    let mut matches = Vec::new();
    if re_search(&SHELL_PROFILE_WRITE, command) {
        matches.push(view(
            "shell_profile_write",
            "Command writes to a shell profile or startup file, which runs on every new terminal session.",
            "Allow if this is setting up a legitimate development environment or PATH entry.",
        ));
    }
    if re_search(&GIT_HOOK_PATHS, command) && is_write_operation(command) {
        matches.push(view(
            "git_hook_write",
            "Command installs or modifies a git hook, which runs automatically on git events.",
            "Allow if this is installing a project-standard code quality or signing hook.",
        ));
    }
    if re_search(&CRON_WRITE, command) {
        matches.push(view(
            "cron_write",
            "Command modifies scheduled tasks (cron), allowing code to run automatically at set times.",
            "Allow if this is setting up a legitimate periodic maintenance task.",
        ));
    }
    if re_search(&LAUNCH_AGENT_PATHS, command) && is_write_operation(command) {
        matches.push(view(
            "launch_agent_write",
            "Command installs a macOS Launch Agent or Daemon, which runs automatically on login or boot.",
            "Allow if this is installing a known legitimate background service.",
        ));
    }
    if re_search(&SYSTEMD_WRITE, command) && is_write_operation(command) {
        matches.push(view(
            "systemd_unit_write",
            "Command installs a systemd service unit, which can run automatically at boot or login.",
            "Allow if this is installing a known legitimate system service.",
        ));
    }
    if re_search(&VSCODE_TASKS, command) && is_write_operation(command) {
        matches.push(view(
            "vscode_tasks_write",
            "Command modifies VS Code tasks or launch configuration, which run automatically in the IDE.",
            "Allow if this is setting up legitimate project build or debug tasks.",
        ));
    }
    if re_search(&REGISTRY_WRITE, command) {
        matches.push(view(
            "registry_write",
            "Command writes to the Windows Registry, which can configure autostart or persistent settings.",
            "Allow if this is a known legitimate software installer or configuration step.",
        ));
    }
    if re_search(&AT_JOB_WRITE, command) {
        matches.push(view(
            "at_job_schedule",
            "Command schedules a one-time deferred job via `at`, which runs automatically at the specified time.",
            "Allow if this is scheduling a legitimate maintenance or notification task.",
        ));
    }
    matches
}

/// Native implementation of the `PersistenceRulesApi` seam.
pub struct NativePersistenceRules;

impl PersistenceRulesApi for NativePersistenceRules {
    fn detect_persistence_mechanisms<'a>(&self, command: &'a str) -> Vec<PersistenceMatchView<'a>> {
        detect_persistence_mechanisms(command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../tests/fixtures/persistence_rules_vectors.json");

    #[test]
    fn persistence_rules_match_python_vectors() {
        let vectors: Vec<Value> = serde_json::from_str(VECTORS).expect("fixture json");
        assert!(vectors.len() >= 100);
        for vector in &vectors {
            let name = vector["name"].as_str().unwrap();
            let command = vector["command"].as_str().unwrap();
            let got: Vec<Value> = NativePersistenceRules
                .detect_persistence_mechanisms(command)
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "mechanism": m.mechanism,
                        "plain_reason": m.plain_reason,
                        "false_positive_hint": m.false_positive_hint,
                    })
                })
                .collect();
            assert_eq!(&Value::Array(got), &vector["expected"], "vector {name}");
        }
    }

    #[test]
    fn translation_rewrites_python_classes() {
        assert!(translate_py_pattern(r"\s[^\s]", false).contains(r"\x1c-\x1f"));
        assert!(translate_py_pattern("install", true).contains(r"\x{130}"));
        assert!(!translate_py_pattern("install", false).contains(r"\x{130}"));
    }
}
