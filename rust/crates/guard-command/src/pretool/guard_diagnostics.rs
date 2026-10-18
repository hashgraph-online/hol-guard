//! Guard's own read-only diagnostics.
//!
//! Agents routinely run these to learn why a command was paused. Only the bare
//! launcher and the exact argument shapes below are admitted, so repair, fix,
//! incident, uninstall, policy and other control subcommands keep the normal
//! review or critical-floor path.
//!
//! `hol-guard dashboard` is admitted beside them. It starts Guard's own daemon
//! when it is not running and opens the local approval center in the browser.
//! The session token travels only to the browser; the printed URL is redacted.
//! It changes no policy, approval or harness state, and it takes no root
//! override, so it cannot point Guard at another home.
//!
//! `hol-guard approvals`, `approvals list` and `approvals retry-hint <id>` are
//! admitted too (`approval_inspection`). They print the approval queue and the
//! retry hint of a resolved request. Resolving, resuming, opening, unlocking and
//! clearing approvals are separate subcommands and stay reviewed or blocked. The
//! bare `approvals` form, like `dashboard`, may open the user's own approval
//! center once for the next pending request; it resolves nothing. Building the
//! queue snapshot also applies a due Watch-posture revert, which only moves a
//! posture back to protected and never weakens one.
//!
//! Like every other bare-name proof here, the inherited `PATH` is a host trust
//! input: Rust has no resolved executable identity. A launcher sitting in the
//! working directory is the one shadow this proof can see, so it fails closed
//! when one exists or when the working directory is unknown.

use std::path::Path;

const SHADOW_NAMES: &[&str] = &[
    "hol-guard",
    "hol-guard.exe",
    "hol-guard.cmd",
    "hol-guard.bat",
];

pub(super) fn safe_hol_guard_segment(
    arguments: &[String],
    cwd: Option<&str>,
    pipeline_index: usize,
) -> bool {
    cwd.is_some_and(|cwd| !cwd_shadows_launcher(Path::new(cwd)))
        && (safe_hol_guard_arguments(arguments)
            || (pipeline_index == 0
                && super::pytest_contained::safe_pytest_contained_arguments(arguments, cwd)))
}

fn cwd_shadows_launcher(cwd: &Path) -> bool {
    !cwd.is_absolute()
        || SHADOW_NAMES.iter().any(|name| {
            // A directory cannot be executed through a bare-name lookup;
            // files and symlinks (even to directories) still shadow.
            cwd.join(name)
                .symlink_metadata()
                .is_ok_and(|metadata| !metadata.is_dir())
        })
}

pub(super) fn safe_hol_guard_arguments(arguments: &[String]) -> bool {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    matches!(
        words.as_slice(),
        ["--version"]
            | ["status" | "doctor" | "settings"]
            | ["daemon", "status"]
            | ["status" | "doctor" | "settings", "--json"]
            | ["daemon", "status", "--json"]
            | ["dashboard"]
            | ["dashboard", "--json"]
    ) || help_request(&words)
        || command_inspection(&words)
        || approval_inspection(&words)
}

/// The approval queue and the retry hint of one resolved request. The decision
/// subcommands (`approve`, `deny`), `resume`, `open`, `lock`, `unlock` and
/// `clear-history`, and every root override (`--home`, `--guard-home`,
/// `--workspace`), are not admitted.
fn approval_inspection(words: &[&str]) -> bool {
    match words {
        ["approvals"]
        | ["approvals", "--json"]
        | ["approvals", "list"]
        | ["approvals", "list", "--json"] => true,
        ["approvals", "retry-hint", id] | ["approvals", "retry-hint", id, "--json"] => {
            request_id(id)
        }
        _ => false,
    }
}

fn request_id(id: &str) -> bool {
    !id.starts_with('-')
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// `hol-guard command test|explain <text>` classifies one command without
/// running it or writing Guard state, and `command extensions [id]` lists the
/// loaded command extensions. Root overrides (`--home`, `--guard-home`,
/// `--workspace`) and the `controls` and `setup` subcommands are not admitted.
fn command_inspection(words: &[&str]) -> bool {
    let ["command", rest @ ..] = words else {
        return false;
    };
    let json_flags = rest.iter().filter(|word| **word == "--json").count();
    let rest: Vec<&str> = rest
        .iter()
        .copied()
        .filter(|word| *word != "--json")
        .collect();
    json_flags <= 1
        && match rest.as_slice() {
            ["test" | "explain", text] => inspected_text(text),
            ["extensions"] => true,
            ["extensions", id] => extension_id(id),
            _ => false,
        }
}

fn inspected_text(text: &str) -> bool {
    !text.trim().is_empty() && !text.starts_with('-') && !text.contains('\0') && text.len() <= 4_096
}

fn extension_id(id: &str) -> bool {
    !id.starts_with(['-', '.'])
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

/// `--help` for the launcher or a documented subcommand. The parser prints
/// usage and exits before any subcommand runs. Only known subcommand names are
/// admitted: a frozen launcher treats a leading word naming a package manager
/// as a shim script path, which the working directory could supply.
///
/// A leading `guard` is the launcher's no-op prefix (`hol-guard guard --help`
/// runs `hol-guard --help`), so it is dropped before the same check.
fn help_request(words: &[&str]) -> bool {
    let words = match words {
        ["guard", rest @ ..] => rest,
        _ => words,
    };
    let known = |word: &&str| HELP_SUBCOMMANDS.contains(word);
    match words {
        ["help", rest @ ..] => rest.len() <= 2 && rest.iter().all(known),
        [rest @ .., "--help" | "-h"] => rest.len() <= 2 && rest.iter().all(known),
        _ => false,
    }
}

const HELP_SUBCOMMANDS: &[&str] = &[
    "abom",
    "advisories",
    "allow",
    "approvals",
    "apps",
    "bootstrap",
    "command",
    "daemon",
    "dashboard",
    "deny",
    "detect",
    "diff",
    "doctor",
    "events",
    "exceptions",
    "explain",
    "export",
    "history",
    "hooks",
    "import",
    "init",
    "install",
    "inventory",
    "list",
    "mcp",
    "policies",
    "policy",
    "receipts",
    "repair",
    "retry-hint",
    "risk-report",
    "run",
    "scan",
    "secrets",
    "security-level",
    "set",
    "settings",
    "show",
    "skills",
    "start",
    "status",
    "stop",
    "sync",
    "trust",
    "uninstall",
    "update",
    "validate",
];

#[cfg(test)]
mod tests {
    use super::{safe_hol_guard_arguments, safe_hol_guard_segment};

    fn arguments(command: &str) -> Vec<String> {
        command.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn admits_only_exact_read_only_diagnostics() {
        for command in [
            "--version",
            "status",
            "status --json",
            "daemon status",
            "daemon status --json",
            "doctor",
            "doctor --json",
            "settings",
            "settings --json",
            "dashboard",
            "dashboard --json",
            "--help",
            "-h",
            "help",
            "help doctor",
            "doctor --help",
            "daemon status -h",
            "secrets --help",
            "update --help",
            "help update",
            "command extensions",
            "command extensions --json",
            "command extensions node.eval",
            "guard --help",
            "guard -h",
            "guard help",
            "guard doctor --help",
            "guard help doctor",
            "approvals",
            "approvals --json",
            "approvals list",
            "approvals list --json",
            "approvals retry-hint 0123456789abcdef0123456789abcdef",
            "approvals retry-hint req-1 --json",
            "approvals --help",
            "approvals list --help",
            "approvals retry-hint --help",
        ] {
            assert!(safe_hol_guard_arguments(&arguments(command)), "{command}");
        }
        for command in [
            "",
            "--json",
            "--version --json",
            "status --repair",
            "status --json --repair",
            "doctor --repair",
            "doctor --fix",
            "doctor --incident",
            "doctor codex",
            "doctor --json --incident",
            "doctor --harnesses",
            "daemon",
            "daemon start",
            "daemon stop",
            "daemon status --port 1",
            "settings set mode off",
            "settings doctor",
            "uninstall",
            "repair",
            "repair --json",
            "repair --dry-run",
            "hooks remove",
            "hooks remove --json",
            "policy disable",
            "clear --all",
            "capability consume",
            "--home /tmp status",
            "status --home /tmp",
            "npm --help",
            "__guard-claude-hook --help",
            "status --json --help",
            "help npm",
            "a b c --help",
            "command",
            "command test",
            "command explain",
            "command controls",
            "command controls --json",
            "command setup --detect",
            "command extensions -x",
            "command extensions ../x",
            "command extensions a b",
            "command explain a b",
            "command explain --home",
            "command explain -x",
            "command --json --json extensions",
            "--json command extensions",
            "--home /tmp command extensions",
            "command extensions --home /tmp",
            "command extensions --guard-home /tmp",
            "command extensions --workspace /tmp",
            "guard",
            "guard repair",
            "guard start",
            "guard status --repair",
            "guard guard --help",
            "guard npm --help",
            "guard a b c --help",
            "dashboard --home /tmp",
            "dashboard --guard-home /tmp",
            "dashboard --workspace /tmp",
            "dashboard --json --json",
            "dashboard open",
            "--home /tmp dashboard",
            "approvals approve req-1",
            "approvals approve req-1 --scope global",
            "approvals deny req-1",
            "approvals resume req-1",
            "approvals open req-1",
            "approvals unlock",
            "approvals lock",
            "approvals clear-history --all",
            "approvals list extra",
            "approvals list --home /tmp",
            "approvals --home /tmp",
            "approvals --guard-home /tmp --json",
            "approvals --workspace /tmp",
            "approvals --json --json",
            "approvals --json list",
            "approvals retry-hint",
            "approvals retry-hint --json",
            "approvals retry-hint --home /tmp",
            "approvals retry-hint -x",
            "approvals retry-hint req-1 --home /tmp",
            "approvals retry-hint req-1 req-2",
            "approvals retry-hint ../req",
            "approvals retry-hint req/1",
            "list approvals",
            "approve req-1",
        ] {
            assert!(!safe_hol_guard_arguments(&arguments(command)), "{command}");
        }
    }

    #[test]
    fn command_inspection_takes_one_literal_command_text() {
        let words = |text: &str, json: bool| {
            let mut words = vec!["command".to_owned(), "explain".to_owned(), text.to_owned()];
            if json {
                words.push("--json".to_owned());
            }
            words
        };
        for text in ["bun run build", "rm -rf /", "git push --force origin main"] {
            assert!(safe_hol_guard_arguments(&words(text, false)), "{text}");
            assert!(safe_hol_guard_arguments(&words(text, true)), "{text}");
        }
        let too_long = "x".repeat(4_097);
        for text in [
            "",
            "   ",
            "--home /tmp/evil",
            "-c x",
            "a\0b",
            too_long.as_str(),
        ] {
            assert!(!safe_hol_guard_arguments(&words(text, false)), "{text:?}");
        }
        let mut extra = words("bun run build", false);
        extra.extend(["--home".to_owned(), "/tmp/evil".to_owned()]);
        assert!(!safe_hol_guard_arguments(&extra));
    }

    #[test]
    fn working_directory_launcher_or_unknown_cwd_keeps_review() {
        let workspace =
            std::env::temp_dir().join(format!("guard-diagnostics-shadow-{}", std::process::id()));
        std::fs::create_dir_all(&workspace).unwrap();
        let cwd = workspace.to_str().unwrap().to_owned();
        let status = arguments("status");
        assert!(safe_hol_guard_segment(&status, Some(&cwd), 0));
        assert!(!safe_hol_guard_segment(&status, None, 0));
        assert!(!safe_hol_guard_segment(&status, Some("relative/dir"), 0));
        std::fs::write(workspace.join("hol-guard"), "#!/bin/sh\n").unwrap();
        let shadowed = safe_hol_guard_segment(&status, Some(&cwd), 0);
        std::fs::remove_dir_all(&workspace).unwrap();
        assert!(!shadowed);
    }
}
