//! Shapes [`super::safe_hol_guard_arguments`] admits and refuses.

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
        "settings list",
        "settings list --json",
        "settings explain",
        "settings explain --json",
        "settings doctor",
        "settings doctor --json",
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
        "approvals wait req-1 --json",
        "approvals wait req-1 --timeout 0",
        "approvals wait req-1 --timeout 600 --json",
        "approvals --help",
        "approvals list --help",
        "approvals retry-hint --help",
        "command test --help",
        "command explain -h",
        "command extensions --help",
        "help command test",
        "guard command test --help",
        "daemon start --help",
        "policy set --help",
        "approvals approve --help",
        "events --help",
        "events",
        "events --json",
        "events --name guard.daemon.start",
        "events --name guard.daemon.start --json",
        "exceptions",
        "exceptions --json",
        "exceptions --harness codex",
        "exceptions --harness codex --json",
        "policies",
        "policies --json",
        "policies --harness grok",
        "policies --harness grok --json",
        "policies verify",
        "policies integrity-status --json",
        "receipts",
        "receipts --json",
        "history",
        "history --json",
        "history explain 42",
        "history explain receipt-7 --json",
        "advisories",
        "advisories --json",
        "advisories list",
        "advisories list --json",
        "advisories list --severity high",
        "advisories explain GHSA-1234-abcd",
        "inventory",
        "inventory --json",
        "trust",
        "trust status",
        "trust status --json",
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
        "settings set protection off",
        "settings list --home /tmp",
        "settings explain --guard-home /tmp",
        "settings doctor --workspace /tmp",
        "settings list extra",
        "settings list --json --json",
        "settings approval-password",
        "settings approval-totp",
        "settings get",
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
        "command ../test --help",
        "command -x --help",
        "command test extra --help",
        "npm test --help",
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
        "approvals open req-1",
        "approvals open req-1 --json",
        "approvals open --json req-1",
        "inbox --help",
        "--home /tmp dashboard",
        "approvals approve req-1",
        "approvals approve req-1 --scope global",
        "approvals deny req-1",
        "approvals resume req-1",
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
        "approvals wait",
        "approvals wait req-1 --timeout 601",
        "approvals wait req-1 --timeout -1",
        "approvals wait req-1 --home /tmp",
        "list approvals",
        "approve req-1",
        "advisories sync",
        "advisories sync --json",
        "inventory --sync",
        "inventory --json --sync",
        "policies clear",
        "policies clear --all",
        "policies repair",
        "policies migrate-local-integrity",
        "policies --home /tmp",
        "policies --harness",
        "policies --harness ../x",
        "events --home /tmp",
        "events --name",
        "events --name a b",
        "exceptions --guard-home /tmp",
        "exceptions --workspace /tmp",
        "exceptions --json --json",
        "history explain",
        "history explain ../receipt",
        "history clear",
        "receipts sync",
        "receipts --home /tmp",
        "advisories explain",
        "advisories list --severity",
        "trust setup",
        "trust reset",
        "trust test",
        "trust status --home /tmp",
        "pnpm --help",
        "uv --help",
        "help pnpm",
        "brew --help",
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
