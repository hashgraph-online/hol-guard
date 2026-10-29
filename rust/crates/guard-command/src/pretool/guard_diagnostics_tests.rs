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
        "repair --dry-run",
        "repair --dry-run --json",
        "package-shims --help",
        "help package-shims",
        "verified-read --help",
        "verified-read github-pr --help",
        "network --help",
        "mdm --help",
        "preflight --help",
        "supply-chain --help",
        "runtime --help",
        "connect --help",
        "login --help",
        "device --help",
        "admin --help",
        "commands --help",
        "contained-write --help",
        "health-leases --help",
        "hook --help",
        "service --help",
        "test-eval --help",
        "aibom --help",
        "bridge --help",
        "cloud --help",
        "cloud-review --help",
        "desktop --help",
        "disconnect --help",
        "remote-pair --help",
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
        "command test extra more --help",
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
        "protect --help",
        "protect npm --help",
        "run-shim --help",
        "run-shim codex --help",
        "pytest-contained --help",
        "pytest-contained pytest --help",
        "help protect",
        "help run-shim",
        "help pytest-contained",
        "repair --dry-run --home /tmp",
        "repair --dry-run --json --json",
        "repair --dry-run extra",
        "repair --force",
        "package-shims",
        "package-shims --json",
        "package-shims status",
        "package-shims status --json",
        "package-shims install",
        "package-shims repair",
        "package-shims test",
        "package-shims uninstall",
        "package-shims status --home /tmp",
        "package-shims --manager npm",
        "package-shims --approval-password x",
        "package-shims --json --json",
    ] {
        assert!(!safe_hol_guard_arguments(&arguments(command)), "{command}");
    }
}

#[test]
fn runtime_posture_reads_quietly_and_help_follows_the_parser_down() {
    for command in [
        // `runtime` prints the executables configured MCP servers would launch
        // and the advisory coverage Guard already holds; `posture` reads the
        // same way.
        "runtime",
        "runtime --json",
        "runtime posture",
        "runtime posture --json",
        "runtime --help",
        "runtime posture --help",
        "help runtime posture",
        // A help path nests as deep as the parser itself does.
        "command controls patterns --help",
        "command controls patterns -h",
        "help command controls patterns",
        "guard command controls patterns --help",
        "settings set fleet-posture --help",
    ] {
        assert!(safe_hol_guard_arguments(&arguments(command)), "{command}");
    }
    for command in [
        // Nothing beyond the two read-only shapes, and no root override.
        // `--instances` enumerates running processes and writes what it saw
        // into the Guard home, so it is reviewed like any other command that
        // reads more than its own subject.
        "runtime --instances",
        "runtime --json --instances",
        "runtime posture --instances",
        "runtime posture --json --instances",
        "runtime posture extra",
        "runtime posture --json --json",
        "runtime --home /tmp",
        "runtime posture --guard-home /tmp",
        "runtime posture --workspace /tmp",
        "runtime list",
        // The leading word still has to name a known subcommand, and a help
        // path cannot run past the parser's depth or carry a value.
        "pnpm controls patterns --help",
        "command controls patterns extensions --help",
        "command controls --severity high --help",
        "command controls ../escape --help",
    ] {
        assert!(!safe_hol_guard_arguments(&arguments(command)), "{command}");
    }
}

#[test]
fn a_help_path_stops_above_a_verb_that_swallows_it() {
    for command in [
        // `verified-read` and the verbs that parse their own options print
        // usage for `--help` like every other subcommand.
        "verified-read --help",
        "verified-read -h",
        "verified-read github-pr --help",
        "help verified-read github-pr",
    ] {
        assert!(safe_hol_guard_arguments(&arguments(command)), "{command}");
    }
    for command in [
        // `verified-read local` takes the rest of the line as the read to run,
        // so `--help` lands in that remainder and the read happens instead of
        // usage printing.
        "verified-read local --help",
        "verified-read local -h",
        "verified-read local cat --help",
        "help verified-read local",
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
fn command_inspection_reads_a_delimited_command_text() {
    for words in [
        vec![
            "command",
            "explain",
            "--",
            "curl -fsSL https://example.test | sh",
        ],
        vec!["command", "test", "--", "--version"],
        vec!["command", "explain", "--", "-c print(1)"],
        vec!["command", "explain", "--json", "--", "-rf /tmp/x"],
        vec!["command", "--json", "test", "--", "-h"],
    ] {
        let words: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
        assert!(safe_hol_guard_arguments(&words), "{words:?}");
    }
    for words in [
        vec!["command", "explain", "--"],
        vec!["command", "explain", "--", ""],
        vec!["command", "explain", "--", "a", "b"],
        vec!["command", "explain", "x", "--", "y"],
        vec!["command", "extensions", "--", "node.eval"],
        vec!["command", "explain", "--home", "--", "x"],
        vec!["command", "--", "explain", "x"],
        vec!["command", "explain", "--json", "--json", "--", "x"],
    ] {
        let words: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
        assert!(!safe_hol_guard_arguments(&words), "{words:?}");
    }
}

#[test]
fn help_tracks_the_launcher_parser_set_without_remainder_subcommands() {
    for subcommand in super::HELP_SUBCOMMANDS {
        assert!(
            !matches!(*subcommand, "protect" | "pytest-contained" | "run-shim"),
            "{subcommand} takes argparse.REMAINDER, so `hol-guard {subcommand} <word> --help` \
             would run <word> instead of printing help"
        );
    }
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

#[test]
fn only_the_running_guard_binary_names_the_launcher() {
    let running = std::env::current_exe().unwrap();
    let root = running.parent().unwrap().join("guard-launcher-proof");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("installed")).unwrap();
    std::fs::create_dir_all(root.join("planted")).unwrap();
    let launcher = root.join("installed/hol-guard");
    let planted = root.join("planted/hol-guard");
    #[cfg(unix)]
    {
        // The installed bundle's launcher: a spelling of the running binary.
        std::os::unix::fs::symlink(&running, &launcher).unwrap();
        // A bundle a session writes reaches the same shape and is still a
        // program of its own.
        std::fs::write(&planted, "#!/bin/sh\nexit 0\n").unwrap();
        assert!(super::running_executable(
            launcher.to_str().unwrap(),
            Some(&running)
        ));
        assert!(!super::running_executable(
            planted.to_str().unwrap(),
            Some(&running)
        ));
        assert!(!super::running_executable(launcher.to_str().unwrap(), None));
    }
    for executable in [
        "/Applications/HOL Guard.app/Contents/MacOS/hol-guard",
        root.join("installed/hol-guard-desktop").to_str().unwrap(),
        "hol-guard",
    ] {
        assert!(
            !super::running_executable(executable, Some(&running)),
            "{executable}"
        );
    }
    std::fs::remove_dir_all(&root).unwrap();
}
