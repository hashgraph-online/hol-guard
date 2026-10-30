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
        "approvals --json list",
        "approvals --json wait req-1",
        "approvals wait req-1 --json --timeout 300",
        "approvals --json wait req-1 --timeout 300",
        "approvals wait --timeout 300 req-1",
        "approvals wait --timeout 300 req-1 --json",
        "approvals --json retry-hint req-1",
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
        "approvals wait --timeout 300",
        "approvals wait --timeout 300 --home",
        "approvals wait --timeout 601 req-1",
        "approvals wait --json --timeout 300 req-1 req-2",
        "approvals --json wait req-1 --json",
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
fn explain_reads_one_artifact_or_local_path() {
    for command in [
        "explain install-connect",
        "explain codex.plugin-7",
        "explain /tmp/project",
        "explain /tmp/project/src/index.ts",
        "explain ./src/index.ts",
        "explain --json /tmp/project",
        "explain /tmp/project --json",
        "explain /tmp/project --cisco-mode off",
        "explain --cisco-mode on /tmp/project",
        "explain --json /tmp/project --cisco-mode auto",
        "explain /tmp/project --cisco-mode auto --json",
        "explain --help",
        "help explain",
    ] {
        assert!(safe_hol_guard_arguments(&arguments(command)), "{command}");
    }

    for command in [
        "explain",
        "explain --json",
        "explain -x",
        "explain --cisco-mode off",
        "explain /tmp/project /tmp/other",
        "explain /tmp/project --cisco-mode",
        "explain /tmp/project --cisco-mode deep",
        "explain --json --json /tmp/project",
        "explain /tmp/project --home /tmp/elsewhere",
        "explain --guard-home /tmp/elsewhere /tmp/project",
        "explain /tmp/project --workspace /tmp/elsewhere",
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

#[cfg(unix)]
#[test]
fn an_installed_guard_program_names_the_launcher_and_a_stray_file_does_not() {
    let context = super::super::PathContext {
        home_dir: Some("/Users/u"),
        cwd: Some("/Users/u/projects/app"),
        ..Default::default()
    };
    // The spellings real waits arrive with: the desktop bundle, Guard's own
    // home, and the virtual environment Guard was installed into.
    for executable in [
        "/Applications/HOL Guard.app/Contents/MacOS/hol-guard",
        "/Users/u/.hol-guard/bin/hol-guard",
        "~/.hol-guard/bin/hol-guard",
        "/Users/u/.local/bin/hol-guard",
        "/Users/u/.local/pipx/venvs/hol-guard/bin/hol-guard",
        "/Users/u/.local/share/uv/tools/hol-guard/bin/hol-guard",
        "/opt/homebrew/bin/hol-guard",
        "/usr/local/bin/hol-guard",
    ] {
        assert!(
            super::guard_install_executable(executable, context),
            "{executable}"
        );
    }
    for executable in [
        // A file a session leaves somewhere of its own is not an install.
        "/tmp/stage/hol-guard",
        "/Users/u/projects/hol-guard-pr-12/hol-guard",
        "./hol-guard",
        // A relative spelling resolves against the directory the agent
        // writes, so a `bin` a clone or an archive left there would run
        // without review.
        "bin/hol-guard",
        "./bin/hol-guard",
        "scripts/hol-guard",
        "tools/hol-guard.exe",
        // The same file reached by its absolute spelling inside the
        // workspace, and by walking back out of one.
        "/Users/u/projects/app/bin/hol-guard",
        "/Users/u/projects/app/vendor/opt/hol-guard",
        "/Users/u/projects/app/../app/bin/hol-guard",
        "~/projects/app/bin/hol-guard",
        // An install root is a place an install is written to, not any
        // directory that happens to carry an install-shaped component. A
        // checkout's own `bin` is reached from a subdirectory of that
        // checkout, or from a sibling one, without ever leaving the trees
        // the agent writes, and the write that put the file there named no
        // Guard location, so nothing reviewed it.
        "/Users/u/projects/bin/hol-guard",
        "/Users/u/projects/other/bin/hol-guard",
        "/Users/u/work/venv/bin/hol-guard",
        "/Users/u/Downloads/release/bin/hol-guard",
        "/srv/build/tools/hol-guard",
        "C:\\Users\\u\\projects\\other\\bin\\hol-guard.exe",
        // The desktop application itself is not the read-only CLI.
        "/Applications/HOL Guard.app/Contents/MacOS/hol-guard-desktop",
        // The bare name reaches the admission arm without this screen.
        "hol-guard",
    ] {
        assert!(
            !super::guard_install_executable(executable, context),
            "{executable}"
        );
    }
    // Without a working directory to place the spelling against, nothing is
    // anchored, so every path keeps its review.
    assert!(!super::guard_install_executable(
        "/opt/homebrew/bin/hol-guard",
        super::super::PathContext::default()
    ));
}

#[cfg(unix)]
#[test]
fn a_component_naming_no_directory_cannot_walk_back_into_the_workspace() {
    // The checkout sits directly below an install root, so the spelling the
    // agent writes is one detour away from a root that would admit it.
    let context = super::super::PathContext {
        home_dir: Some("/Users/u"),
        cwd: Some("/opt/project"),
        ..Default::default()
    };
    assert!(!super::guard_install_executable(
        "/opt/project/bin/hol-guard",
        context
    ));
    for detour in [
        "/opt/./project/bin/hol-guard",
        "/opt//project/bin/hol-guard",
        "/opt/project/./bin/hol-guard",
        "/opt/project/bin/./hol-guard",
    ] {
        assert!(
            !super::guard_install_executable(detour, context),
            "{detour}"
        );
    }
    // The same detour spelling of a genuine install root is refused too: the
    // proof reads the spelling it was handed rather than resolving it.
    assert!(!super::guard_install_executable(
        "/usr/./local/bin/hol-guard",
        context
    ));
}

#[cfg(windows)]
#[test]
fn an_installed_guard_program_names_the_launcher_on_windows() {
    let context = super::super::PathContext {
        home_dir: Some("C:\\Users\\u"),
        cwd: Some("C:\\Users\\u\\projects\\app"),
        ..Default::default()
    };
    for executable in [
        "C:\\Program Files\\HOL Guard\\hol-guard.exe",
        "C:\\ProgramData\\hol-guard\\bin\\hol-guard.exe",
        "C:\\Users\\u\\AppData\\Local\\Programs\\HOL Guard\\hol-guard.exe",
        "C:\\Users\\u\\AppData\\Local\\pipx\\pipx\\venvs\\hol-guard\\Scripts\\hol-guard.exe",
        "C:\\Users\\u\\AppData\\Roaming\\uv\\tools\\hol-guard\\Scripts\\hol-guard.exe",
    ] {
        assert!(
            super::guard_install_executable(executable, context),
            "{executable}"
        );
    }
    for executable in [
        // `%LOCALAPPDATA%\Temp` is where a session's own scratch files land,
        // so a `bin` unpacked there is the Windows spelling of `/tmp/stage`.
        "C:\\Users\\u\\AppData\\Local\\Temp\\clone\\bin\\hol-guard.exe",
        "C:\\Users\\u\\AppData\\Local\\Temp\\hol-guard\\hol-guard.exe",
        "C:\\Users\\u\\projects\\other\\bin\\hol-guard.exe",
        "C:\\Users\\u\\projects\\app\\bin\\hol-guard.exe",
        "C:\\Users\\u\\projects\\app\\.\\bin\\hol-guard.exe",
        "bin\\hol-guard.exe",
        "hol-guard.exe",
    ] {
        assert!(
            !super::guard_install_executable(executable, context),
            "{executable}"
        );
    }
}

#[cfg(unix)]
#[test]
fn an_application_root_admits_guards_own_directory_and_no_sibling() {
    let context = super::super::PathContext {
        home_dir: Some("/Users/u"),
        cwd: Some("/Users/u/projects/app"),
        ..Default::default()
    };
    for executable in [
        "/Applications/HOL Guard.app/Contents/MacOS/hol-guard",
        "/Applications/hol-guard/bin/hol-guard",
        "/Users/u/Applications/HOL Guard.app/Contents/MacOS/hol-guard",
    ] {
        assert!(
            super::guard_install_executable(executable, context),
            "{executable}"
        );
    }
    // A directory below an application root belongs to whoever wrote it. A
    // checkout unpacked there carries its own `bin`, which the location
    // screen reads as an install, so the root has to name Guard's directory
    // rather than admit every sibling of it.
    for executable in [
        "/Applications/demo/bin/hol-guard",
        "/Applications/Some Vendor/tools/hol-guard",
        "/Users/u/Applications/demo/bin/hol-guard",
    ] {
        assert!(
            !super::guard_install_executable(executable, context),
            "{executable}"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_component_windows_would_trim_cannot_reach_the_workspace() {
    // Windows opens `app.\bin` as `app\bin`, so a spelling carrying the dot
    // names the workspace's own directory while missing the prefix that
    // refuses it. The reading here is the spelling's, on every platform.
    let context = super::super::PathContext {
        home_dir: Some("/Users/u"),
        cwd: Some("/Users/u/Library/Application Support/app"),
        ..Default::default()
    };
    for detour in [
        "/Users/u/Library/Application Support/app./bin/hol-guard",
        "/Users/u/Library/Application Support/app /bin/hol-guard",
        "/Users/u/Library/Application Support/app/bin./hol-guard",
        // A short name is another spelling the prefix comparison cannot read.
        "/Users/u/Library/Applic~1/app/bin/hol-guard",
    ] {
        assert!(
            !super::guard_install_executable(detour, context),
            "{detour}"
        );
    }
    assert!(super::guard_install_executable(
        "/Users/u/Library/Application Support/hol-guard/bin/hol-guard",
        context
    ));
}

#[cfg(unix)]
#[test]
fn a_batch_launcher_is_not_an_installed_guard_program() {
    // The desktop PATH shim is a real spelling of the launcher, and `cmd.exe`
    // reads a batch target's arguments a second time. `command test <text>`
    // carries the operators that second reading would act on, so the shim
    // keeps its review instead of the admission the executable gets.
    let context = super::super::PathContext {
        home_dir: Some("/Users/u"),
        cwd: Some("/Users/u/projects/app"),
        ..Default::default()
    };
    for executable in [
        "/Users/u/.hol-guard/bin/hol-guard.cmd",
        "/Users/u/.local/bin/hol-guard.bat",
    ] {
        assert!(
            !super::guard_install_executable(executable, context),
            "{executable}"
        );
    }
    assert!(super::guard_install_executable(
        "/Users/u/.hol-guard/bin/hol-guard.exe",
        context
    ));
}

#[cfg(windows)]
#[test]
fn a_checkout_below_an_application_root_keeps_its_review_on_windows() {
    let context = super::super::PathContext {
        home_dir: Some("C:\\Users\\u"),
        cwd: Some("C:\\Users\\u\\projects\\app"),
        ..Default::default()
    };
    for executable in [
        // `Programs` holds one directory per installer. A checkout written
        // beside them carries a `bin` the location screen reads as an install.
        "C:\\Users\\u\\AppData\\Local\\Programs\\demo\\bin\\hol-guard.exe",
        "C:\\Program Files\\demo\\bin\\hol-guard.exe",
        "C:\\ProgramData\\demo\\bin\\hol-guard.exe",
        // Windows trims a trailing dot before it opens the directory, so this
        // spelling reaches the workspace's own `bin` while missing its prefix.
        "C:\\Users\\u\\AppData\\Roaming\\proj.\\bin\\hol-guard.exe",
        "C:\\Users\\u\\AppData\\Roaming\\PROGRA~1\\bin\\hol-guard.exe",
        // A batch target is re-read by `cmd.exe` after it is spawned.
        "C:\\Program Files\\HOL Guard\\hol-guard.cmd",
    ] {
        assert!(
            !super::guard_install_executable(executable, context),
            "{executable}"
        );
    }
}
