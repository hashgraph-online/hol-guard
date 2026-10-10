//! Guard's own read-only diagnostics.
//!
//! Agents routinely run these to learn why a command was paused. Only the bare
//! launcher and the exact argument shapes below are admitted, so repair, fix,
//! incident, uninstall, policy and other control subcommands keep the normal
//! review or critical-floor path.
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

pub(super) fn safe_hol_guard_segment(arguments: &[String], cwd: Option<&str>) -> bool {
    safe_hol_guard_arguments(arguments)
        && cwd.is_some_and(|cwd| !cwd_shadows_launcher(Path::new(cwd)))
}

fn cwd_shadows_launcher(cwd: &Path) -> bool {
    !cwd.is_absolute()
        || SHADOW_NAMES
            .iter()
            .any(|name| cwd.join(name).symlink_metadata().is_ok())
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
    )
}

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
        ] {
            assert!(!safe_hol_guard_arguments(&arguments(command)), "{command}");
        }
    }

    #[test]
    fn working_directory_launcher_or_unknown_cwd_keeps_review() {
        let workspace =
            std::env::temp_dir().join(format!("guard-diagnostics-shadow-{}", std::process::id()));
        std::fs::create_dir_all(&workspace).unwrap();
        let cwd = workspace.to_str().unwrap().to_owned();
        let status = arguments("status");
        assert!(safe_hol_guard_segment(&status, Some(&cwd)));
        assert!(!safe_hol_guard_segment(&status, None));
        assert!(!safe_hol_guard_segment(&status, Some("relative/dir")));
        std::fs::write(workspace.join("hol-guard"), "#!/bin/sh\n").unwrap();
        let shadowed = safe_hol_guard_segment(&status, Some(&cwd));
        std::fs::remove_dir_all(&workspace).unwrap();
        assert!(!shadowed);
    }
}
