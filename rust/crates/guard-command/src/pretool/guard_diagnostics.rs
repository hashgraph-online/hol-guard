//! Guard's own read-only diagnostics.
//!
//! Agents routinely run these to learn why a command was paused. Only the bare
//! launcher and the exact argument shapes below are admitted, so repair, fix,
//! incident, uninstall, policy and other control subcommands keep the normal
//! review or critical-floor path.

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
    use super::safe_hol_guard_arguments;

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
            "policy disable",
            "clear --all",
            "capability consume",
            "--home /tmp status",
            "status --home /tmp",
        ] {
            assert!(!safe_hol_guard_arguments(&arguments(command)), "{command}");
        }
    }
}
