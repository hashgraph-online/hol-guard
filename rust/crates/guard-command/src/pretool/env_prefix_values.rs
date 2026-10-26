//! Whether [`super::project`] removed a value the command reads for itself.
//!
//! The projection removes two kinds of setting. Presentation, locale and
//! quieting settings cannot change what a command does, so the command
//! without them is the command that runs, wherever it runs. An ordinary
//! project setting (`FOO=1`, `NODE_ENV=test`) is a value the program may
//! read. Dropping it is sound only for a verdict that runs the full text on
//! the host, an exact proof. Contained execution would run the projected
//! command without the value, so such a verdict goes to the reviewed
//! projection, which knows which profiles drop or carry settings.

use super::{assignment, inert_assignment, shell_assignment, COMMAND_SEPARATORS};
use crate::cloud_scrub_shell::shell_tokens;

/// True when a leading setting of any simple command in `command` is not
/// inert. Text that does not tokenize counts as carrying a value.
pub(in crate::pretool::generic) fn removes_values(command: &str) -> bool {
    let chars: Vec<char> = command.chars().collect();
    let Some(tokens) = shell_tokens(&chars) else {
        return true;
    };
    let mut prefix = true;
    let mut unset_name = false;
    for token in &tokens {
        if token.is_control {
            prefix = COMMAND_SEPARATORS.contains(&token.value.as_str());
            unset_name = false;
            continue;
        }
        // `env -u NAME` removes a name; it never passes a value.
        if !prefix || std::mem::take(&mut unset_name) {
            continue;
        }
        let value = token.value.as_str();
        match shell_assignment(&chars, token).or_else(|| assignment(token)) {
            Some((name, assigned)) if !inert_assignment(name, assigned) => return true,
            Some(_) => {}
            None if value == "env" || value == "/usr/bin/env" => {}
            None if value == "-u" || value == "--unset" => unset_name = true,
            None if value.starts_with('-') => {}
            None => prefix = false,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::removes_values;

    #[test]
    fn inert_settings_carry_no_value() {
        for command in [
            "LC_ALL=C ls src",
            "NO_COLOR=1 bunx vitest run x | tail -20",
            "bunx vitest run x | FORCE_COLOR=0 tail -20",
            "env -u GH_TOKEN -- git status",
            "env --unset=GH_TOKEN GIT_PAGER=cat git log -3",
            "GH_TOKEN= gh repo view o/r",
            "ls FOO=1",
            "npm --prefix ../sibling run build",
        ] {
            assert!(!removes_values(command), "{command}");
        }
    }

    #[test]
    fn ordinary_settings_carry_a_value() {
        for command in [
            "FOO=1 npm --prefix ../sibling run build",
            "bunx vitest run x | FOO=1 tail -20",
            "FOO=1 bunx vitest run x | tail -20",
            "git status && NODE_ENV=test node --test",
            "env NODE_ENV=test ls",
            "env -u GH_TOKEN FOO=1 ls",
            "LC_ALL=C LOG_LEVEL=debug ls src",
        ] {
            assert!(removes_values(command), "{command}");
        }
    }
}
