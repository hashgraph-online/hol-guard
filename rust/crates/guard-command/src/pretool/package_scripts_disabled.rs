//! Proof that a package install cannot run lifecycle scripts.
//!
//! With `--ignore-scripts` no lifecycle script runs, so the installed
//! `package_script` risk setting has nothing to govern. pnpm also loads the
//! project's pnpmfile unless `--ignore-pnpmfile` is set, and yarn runs its
//! configured release and plugins, so yarn never qualifies. The proof is
//! deliberately narrow: one plain install segment, no
//! environment prefix, no positional package names, no wrapper. The install
//! may follow a plain `cd <dir>` and feed a bounded `tail`/`head`, since
//! neither runs package code.

use crate::{parse_command, CommandModelRequestV1, CommandSegmentV1};

fn flag_disables_scripts(argument: &str) -> bool {
    matches!(argument, "--ignore-scripts" | "--ignore-scripts=true")
}

fn flag_reenables_scripts(argument: &str) -> bool {
    let lowered = argument.to_ascii_lowercase();
    matches!(
        lowered.as_str(),
        "--ignore-scripts=false"
            | "--ignore-scripts=0"
            | "--no-ignore-scripts"
            | "--scripts"
            | "--foreground-scripts"
            | "--foreground-scripts=true"
    ) || (lowered.starts_with("--ignore-scripts=") && lowered != "--ignore-scripts=true")
        || lowered.starts_with("--mode=")
}

/// True only for a lone `npm|pnpm|bun install|i|ci` with a flag that disables
/// lifecycle scripts, `--ignore-pnpmfile` for pnpm, and nothing that
/// re-enables them.
pub fn no_script_install_command(command: &str) -> bool {
    let Ok(model) = parse_command(&CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    }) else {
        return false;
    };
    if model.confidence != "exact"
        || model.uncertainty_reason.is_some()
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
    {
        return false;
    }
    let segments = model.segments.as_slice();
    let segments = match segments.split_first() {
        Some((first, rest)) if directory_change(first) => rest,
        _ => segments,
    };
    let segments = match segments.split_last() {
        Some((last, rest)) if output_filter(last) => rest,
        _ => segments,
    };
    let [segment] = segments else {
        return false;
    };
    if segment.pipeline_index != 0 {
        return false;
    }
    let Some(executable) = segment.executable.as_deref() else {
        return false;
    };
    let manager = executable.rsplit('/').next().unwrap_or(executable);
    if !matches!(manager, "npm" | "pnpm" | "bun")
        || !segment.environment_names.is_empty()
        || !segment.wrapper_chain.is_empty()
        || segment.path_overridden
        || segment.tokens.len() != segment.arguments.len() + 1
    {
        return false;
    }
    // A trailing `2>&1` only joins stderr to the install's own output.
    let arguments = match segment.arguments.split_last() {
        Some((last, rest))
            if last == "2>&1" && segment.tokens.last().map(String::as_str) == Some("2>&1") =>
        {
            rest
        }
        _ => segment.arguments.as_slice(),
    };
    let Some((subcommand, flags)) = arguments.split_first() else {
        return false;
    };
    if !matches!(subcommand.as_str(), "install" | "i" | "ci") {
        return false;
    }
    flags.iter().all(|flag| flag.starts_with("--"))
        && flags.iter().any(|flag| flag_disables_scripts(flag))
        && (manager != "pnpm" || flags.iter().any(|flag| flag == "--ignore-pnpmfile"))
        && !flags.iter().any(|flag| flag_reenables_scripts(flag))
}

/// True when some step runs `npm|pnpm|bun|yarn install|i|ci|add`. Only the
/// held-install advice uses this; it proves nothing about the command.
fn names_package_install(command: &str) -> bool {
    parse_command(&CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .is_ok_and(|model| {
        model.segments.iter().any(|segment| {
            let executable = segment.executable.as_deref().unwrap_or("");
            matches!(
                executable.rsplit('/').next(),
                Some("npm" | "pnpm" | "bun" | "yarn")
            ) && segment
                .arguments
                .first()
                .is_some_and(|verb| matches!(verb.as_str(), "install" | "i" | "ci" | "add"))
        })
    })
}

/// Whether the command in a PreTool payload has an install step.
pub fn held_command_installs(payload: &serde_json::Value) -> bool {
    super::generic::extract_untrusted_command_context(payload)
        .ok()
        .and_then(|context| context.command)
        .is_some_and(|command| names_package_install(&command))
}

fn plain(segment: &CommandSegmentV1) -> bool {
    segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && segment.tokens.len() == segment.arguments.len() + 1
}

fn directory_change(segment: &CommandSegmentV1) -> bool {
    plain(segment)
        && segment.pipeline_index == 0
        && segment.executable.as_deref() == Some("cd")
        && matches!(segment.arguments.as_slice(), [target] if super::safe_directory_target(target))
}

fn output_filter(segment: &CommandSegmentV1) -> bool {
    let count = |value: &str| {
        !value.is_empty() && value.len() <= 6 && value.bytes().all(|byte| byte.is_ascii_digit())
    };
    plain(segment)
        && segment.pipeline_index == 1
        && matches!(segment.executable.as_deref(), Some("tail" | "head"))
        && match segment.arguments.as_slice() {
            [value] => value.strip_prefix('-').is_some_and(count),
            [flag, value] => flag == "-n" && count(value),
            _ => false,
        }
}

#[cfg(test)]
mod tests {
    use super::{names_package_install, no_script_install_command};

    #[test]
    fn install_advice_follows_an_install_step() {
        for command in [
            "bun install --frozen-lockfile",
            "cd app && npm ci",
            "pnpm add left-pad",
            "yarn install && yarn build",
        ] {
            assert!(names_package_install(command), "{command}");
        }
        for command in [
            "bun scripts/report.ts --json",
            "REPORT_DIR=\"${TMPDIR:-/tmp}/x\" bun scripts/report.ts",
            "npm run build",
            "bun run install-hooks",
            "npx tsc --noEmit",
        ] {
            assert!(!names_package_install(command), "{command}");
        }
    }

    #[test]
    fn proves_only_the_plain_no_scripts_install_forms() {
        for command in [
            "bun install --frozen-lockfile --ignore-scripts",
            "npm ci --ignore-scripts",
            "npm install --ignore-scripts",
            "pnpm install --ignore-scripts --ignore-pnpmfile",
            "/usr/bin/npm ci --ignore-scripts=true",
            "cd /tmp/w/app && bun install --ignore-scripts",
            "cd /tmp/w/app && bun install --frozen-lockfile --ignore-scripts 2>&1 | tail -6",
            "bun install --ignore-scripts | head -n 20",
        ] {
            assert!(no_script_install_command(command), "{command}");
        }
        for command in [
            "bun install",
            "npm ci",
            "bun install --ignore-scripts=false",
            "bun install --ignore-scripts --ignore-scripts=false",
            "npm install --ignore-scripts --no-ignore-scripts",
            "npm install --ignore-scripts --foreground-scripts",
            "npm run build --ignore-scripts",
            "bun run build",
            "npm install left-pad --ignore-scripts",
            "npm install --ignore-scripts && npm run build",
            "bun install --ignore-scripts; rm x",
            "bun install --ignore-scripts | cat",
            "bun install --ignore-scripts | tail -f",
            "cd /tmp/w/app && bun install --frozen-lockfile 2>&1 | tail -5",
            "cd /tmp/w/app && npm run build && bun install --ignore-scripts",
            "cd $(id) && bun install --ignore-scripts",
            "cd /tmp/w/app /tmp/x && bun install --ignore-scripts",
            "tail -5 | bun install --ignore-scripts",
            "npm_config_ignore_scripts=false bun install --ignore-scripts",
            "FOO=1 bun install --ignore-scripts",
            "env FOO=1 bun install --ignore-scripts",
            "bun install --ignore-scripts > /tmp/w/out",
            "bun install --ignore-scripts $(id)",
            "npm install --mode=skip-build",
            "yarn install --mode=update-lockfile --ignore-scripts",
            "pip install --ignore-scripts",
            "pnpm install --ignore-scripts",
            "yarn install --ignore-scripts",
            "yarn install --mode=skip-build",
            "cd /tmp/w/app && pnpm install --ignore-scripts",
        ] {
            assert!(!no_script_install_command(command), "{command}");
        }
    }
}
