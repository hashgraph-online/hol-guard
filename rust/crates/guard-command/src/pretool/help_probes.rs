//! Package-manager usage text: `uv add --help`, `npm install --help`.
//!
//! A help flag makes these programs print their own usage and exit before the
//! verb in front of it resolves a name, contacts a registry, downloads an
//! archive or writes a lockfile. Nothing is installed, so the command is the
//! same kind of question as the version probe next door.
//!
//! The probe still executes the named binary, so it keeps the identity rule
//! the other bare-name probes use: only a bare basename with no path
//! separator, no environment prefix and no wrapper reaches this proof, and
//! [`super::segment_proof::exact_safe_segment_with_context`] enforces those
//! preconditions before it asks.
//!
//! The verb in front of the flag is read against the manager that owns it,
//! never a shared list, because the same word means different things to
//! different launchers: `uv run pytest --help` loads every `conftest.py` the
//! collection reaches, `bun check --help` runs the workspace's `check`
//! script, and `helm audit --help` dispatches to a plugin of that name. So
//! each manager admits only verbs that are its own built-ins and that name no
//! program to run.
//!
//! Deliberately absent:
//! - `uvx`: it is `uv tool run`, so its first word is a package to fetch and
//!   execute. `uvx build --help` runs `build` from the index.
//! - `bun`: `bun <word>` falls back to `bun run <word>`, which runs the
//!   workspace's `package.json` script or a file of that name.
//! - `helm`: a plugin whose name matches the verb takes the command, so the
//!   usage text would come from a binary the command never names.
//! - `docker`: `docker --help` lists CLI plugins, and it discovers them by
//!   executing each one's metadata command.
//! - `yarn` and `pnpm`: Yarn's `yarnPath` and Corepack's `packageManager`
//!   field select a workspace-supplied binary that the probe would execute,
//!   for the same reason the version probe refuses them.
//! - `cargo` and `go`: a `rust-toolchain.toml` `path` or a `go.mod`
//!   `toolchain` line makes the launcher fetch and run a different toolchain.
//! - `git`: `git <verb> --help` opens the manual page through the configured
//!   pager, which runs a program the command never names.
//! - `npm help <verb>`: the `help` verb opens npm's configured viewer, which
//!   is `man` on Unix. Only the `--help` flag prints to stdout.
//! - `npm init` and `npm create`: they resolve a `create-*` package and run
//!   it, so the word after them is a program.

/// The tools whose usage text goes to stdout, with `-h` as their own help
/// flag rather than something else.
fn help_flag(basename: &str, flag: &str) -> bool {
    matches!(
        basename,
        "uv" | "pip"
            | "pip3"
            | "npm"
            | "deno"
            | "ruff"
            | "black"
            | "mypy"
            | "rg"
            | "fd"
            | "jq"
            | "tsc"
    ) && matches!(flag, "--help" | "-h")
}

/// A built-in verb of this manager that names no program to run, so the help
/// flag after it is read by the manager itself.
fn usage_only_verb(basename: &str, verb: &str) -> bool {
    match basename {
        "uv" => matches!(
            verb,
            "add"
                | "build"
                | "cache"
                | "export"
                | "init"
                | "install"
                | "lock"
                | "pip"
                | "publish"
                | "python"
                | "remove"
                | "sync"
                | "tree"
                | "uninstall"
                | "venv"
                | "version"
        ),
        "pip" | "pip3" => matches!(
            verb,
            "cache"
                | "check"
                | "config"
                | "download"
                | "freeze"
                | "index"
                | "inspect"
                | "install"
                | "list"
                | "show"
                | "uninstall"
                | "wheel"
        ),
        // npm resolves its own aliases from a table it carries, so `add` is
        // `install` and `info` is `view` before anything else happens. The
        // names below are those aliases, each standing for a verb this arm
        // already admits. The three npm aliases that name a program to run
        // stay out with the verbs they point at: `create` is `init`, `x` is
        // `exec`, and `run` is `run-script`.
        "npm" => matches!(
            verb,
            "add"
                | "audit"
                | "ci"
                | "clean-install"
                | "ddp"
                | "dedupe"
                | "explain"
                | "i"
                | "ic"
                | "in"
                | "info"
                | "install"
                | "la"
                | "link"
                | "list"
                | "ll"
                | "ln"
                | "ls"
                | "outdated"
                | "pkg"
                | "prune"
                | "publish"
                | "r"
                | "remove"
                | "rm"
                | "show"
                | "un"
                | "uninstall"
                | "unlink"
                | "up"
                | "update"
                | "v"
                | "view"
                | "why"
        ),
        "deno" => matches!(
            verb,
            "add"
                | "check"
                | "fmt"
                | "info"
                | "install"
                | "lint"
                | "outdated"
                | "publish"
                | "remove"
                | "uninstall"
                | "upgrade"
        ),
        "ruff" => matches!(verb, "check" | "clean" | "config" | "format" | "linter"),
        // The single-purpose tools take no verb at all.
        _ => false,
    }
}

/// Whether this manager's startup reads a configuration the session could
/// have pointed elsewhere. npm and pip both load their configuration before
/// they print usage, so the probe asks for the whole proof the read listings
/// next door require, files included: npm runs an `onload-script` and honours
/// a redirected `userconfig` while it is still working out what to print, so
/// an environment that merely leaves the names alone is not enough.
pub(super) fn configuration_inert(basename: &str, context: super::PathContext<'_>) -> bool {
    match basename {
        "npm" => {
            context.npm_config_inert
                && context.shell_home_matches
                && super::npm_reads::configuration_inert(context)
        }
        "pip" | "pip3" => {
            context.pip_config_inert
                && context.shell_home_matches
                && super::pip_reads::configuration_inert(context)
        }
        _ => true,
    }
}

/// A lone help flag, or one behind at most two of the manager's own
/// usage-only verbs.
///
/// npm's and pip's admission also needs the files
/// [`configuration_inert`] reads, which no unit context names a directory
/// for, so their verbs are proved in the benign gate's fixture home.
/// `tests/fixtures/benign_false_positive_gate.json` carries the alias rows.
pub(super) fn safe_help_probe(
    basename: &str,
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    let Some((flag, verbs)) = arguments.split_last() else {
        return false;
    };
    help_flag(basename, flag)
        && verbs.len() <= 2
        && verbs.iter().all(|verb| usage_only_verb(basename, verb))
        && configuration_inert(basename, context)
}

#[cfg(test)]
mod tests {
    use super::safe_help_probe;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn context() -> super::super::PathContext<'static> {
        super::super::PathContext {
            npm_config_inert: true,
            pip_config_inert: true,
            ..Default::default()
        }
    }

    /// npm and pip read files this context names no directory for, so the
    /// shape tests below carry the managers whose usage text needs no proof
    /// beyond their own words. The two whose startup reads a configuration
    /// are admitted by the benign gate instead, where a fixture home holds
    /// the files the proof reads.
    #[test]
    fn a_configuration_the_session_can_write_refuses_the_probe() {
        let root = std::env::temp_dir().join(format!("guard-help-npmrc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("home");
        let project = root.join("project");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        // npm requires this file while it is still working out what to print.
        std::fs::write(project.join(".npmrc"), "onload-script=./onload.js\n").unwrap();
        let home = home.to_string_lossy().into_owned();
        let project = project.to_string_lossy().into_owned();
        let written = super::super::PathContext {
            npm_config_inert: true,
            pip_config_inert: true,
            shell_home_matches: true,
            home_dir: Some(&home),
            cwd: Some(&project),
            ..Default::default()
        };

        assert!(!safe_help_probe(
            "npm",
            &args(&["install", "--help"]),
            written
        ));
        // The refusal is the file, not the shape: a manager that reads no
        // configuration prints its usage from the same directory.
        assert!(safe_help_probe("jq", &args(&["--help"]), written));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn install_family_usage_text_is_admitted() {
        for (tool, arguments) in [
            ("uv", vec!["add", "--help"]),
            ("uv", vec!["add", "-h"]),
            ("uv", vec!["pip", "install", "--help"]),
            ("uv", vec!["sync", "--help"]),
            ("uv", vec!["--help"]),
            ("deno", vec!["install", "--help"]),
            ("ruff", vec!["check", "--help"]),
            ("jq", vec!["--help"]),
        ] {
            assert!(
                safe_help_probe(tool, &args(&arguments), context()),
                "{tool} {arguments:?}"
            );
        }
    }

    #[test]
    fn verbs_that_name_a_program_to_run_are_refused() {
        for (tool, arguments) in [
            // The flag reaches pytest, which loads the workspace's conftest.
            ("uv", vec!["run", "pytest", "--help"]),
            ("uv", vec!["run", "--help"]),
            ("uv", vec!["tool", "run", "--help"]),
            ("npm", vec!["exec", "--help"]),
            ("npm", vec!["run", "test", "--help"]),
            // `npm init <name>` resolves and runs a `create-*` package.
            ("npm", vec!["init", "--help"]),
            // npm's own aliases for those three verbs point at the same
            // programs, so they are refused with them.
            ("npm", vec!["create", "--help"]),
            ("npm", vec!["x", "--help"]),
            // `uvx` is `uv tool run`: the verb is a package to fetch and run.
            ("uvx", vec!["build", "--help"]),
            ("uvx", vec!["pip", "--help"]),
            ("uvx", vec!["--help"]),
            // The script, not the manager, reads the flag.
            ("uv", vec!["run", "script.py", "--help"]),
        ] {
            assert!(
                !safe_help_probe(tool, &args(&arguments), context()),
                "{tool} {arguments:?}"
            );
        }
    }

    /// npm's own admission also reads its configuration, which this unit
    /// context names no directory for, so the shape test above cannot tell a
    /// refused verb from a refused configuration. The verb list answers for
    /// itself here: every word npm resolves to a package or a script stays
    /// out of it, whatever the configuration proof later decides.
    #[test]
    fn npm_verbs_that_run_a_program_stay_out_of_the_usage_list() {
        for verb in ["create", "x", "exec", "run", "run-script", "init"] {
            assert!(!super::usage_only_verb("npm", verb), "npm {verb}");
        }
        // The aliases that only print usage are still in it.
        for verb in [
            "add",
            "remove",
            "un",
            "in",
            "up",
            "info",
            "ln",
            "clean-install",
        ] {
            assert!(super::usage_only_verb("npm", verb), "npm {verb}");
        }
    }

    #[test]
    fn workspace_selected_launchers_and_pagers_are_refused() {
        for (tool, arguments) in [
            ("yarn", vec!["add", "--help"]),
            ("pnpm", vec!["add", "--help"]),
            ("cargo", vec!["add", "--help"]),
            ("go", vec!["install", "--help"]),
            ("git", vec!["commit", "--help"]),
            ("poetry", vec!["add", "--help"]),
            // `bun <word>` falls back to running that script or file.
            ("bun", vec!["add", "--help"]),
            ("bun", vec!["check", "--help"]),
            ("bun", vec!["init", "-h"]),
            // A plugin of the same name takes the command.
            ("helm", vec!["audit", "--help"]),
            // Help discovers Docker's CLI plugins by executing them.
            ("docker", vec!["build", "--help"]),
            ("docker", vec!["--help"]),
            // The flag has to be the last word; anything after it is an
            // operand the manager would act on.
            ("npm", vec!["install", "--help", "left-pad"]),
            ("uv", vec![]),
            ("npm", vec!["install"]),
        ] {
            assert!(
                !safe_help_probe(tool, &args(&arguments), context()),
                "{tool} {arguments:?}"
            );
        }
    }

    #[test]
    fn a_verb_belonging_to_another_manager_is_refused() {
        for (tool, arguments) in [
            // `npm sync` and `npm venv` are not npm commands; admitting them
            // from a shared list is what let a launcher's fallback through.
            ("npm", vec!["sync", "--help"]),
            ("npm", vec!["venv", "--help"]),
            ("pip", vec!["add", "--help"]),
            ("deno", vec!["sync", "--help"]),
            ("ruff", vec!["install", "--help"]),
            // The single-purpose tools take no verb at all.
            ("jq", vec!["install", "--help"]),
            ("rg", vec!["check", "--help"]),
        ] {
            assert!(
                !safe_help_probe(tool, &args(&arguments), context()),
                "{tool} {arguments:?}"
            );
        }
    }

    #[test]
    fn a_redirected_manager_configuration_keeps_the_question() {
        let npm_moved = super::super::PathContext {
            pip_config_inert: true,
            ..Default::default()
        };
        assert!(!safe_help_probe(
            "npm",
            &args(&["install", "--help"]),
            npm_moved
        ));
        let pip_moved = super::super::PathContext {
            npm_config_inert: true,
            ..Default::default()
        };
        assert!(!safe_help_probe(
            "pip",
            &args(&["install", "--help"]),
            pip_moved
        ));
        // A tool with no configuration of its own is unaffected.
        assert!(safe_help_probe("jq", &args(&["--help"]), pip_moved));
    }
}
