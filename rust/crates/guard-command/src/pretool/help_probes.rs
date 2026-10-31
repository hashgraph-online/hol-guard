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
//! The verbs in front of the flag are an allow-list rather than a shape,
//! because a manager verb that names a program to run hands the flag to that
//! program instead of printing its own usage: `uv run pytest --help` loads
//! every `conftest.py` the collection reaches. So `run`, `exec`, `x`, `dlx`
//! and `tool` are deliberately absent, and only the install-family verbs that
//! never name a program are listed.
//!
//! Deliberately absent:
//! - `yarn` and `pnpm`: Yarn's `yarnPath` and Corepack's `packageManager`
//!   field select a workspace-supplied binary that the probe would execute,
//!   for the same reason the version probe refuses them.
//! - `cargo` and `go`: a `rust-toolchain.toml` `path` or a `go.mod`
//!   `toolchain` line makes the launcher fetch and run a different toolchain.
//! - `git`: `git <verb> --help` opens the manual page through the configured
//!   pager, which runs a program the command never names.
//! - `npm help <verb>`: the `help` verb opens npm's configured viewer, which
//!   is `man` on Unix. Only the `--help` flag prints to stdout.
//! - `-h` for `docker`: it is `--hostname` on `docker run`, not help.

/// The managers whose usage text goes to stdout, and whether `-h` is their
/// own help flag rather than something else.
fn help_flag(basename: &str, flag: &str) -> bool {
    let short = match basename {
        "uv" | "uvx" | "pip" | "pip3" | "npm" | "bun" | "deno" | "ruff" | "black" | "mypy"
        | "rg" | "fd" | "jq" | "tsc" | "helm" => true,
        "docker" => false,
        _ => return false,
    };
    flag == "--help" || (short && flag == "-h")
}

/// A manager verb that names no program to run, so the help flag after it is
/// read by the manager itself.
fn usage_only_verb(verb: &str) -> bool {
    matches!(
        verb,
        "add"
            | "audit"
            | "build"
            | "check"
            | "ci"
            | "export"
            | "format"
            | "freeze"
            | "i"
            | "init"
            | "install"
            | "link"
            | "list"
            | "lock"
            | "ls"
            | "outdated"
            | "pip"
            | "prune"
            | "publish"
            | "remove"
            | "rm"
            | "search"
            | "show"
            | "sync"
            | "tree"
            | "uninstall"
            | "unlink"
            | "update"
            | "upgrade"
            | "venv"
            | "view"
            | "why"
    )
}

/// A lone help flag, or one behind at most two usage-only verbs.
pub(super) fn safe_help_probe(basename: &str, arguments: &[String]) -> bool {
    let Some((flag, verbs)) = arguments.split_last() else {
        return false;
    };
    help_flag(basename, flag)
        && verbs.len() <= 2
        && verbs.iter().all(|verb| usage_only_verb(verb))
}

#[cfg(test)]
mod tests {
    use super::safe_help_probe;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn install_family_usage_text_is_admitted() {
        for (tool, arguments) in [
            ("uv", vec!["add", "--help"]),
            ("uv", vec!["add", "-h"]),
            ("uv", vec!["pip", "install", "--help"]),
            ("uv", vec!["sync", "--help"]),
            ("uv", vec!["--help"]),
            ("npm", vec!["install", "--help"]),
            ("npm", vec!["i", "-h"]),
            ("pip", vec!["install", "--help"]),
            ("pip3", vec!["install", "-h"]),
            ("bun", vec!["add", "--help"]),
            ("deno", vec!["install", "--help"]),
            ("docker", vec!["build", "--help"]),
            ("ruff", vec!["check", "--help"]),
        ] {
            assert!(safe_help_probe(tool, &args(&arguments)), "{tool} {arguments:?}");
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
            ("bun", vec!["x", "--help"]),
            // The script, not the manager, reads the flag.
            ("uv", vec!["run", "script.py", "--help"]),
        ] {
            assert!(
                !safe_help_probe(tool, &args(&arguments)),
                "{tool} {arguments:?}"
            );
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
            // `-h` is `--hostname` on `docker run`.
            ("docker", vec!["build", "-h"]),
            // The flag has to be the last word; anything after it is an
            // operand the manager would act on.
            ("npm", vec!["install", "--help", "left-pad"]),
            ("uv", vec![]),
            ("npm", vec!["install"]),
        ] {
            assert!(
                !safe_help_probe(tool, &args(&arguments)),
                "{tool} {arguments:?}"
            );
        }
    }
}
