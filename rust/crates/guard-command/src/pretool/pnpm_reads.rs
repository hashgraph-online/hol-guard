//! Read-only pnpm queries: `pnpm outdated`, `pnpm view`/`pnpm info` and
//! `pnpm audit`.
//!
//! These are the same three registry reports [`super::npm_reads`] proves for
//! npm, over the same configuration. `outdated` reads the project manifest and
//! the lockfile and asks the registry for the published versions of the names
//! already there, `view` prints one package's public metadata, and `audit`
//! sends those same installed names and versions to the advisory endpoint.
//! None resolves a new tree, writes to the project or runs package code, so a
//! report that a dependency moved on stays a report.
//!
//! pnpm reads `.npmrc` through npm's own configuration loader, so the proof is
//! npm's: every `.npmrc` pnpm could read has to leave the registry, its trust
//! and npm's paths alone, and no inherited npm or Node variable may move them
//! either. That check already refuses a `pnpmfile` or `global-pnpmfile` line,
//! which is how a configuration file names pnpm's hook module.
//!
//! A project may also carry that hook module at its default name. pnpm loads
//! `.pnpmfile.cjs` from the directory holding the lockfile, and the hooks in
//! it are ordinary JavaScript pnpm runs in its own process, so the reading
//! needs no such file above the working directory. A workspace that keeps one
//! stays reviewed.
//!
//! Still reviewed:
//! - every other subcommand. `install`, `add`, `update`, `dlx` and `patch`
//!   resolve or run code, `store` and `prune` rewrite the store, and `publish`
//!   sends the project to a registry.
//! - `--dir`, `--filter`, `--workspace-root` and `-w`, which choose another
//!   project or another set of them, and `--registry`, which moves the fetch
//!   the configuration check just pinned.
//! - `audit --fix`, which rewrites the manifest, and any operand on it.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

pub(super) fn safe_pnpm_read(arguments: &[String], context: super::PathContext<'_>) -> bool {
    let Some((subcommand, rest)) = arguments.split_first() else {
        return false;
    };
    let shape = match subcommand.as_str() {
        "outdated" => outdated_arguments(rest),
        "view" | "info" => super::npm_reads::view_arguments(rest),
        "audit" => audit_arguments(rest),
        _ => false,
    };
    shape
        && context.npm_config_inert
        && context.shell_home_matches
        && super::npm_reads::configuration_inert(context)
        && hook_module_absent(context)
}

/// The report over the installed names. `--recursive` widens it to every
/// package of a workspace already on disk, which is the same read repeated,
/// and `--global` reads the tree at pnpm's own prefix, which the `.npmrc`
/// check has already pinned.
fn outdated_arguments(arguments: &[String]) -> bool {
    arguments.iter().all(|argument| {
        matches!(
            argument.as_str(),
            "--json"
                | "--long"
                | "--compatible"
                | "--no-table"
                | "--table"
                | "--recursive"
                | "-r"
                | "--global"
                | "-g"
        ) || matches!(
            argument.strip_prefix("--format="),
            Some("table" | "list" | "json")
        ) || super::npm_reads::plain_registry_spec(argument)
    })
}

/// The advisory report. pnpm writes the severity bound either way, so both
/// spellings are read, and the value has to be one of the levels pnpm names.
/// `--fix` rewrites the manifest, so it is not among them, and the command
/// takes no operand.
fn audit_arguments(arguments: &[String]) -> bool {
    let mut remaining = arguments.iter();
    while let Some(argument) = remaining.next() {
        let accepted = matches!(
            argument.as_str(),
            "--json"
                | "--recursive"
                | "-r"
                | "--dev"
                | "-D"
                | "--prod"
                | "-P"
                | "--no-optional"
                | "--ignore-registry-errors"
        ) || matches!(
            argument.strip_prefix("--audit-level="),
            Some("info" | "low" | "moderate" | "high" | "critical")
        );
        if accepted {
            continue;
        }
        if argument == "--audit-level" {
            let level = remaining.next().map(String::as_str);
            if matches!(
                level,
                Some("info" | "low" | "moderate" | "high" | "critical")
            ) {
                continue;
            }
        }
        return false;
    }
    true
}

/// No `.pnpmfile.cjs` at or above the working directory, by both the written
/// path and the physical one, so a link in the walked path cannot hide a file
/// pnpm would still find.
fn hook_module_absent(context: super::PathContext<'_>) -> bool {
    let Some(cwd) = context.cwd.map(Path::new) else {
        return false;
    };
    if !cwd.is_absolute() {
        return false;
    }
    let Ok(physical) = fs::canonicalize(cwd) else {
        return false;
    };
    cwd.ancestors()
        .chain(physical.ancestors())
        .all(|directory| nothing_at(&directory.join(".pnpmfile.cjs")))
}

/// Absence is the one error that answers the question. Any other means the
/// path was not read, which is not a reading that it holds nothing.
fn nothing_at(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(_) => false,
        Err(error) => error.kind() == ErrorKind::NotFound,
    }
}

#[cfg(test)]
#[path = "pnpm_reads_tests.rs"]
mod tests;
