//! Which local tool a contained node-tool command runs, and in which mode.
//!
//! The spellings a command uses are peeled elsewhere; this is the table they
//! all land on. Each supported tool is named with the entrypoints its
//! published versions install, so the sink resolves the files for the tool
//! native authority chose rather than looking the tool up a second time.
//!
//! The mode gate answers the other half: `tsc` emitting nothing, `vite
//! build`, and Prettier in a checking mode are the runs a read-only or
//! build-output profile can carry. `tsc` is the only one whose answer is not
//! on the command line, because a generated project keeps the no-emit mode
//! in the file instead.

use std::path::Path;

use super::ToolMode;

/// Prettier publishes one entrypoint per major, and version 2 remains common
/// enough to name: Prettier 3 moved its executable into `bin/`.
pub(crate) const PRETTIER_ENTRIES: [&str; 2] =
    ["prettier/bin/prettier.cjs", "prettier/bin-prettier.js"];

/// Every supported tool and the entrypoints its published versions install.
/// A tool that publishes one entrypoint per major is installed under
/// whichever spelling its version uses, so every spelling is named and the
/// caller keeps the one the nearest project installs.
const TOOL_ENTRIES: &[(&str, &[&str])] = &[
    ("eslint", &["eslint/bin/eslint.js"]),
    ("tsc", &["typescript/bin/tsc"]),
    ("vite", &["vite/bin/vite.js"]),
    ("prettier", &PRETTIER_ENTRIES),
];

/// A local file path with a `node_modules` component naming one tool's
/// published entrypoint: `node_modules/<entry>`, `./node_modules/<entry>` or
/// `<dir>/node_modules/<entry>`.
pub(crate) fn local_package_entry(entry: &str, package_entry: &str) -> bool {
    entry
        .strip_suffix(package_entry)
        .and_then(|prefix| prefix.strip_suffix("node_modules/"))
        .is_some_and(|prefix| prefix.is_empty() || prefix.ends_with('/'))
}

/// Whether a Prettier command asks only whether the files are formatted.
/// `--check` and `--list-different` print and exit; every other spelling may
/// reach `--write`, which rewrites each file it visits.
pub(crate) fn prettier_checks(arguments: &[String]) -> bool {
    arguments.iter().any(|argument| {
        matches!(
            argument.as_str(),
            "--check" | "-c" | "--list-different" | "-l"
        )
    })
}

/// The admitted tool of this name and the entrypoints it publishes.
pub(crate) fn tool_entries(name: &str) -> Option<(&'static str, &'static [&'static str])> {
    TOOL_ENTRIES.iter().copied().find(|(tool, _)| *tool == name)
}

/// Whether a `tsc` run emits nothing because the project it reads says so
/// rather than because the command line does.
///
/// The answer is the config's, so it is read only when the command line is
/// silent, and only when the run directory is known. A caller that has no
/// directory reads the command line alone, which is the answer this route
/// has always given.
pub(crate) fn config_declares_no_emit(
    name: &str,
    arguments: &[String],
    directory: Option<&Path>,
) -> bool {
    name == "tsc"
        && !arguments.iter().any(|word| word == "--noEmit")
        && crate::tsc_project::declares_no_emit(arguments, directory)
}

/// The supported tool a name stands for, the entrypoints it publishes and
/// the mode it runs in, or `None` when the tool or its mode is not one of the
/// supported runs.
pub(crate) fn supported_tool(
    name: &str,
    arguments: &[String],
) -> Option<(&'static str, &'static [&'static str], ToolMode)> {
    supported_tool_in(name, arguments, None)
}

/// [`supported_tool`] for a run whose directory is known, so a `tsc` run can
/// be read against the project it names as well as the options it carries.
pub(crate) fn supported_tool_in(
    name: &str,
    arguments: &[String],
    directory: Option<&Path>,
) -> Option<(&'static str, &'static [&'static str], ToolMode)> {
    let declared = config_declares_no_emit(name, arguments, directory);
    supported_tool_declared(name, arguments, declared)
}

/// [`supported_tool_in`] for a caller that has already read the project.
///
/// The admission and the `--noEmit` the route writes back onto the run rest
/// on that one answer. Reading the file a second time here would let a
/// config written between the two readings admit a run whose arguments never
/// carried the option.
pub(crate) fn supported_tool_declared(
    name: &str,
    arguments: &[String],
    declared_no_emit: bool,
) -> Option<(&'static str, &'static [&'static str], ToolMode)> {
    let mode = match name {
        "eslint" => ToolMode::Report,
        "tsc" if arguments.iter().any(|word| word == "--noEmit") || declared_no_emit => {
            ToolMode::Report
        }
        // Only a checking mode reports instead of rewriting the files it visits.
        "prettier" if prettier_checks(arguments) => ToolMode::Report,
        "vite" if arguments.first().is_some_and(|word| word == "build") => ToolMode::Build,
        _ => return None,
    };
    let (tool, entries) = tool_entries(name)?;
    Some((tool, entries, mode))
}

/// The tool a `node` command starts, from the entrypoint it names, or `""`
/// when the entrypoint belongs to no supported tool.
pub(crate) fn entry_tool(entry: &str) -> &'static str {
    TOOL_ENTRIES
        .iter()
        .find(|(_, entries)| {
            entries
                .iter()
                .any(|published| local_package_entry(entry, published))
        })
        .map_or("", |(tool, _)| *tool)
}
