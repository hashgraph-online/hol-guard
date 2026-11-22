//! Read-only `sqlite3` queries against a local database file.
//!
//! The shipped shape is `sqlite3 [OUTPUT OPTIONS] FILE "select ..."`: the CLI
//! opens the named database, runs one statement and exits. Only that shape is
//! proven. The statement must be a single `SELECT` (or a `WITH` whose body is
//! one), because SQLite accepts a data-modifying statement wherever a query
//! fits, and a `;` would start a second statement the screen never read.
//!
//! Dot-commands stay reviewed in full. `.output`, `.once`, `.import`, `.save`,
//! `.backup`, `.read`, `.load`, `.shell` and `.system` write files, load code
//! or run programs, and the harmless ones (`.tables`, `.schema`) have plain
//! `sqlite_master` queries that this proof already covers.
//!
//! Without `-init`, the CLI runs `~/.sqliterc` at startup, and that file may
//! hold any dot-command. The read is admitted only when no such file exists,
//! as `psql` is admitted only when no `~/.psqlrc` can run. `-init` names a
//! startup file of its own, so it stays reviewed rather than becoming a way to
//! point the CLI at one.

use std::path::Path;

/// Options that take no value and only shape the printed rows.
const FLAGS: &[&str] = &[
    "ascii", "bail", "batch", "box", "column", "csv", "echo", "header", "headers", "html", "json",
    "line", "list", "markdown", "noheader", "quote", "readonly", "table",
];

/// Options whose value is printed text rather than a path or a program.
const VALUED: &[&str] = &["newline", "nullvalue", "separator"];

/// Statement keywords that write, read outside the query, or open a second
/// database. `commit`, `release` and `rollback` close a transaction a write
/// opened, so they travel with one. `end` is left out: it closes `CASE`, and a
/// transaction it could close needs a `BEGIN` this screen has already refused.
const WRITE_WORDS: &[&str] = &[
    "alter",
    "analyze",
    "attach",
    "begin",
    "commit",
    "create",
    "delete",
    "detach",
    "drop",
    "insert",
    "pragma",
    "reindex",
    "release",
    "rollback",
    "savepoint",
    "update",
    "vacuum",
];

/// Functions that reach outside the database: the file helpers and the archive
/// and page extensions the shipped CLI builds in, plus extension loading. These
/// are ordinary words as well, so only a call is refused.
const UNSAFE_FUNCTIONS: &[&str] = &[
    "edit",
    "fts3_tokenizer",
    "load_extension",
    "readfile",
    "sqlar_compress",
    "sqlar_uncompress",
    "sqlite_dbpage",
    "writefile",
    "zipfile",
];

pub(super) fn safe_sqlite3_arguments(
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    admitted(arguments, context, || {
        startup_file_absent(
            context.home_dir,
            std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .as_deref(),
        )
    })
}

fn admitted(
    arguments: &[String],
    context: super::PathContext<'_>,
    startup_file_absent: impl FnOnce() -> bool,
) -> bool {
    let Some((database, statement)) = parse(arguments) else {
        return false;
    };
    database_argument(database, context) && read_only_statement(statement) && startup_file_absent()
}

/// The database path and the one statement, or `None` when any other option,
/// operand or count appears.
fn parse(arguments: &[String]) -> Option<(&str, &str)> {
    let mut operands: Vec<&str> = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        index += 1;
        let Some(name) = option_name(argument) else {
            operands.push(argument);
            continue;
        };
        if FLAGS.contains(&name) {
            continue;
        }
        if !VALUED.contains(&name) {
            return None;
        }
        let value = arguments.get(index)?;
        index += 1;
        if value.contains('\0') {
            return None;
        }
    }
    match operands.as_slice() {
        [database, statement] => Some((database, statement)),
        _ => None,
    }
}

/// The option's name without its leading dashes. The CLI accepts one dash or
/// two for every option, and no option takes an attached `=value`.
fn option_name(argument: &str) -> Option<&str> {
    let name = argument
        .strip_prefix("--")
        .or_else(|| argument.strip_prefix('-'))?;
    (!name.is_empty() && !name.contains('=')).then_some(name)
}

/// A plain path to the database the query reads. A URI filename carries its
/// own open mode and may name a second file through `?vfs=`, and `:memory:`
/// and `""` are not paths at all, so none of them is proven here.
fn database_argument(value: &str, context: super::PathContext<'_>) -> bool {
    let lowered = value.to_ascii_lowercase();
    if value.is_empty()
        || value.starts_with('-')
        || lowered.starts_with("file:")
        || lowered == ":memory:"
        // `SQLITE_USE_URI` turns every filename into a URI, where a query
        // string picks the open mode and may name another file through `vfs=`.
        || value.contains('?')
        || crate::pretool::sensitive_read_path_argument(value)
    {
        return false;
    }
    super::read_paths::existing_regular_read_target(value, context.home_dir, context.cwd)
        // An absent database is created empty, which is the write `touch`
        // already proves, so it is screened as that write's target is.
        || super::safe_writes::creatable_target(value, context, false)
}

/// One `SELECT`, with nothing after it and no word that writes or reaches
/// outside the database.
fn read_only_statement(statement: &str) -> bool {
    let text = statement.trim();
    let text = text.strip_suffix(';').unwrap_or(text).trim_end();
    if text.is_empty() || text.contains(';') || text.contains('\0') {
        return false;
    }
    let lowered = text.to_ascii_lowercase();
    let words = words(&lowered);
    if !matches!(words.first().map(|word| word.name), Some("select" | "with")) {
        return false;
    }
    words.iter().enumerate().all(|(index, word)| {
        if word.name == "replace" {
            // `replace(text, from, to)` is an ordinary string function; only
            // `REPLACE INTO` writes.
            return words.get(index + 1).map(|next| next.name) != Some("into");
        }
        !(WRITE_WORDS.contains(&word.name)
            || (word.called && UNSAFE_FUNCTIONS.contains(&word.name)))
    })
}

struct Word<'a> {
    name: &'a str,
    /// Whether the next character that is not a space opens an argument list.
    called: bool,
}

fn words(lowered: &str) -> Vec<Word<'_>> {
    let mut words = Vec::new();
    let mut rest = lowered;
    while let Some(start) =
        rest.find(|letter: char| letter.is_ascii_alphanumeric() || letter == '_')
    {
        let tail = &rest[start..];
        let end = tail
            .find(|letter: char| !letter.is_ascii_alphanumeric() && letter != '_')
            .unwrap_or(tail.len());
        words.push(Word {
            name: &tail[..end],
            called: tail[end..].trim_start().starts_with('('),
        });
        rest = &tail[end..];
    }
    words
}

/// Whether the account has no `~/.sqliterc` for the CLI to run at startup.
/// The shell's own `HOME` is checked too, because the CLI resolves the file
/// from the environment it is launched in rather than from the account.
fn startup_file_absent(home_dir: Option<&str>, shell_home: Option<&std::ffi::OsStr>) -> bool {
    let Some(home) = home_dir.map(Path::new).filter(|home| home.is_absolute()) else {
        return false;
    };
    absent(home)
        && shell_home
            .filter(|value| !value.is_empty())
            .is_none_or(|shell| {
                let shell = Path::new(shell);
                shell.is_absolute() && absent(shell)
            })
}

fn absent(home: &Path) -> bool {
    matches!(
        std::fs::symlink_metadata(home.join(".sqliterc")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}

#[cfg(test)]
#[path = "sqlite_reads_tests.rs"]
mod tests;
