//! A `python3 -c` program that only reshapes what it reads.
//!
//! Agents pipe JSON from `gh`, `curl` or a CLI into a short Python program
//! far more often than into `jq`: `gh pr checks 7 --json name,state |
//! python3 -c 'import json,sys; ...'`. The program reads standard input,
//! computes, and prints. It is proven read-only when three things hold.
//!
//! - The program source passes [`program::screened`]: it imports only
//!   modules that compute, names no builtin that opens a file or evaluates
//!   text, and cannot reach another object's namespace.
//! - The interpreter loads nothing a variable chose: `-I` or `-E` is given,
//!   or no inherited or prefixed `PYTHON*` variable outside a fixed list of
//!   output and diagnostics switches is set.
//! - No module in the working directory can stand in for one the standard
//!   library provides. `-c` puts the working directory first on the module
//!   path, so a `json.py` beside the command would run on `import json`.
//!   `-I` and `-P` leave it off the path; otherwise the directory must be
//!   known, no other step of the command may create a file, and no
//!   importable entry in it may carry a standard library module's name.

mod names;
mod program;
#[cfg(test)]
mod tests;

/// Options the filter may give the interpreter before `-c`.
#[derive(Default)]
struct Options {
    ignores_environment: bool,
    safe_path: bool,
    no_site: bool,
    program: usize,
}

/// The existing constant-expression proof for `python`, `python3` and
/// `node`, then the filter proof for Python.
pub(super) fn inline_program(
    basename: &str,
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    super::pure_expression::safe_inline_expression(basename, &segment.arguments)
        || (matches!(basename, "python" | "python3") && safe_filter(model, segment, context))
}

fn safe_filter(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    let Some(options) = interpreter_options(&segment.arguments) else {
        return false;
    };
    ['$', '`'].iter().all(|character| {
        !segment.text.contains(*character)
            || super::shell_literal::literal_everywhere(&segment.text, *character)
    }) && !unquoted_glob(&segment.text)
        && (options.no_site || interpreter_outside_workspace(segment, context))
        && program::screened(&segment.arguments[options.program])
        && (options.ignores_environment || environment_settled(model, segment, context))
        && (options.safe_path || working_directory_clean(model, segment, context))
}

/// Reads `-I`, `-E`, `-P` and the switches that only change buffering,
/// bytecode writing or the user site, up to `-c PROGRAM`.
fn interpreter_options(arguments: &[String]) -> Option<Options> {
    let mut options = Options::default();
    for (index, argument) in arguments.iter().enumerate() {
        let flags = argument
            .strip_prefix('-')
            .filter(|flags| !flags.is_empty() && !flags.starts_with('-'))?;
        for (position, flag) in flags.char_indices() {
            match flag {
                'I' => {
                    options.ignores_environment = true;
                    options.safe_path = true;
                }
                'E' => options.ignores_environment = true,
                'P' => options.safe_path = true,
                'S' => options.no_site = true,
                's' | 'B' | 'u' | 'q' => {}
                'c' if position + 1 == flags.len() && index + 1 < arguments.len() => {
                    options.program = index + 1;
                    return Some(options);
                }
                _ => return None,
            }
        }
    }
    None
}

/// An unquoted `*`, `?` or `[` expands to file names before the interpreter
/// starts, so `python3 -c *` would run whichever name matched first rather
/// than the screened text. Quoted or escaped, the shell leaves them alone.
fn unquoted_glob(text: &str) -> bool {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for character in text.chars() {
        match quote {
            Some('\'') => {
                if character == '\'' {
                    quote = None;
                }
            }
            _ if escaped => escaped = false,
            _ if character == '\\' => escaped = true,
            Some(_) => {
                if character == '"' {
                    quote = None;
                }
            }
            None if matches!(character, '\'' | '"') => quote = Some(character),
            None if matches!(character, '*' | '?' | '[') => return true,
            None => {}
        }
    }
    false
}

/// An interpreter named by a path in the working directory, such as
/// `.venv/bin/python3`, runs the `.pth` startup files of that environment
/// before the program; `-S` skips them. A bare name or a path outside the
/// working directory resolves the way every other command does.
fn interpreter_outside_workspace(
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    path_outside_workspace(segment.executable.as_deref().unwrap_or(""), context.cwd)
}

/// Compares resolved paths: a `..` step or a link could otherwise name a
/// workspace interpreter by a path that does not start with the cwd.
fn path_outside_workspace(executable: &str, cwd: Option<&str>) -> bool {
    if !executable.contains('/') {
        return true;
    }
    let path = std::path::Path::new(executable);
    executable.starts_with('/')
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
        && cwd.is_some_and(|cwd| {
            let Some(invocation_parent) = path.parent() else {
                return false;
            };
            match (
                std::fs::canonicalize(path),
                std::fs::canonicalize(invocation_parent),
                std::fs::canonicalize(cwd),
            ) {
                (Ok(interpreter), Ok(invocation_parent), Ok(resolved_cwd)) => {
                    // CPython chooses a virtual environment from the invoked
                    // path, even when .venv/bin/python3 links to /usr/bin.
                    // The final canonical executable alone cannot prove that
                    // workspace .pth startup files will be skipped.
                    !path.starts_with(std::path::Path::new(cwd))
                        && !path.starts_with(&resolved_cwd)
                        && !invocation_parent.starts_with(&resolved_cwd)
                        && !interpreter.starts_with(&resolved_cwd)
                }
                _ => false,
            }
        })
}

/// No variable the interpreter reads can add a module path or startup code:
/// none is inherited, none prefixes this step, and no other step names one.
fn environment_settled(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    context.python_environment_inert
        && !segment
            .environment_names
            .iter()
            .any(|name| names::steering_variable(name))
        && model
            .segments
            .iter()
            .filter(|other| other.span != segment.span)
            .all(|other| !other.text.to_ascii_uppercase().contains("PYTHON"))
}

/// Whether an inherited environment leaves the interpreter's module path and
/// startup alone.
pub(super) fn environment_inert(
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    match execution_environment {
        Some(environment) => {
            environment.has_valid_shape()
                && !environment
                    .environment_names
                    .iter()
                    .any(|name| names::steering_variable(name))
        }
        None => !std::env::vars_os().any(|(name, value)| {
            !value.is_empty() && names::steering_variable(&name.to_string_lossy())
        }),
    }
}

/// Importable suffixes, matched without regard to case.
const MODULE_SUFFIXES: &[&str] = &[".py", ".pyc", ".pyo", ".pyw", ".pyd", ".so"];

/// Entries read from the working directory before the proof gives up.
const MAX_ENTRIES: usize = 4096;

/// No module or package in the working directory carries a standard library
/// name, and nothing in the command can add one or move to another
/// directory before the interpreter starts.
fn working_directory_clean(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    let Some(cwd) = context.cwd else {
        return false;
    };
    // The interpreter may write once it runs, but nothing it writes exists
    // before it looks up a module; every other step must create nothing,
    // and only a leading `cd`, already folded into `cwd`, may move.
    let peers_settled = model.segments.iter().enumerate().all(|(index, other)| {
        let basename = super::executable_basename(other.executable.as_deref().unwrap_or(""));
        other.span == segment.span
            || ((super::search::grep::creates_nothing(other)
                || peer_proven_read_only(model, other, basename, context))
                && (index == 0 || !matches!(basename, "cd" | "pushd" | "popd")))
    });
    if !peers_settled {
        return false;
    }
    let Ok(entries) = std::fs::read_dir(cwd) else {
        return false;
    };
    let mut count = 0;
    for entry in entries {
        count += 1;
        let Ok(entry) = entry else {
            return false;
        };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            return false;
        };
        if count > MAX_ENTRIES {
            return false;
        }
        let stem = name.split('.').next().unwrap_or("");
        if names::shadows_standard_library(stem) && importable(&entry.path(), &name) {
            return false;
        }
    }
    true
}

/// A producer such as `gh pr list --json` or `curl -s URL` that carries its
/// own read-only proof writes nothing outside a scratch location. That holds
/// only while the working directory is not one itself: `curl -o` may save to
/// a private temporary file, and a `/tmp` checkout would take a `json.py`.
/// Another interpreter step is held to the plain screen, so the proofs never
/// call back into each other.
fn peer_proven_read_only(
    model: &crate::CanonicalCommandV1,
    other: &crate::CommandSegmentV1,
    basename: &str,
    context: super::PathContext<'_>,
) -> bool {
    let Some(probe) = context.cwd.and_then(|cwd| {
        std::path::Path::new(cwd)
            .join("json.py")
            .to_str()
            .map(str::to_owned)
    }) else {
        return false;
    };
    other.wrapper_chain.is_empty()
        && !basename.starts_with("python")
        && !super::curl_reads::output_targets::scratch_output_target(&probe, context)
        && super::segment_proof::exact_safe_segment_with_context(model, other, false, context)
}

/// A package directory holds an `__init__` module; a module file carries an
/// importable suffix. A directory without one is a namespace portion, which
/// never wins over a real module later on the path.
fn importable(path: &std::path::Path, name: &str) -> bool {
    if path.is_dir() {
        return std::fs::read_dir(path).map_or(true, |mut entries| {
            entries.any(|entry| {
                entry.map_or(true, |entry| {
                    entry.file_name().to_string_lossy().starts_with("__init__.")
                })
            })
        });
    }
    let lower = name.to_ascii_lowercase();
    MODULE_SUFFIXES.iter().any(|suffix| lower.ends_with(suffix))
}
