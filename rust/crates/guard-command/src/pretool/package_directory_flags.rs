//! Package-manager directory flags: `bun --cwd <dir>`, `npm --prefix <dir>`,
//! `pnpm -C <dir>` and `yarn --cwd <dir>` run the rest exactly as
//! `cd <dir> && <manager> <rest>` would. The flag form is rewritten into that
//! list with the directory resolved the way the manager resolves it, so it
//! faces the same directory proof, sibling-repository rule and containment
//! checks as the `cd` form. The execution sink peels the same flag
//! (`contained_wrapper.py`) and re-authorizes the rest in that directory.
use crate::{CanonicalCommandV1, CommandModelRequestV1};
use std::path::{Component, Path, PathBuf};

/// The `cd <dir> && …` list equivalent to a directory-flag command.
pub(in crate::pretool) struct Projected {
    pub(in crate::pretool) model: CanonicalCommandV1,
    pub(in crate::pretool) text: String,
}

fn directory_flags(manager: &str) -> &'static [&'static str] {
    match manager {
        "bun" | "yarn" => &["--cwd"],
        "npm" => &["--prefix", "-C"],
        "pnpm" => &["--dir", "-C"],
        _ => &[],
    }
}

/// Any spelling of a directory flag: `--cwd`, `--cwd=x`, `-C`, `-Cx`.
fn names_flag(word: &str, flags: &[&str]) -> bool {
    flags.iter().any(|flag| {
        let short = !flag.starts_with("--");
        word.strip_prefix(*flag)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('=') || short)
    })
}

/// A word the shell passes through unchanged: no quoting, expansion,
/// globbing or operator characters. `2>&1` is the one redirection kept.
fn plain(word: &str) -> bool {
    word == "2>&1"
        || (!word.is_empty()
            && word.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'/' | b'.' | b'_' | b'-' | b'@' | b'+' | b'=' | b':' | b','
                    )
            }))
}

/// `.` and `..` resolved lexically, as `path.resolve` does in every Node
/// package manager. `None` above the root or for a non-absolute result.
fn lexical(path: &Path) -> Option<PathBuf> {
    let mut resolved = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => resolved.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                if !resolved.pop() {
                    return None;
                }
            }
            Component::Normal(part) => resolved.push(part),
            Component::Prefix(_) => return None,
        }
    }
    resolved.is_absolute().then_some(resolved)
}

/// The manager's working directory: the value joined to the physical cwd
/// (`process.cwd()`), normalized lexically, then resolved on disk.
fn resolve(value: &str, cwd: &str) -> Option<String> {
    if value.starts_with(['-', '~']) || value.contains("//") || !plain(value) || value == "2>&1" {
        return None;
    }
    let base = std::fs::canonicalize(cwd).ok()?;
    let directory = std::fs::canonicalize(lexical(&base.join(value))?).ok()?;
    let directory = directory.to_str().filter(|path| plain(path))?.to_owned();
    Path::new(&directory).is_dir().then_some(directory)
}

/// Rewrite `<manager> [run] <flag> <dir> <rest>` (with only a bounded output
/// filter or status echo after it) into `cd <resolved dir> && <manager> [run] <rest>`.
pub(in crate::pretool) fn as_cd_list(
    model: &CanonicalCommandV1,
    context: super::super::PathContext<'_>,
) -> Option<Projected> {
    if cfg!(windows)
        || model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
    {
        return None;
    }
    let (first, later) = model.segments.split_first()?;
    let executable = first.executable.as_deref()?;
    let flags = directory_flags(executable);
    if flags.is_empty()
        || first.pipeline_index != 0
        || !first.environment_names.is_empty()
        || !first.wrapper_chain.is_empty()
        || first.path_overridden
        || !later
            .iter()
            .all(|segment| super::output_filter(segment) || super::status_echo(model, segment))
    {
        return None;
    }
    // Only plain words, so the source text is exactly these words.
    let chars: Vec<char> = model.normalized_text.chars().collect();
    let source: String = chars
        .get(first.span.start..first.span.end)?
        .iter()
        .collect();
    let words: Vec<&str> = source.split_whitespace().collect();
    if !chars
        .get(..first.span.start)?
        .iter()
        .all(|c| c.is_whitespace())
        || words.first() != Some(&executable)
        || words.len() != first.arguments.len() + 1
        || words[1..]
            .iter()
            .zip(&first.arguments)
            .any(|(word, argument)| *word != argument.as_str() || !plain(word))
    {
        return None;
    }
    let arguments = &words[1..];
    let options = arguments.iter().take_while(|word| **word != "--");
    // One directory flag, before the verb or right after `run`; a repeated
    // or later one could be passed to the script or override the first.
    if options.filter(|word| names_flag(word, flags)).count() != 1 {
        return None;
    }
    let index = usize::from(arguments.first() == Some(&"run"));
    let flag = *arguments.get(index)?;
    let (value, consumed) = if flags.contains(&flag) {
        (*arguments.get(index + 1)?, 2)
    } else {
        let (name, value) = flag.split_once('=')?;
        (flags.contains(&name) && name.starts_with("--")).then_some((value, 1))?
    };
    let directory = resolve(value, context.cwd?)?;
    let removed = index..index + consumed;
    let rest: Vec<&str> = arguments
        .iter()
        .enumerate()
        .filter(|(position, _)| !removed.contains(position))
        .map(|(_, word)| *word)
        .collect();
    if rest.is_empty() {
        return None;
    }
    // Every rest is projected, not only `run` and `test`. What comes out is
    // the `cd <dir> && <manager> <rest>` the user could have typed, so the
    // rest is judged in the resolved directory on the terms it has there:
    // `pnpm install` still meets the package checks, `npm exec vitest` still
    // meets the node-tool containment route, and an implicit script run such
    // as `pnpm build` reaches the containment route the `cd` form reaches.
    let remainder: String = chars[first.span.end..].iter().collect();
    let text = format!(
        "cd {directory} && {executable} {}{remainder}",
        rest.join(" ")
    );
    let projected = crate::parse_command(&CommandModelRequestV1 {
        command: text.clone(),
        dialect: model.dialect.clone(),
        transport: model.transport.clone(),
        extraction_provenance: model.extraction_provenance.clone(),
    })
    .ok()
    .filter(|projected| projected.confidence == "exact")?;
    Some(Projected {
        model: projected,
        text,
    })
}

// The tests spell the workspace path inside POSIX shell text, and the peel
// itself is Unix-only, so they run where the arm they cover compiles.
#[cfg(all(test, unix))]
#[path = "package_directory_flags_tests.rs"]
mod tests;
