//! Which literal output targets the redirect projection may remove: a path
//! the shell opens as written, inside the working directory or a temporary
//! root, never credential-shaped or reached through a symlink, and hidden
//! only as a plain scratch path such as `.tmp/log.txt`.

use crate::pretool::PathContext;

fn posix_temp_file(target: &str) -> bool {
    let Some(rest) = target
        .strip_prefix("/tmp/")
        .or_else(|| target.strip_prefix("/private/tmp/"))
    else {
        return false;
    };
    !rest.is_empty()
        && !rest.contains('/')
        && !rest.contains("..")
        && rest
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || "._-+@%,=".contains(value))
}

pub(super) fn safe_output_target(target: &str, context: PathContext<'_>) -> bool {
    if target.is_empty()
        || target.len() > 4096
        || target.starts_with(['-', '~'])
        || !target
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || "._-/+@%,=:".contains(value))
        || crate::pretool::sensitive_command(target)
    {
        return false;
    }
    let path = std::path::Path::new(target);
    // Windows does not treat `/tmp/file` as absolute, so the host path walk
    // never sees the POSIX temp directory. A single literal temp segment is
    // still a bounded file write and keeps the review floor.
    if !path.is_absolute() && posix_temp_file(target) {
        return true;
    }
    // A POSIX-rooted path other than the bounded temp-file exception cannot
    // be resolved safely with Windows host path semantics.
    #[cfg(windows)]
    if target.starts_with('/') {
        return false;
    }
    let mut hidden = false;
    for component in path.components() {
        match component {
            std::path::Component::Normal(name) => match name.to_str() {
                Some(name) => hidden |= name.starts_with('.'),
                None => return false,
            },
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            _ => return false,
        }
    }
    // Hidden components cover dotfiles, `.git/hooks`, `.env` and harness
    // configuration. Only a plain scratch path the file-edit write check
    // accepts, such as `.tmp/log.txt`, passes.
    if hidden && !bounded_write(target, context) {
        return false;
    }
    let cwd = context
        .cwd
        .map(std::path::Path::new)
        .filter(|cwd| cwd.is_absolute());
    if path.is_absolute() {
        if let Some(base) = ["/tmp", "/private/tmp"]
            .into_iter()
            .map(std::path::Path::new)
            .find(|base| path.starts_with(base) && path != *base)
        {
            return path
                .strip_prefix(base)
                .is_ok_and(|rest| no_symlink_components(base, rest));
        }
        return cwd.is_some_and(|cwd| {
            path != cwd
                && path
                    .strip_prefix(cwd)
                    .is_ok_and(|rest| no_symlink_components(cwd, rest))
        });
    }
    cwd.is_some_and(|cwd| no_symlink_components(cwd, path))
}

pub(super) fn bounded_write(target: &str, context: PathContext<'_>) -> bool {
    use crate::pretool::safe_writes::{
        bounded_native_file_write_target, bounded_native_temporary_write_target,
    };
    // Home is outside the workspace even when it sits below a temporary
    // directory, as it does for disposable and CI accounts.
    let path = std::path::Path::new(target);
    let under = |base: Option<&str>| base.is_some_and(|base| path.starts_with(base));
    if path.is_absolute() && under(context.home_dir) && !under(context.cwd) {
        return false;
    }
    // Truncating an existing program replaces what a later step may run.
    if crate::pretool::curl_reads::output_targets::existing_executable(target, context.cwd) {
        return false;
    }
    bounded_native_file_write_target(target, context.home_dir, context.cwd)
        || bounded_native_temporary_write_target(target, context.home_dir, context.cwd)
}

/// Writing through an existing symlink could reach any file the user owns.
fn no_symlink_components(base: &std::path::Path, relative: &std::path::Path) -> bool {
    let mut current = base.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return false,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
            Err(_) => return false,
        }
    }
    true
}

/// A later step that names a file this command writes below the working
/// directory, spelled from the root, names what the relative spelling names:
/// `> .tmp/run.log; wc -l <cwd>/.tmp/run.log`. Rewriting exactly those words
/// lets the read keep the floor its relative spelling gets. Only a written
/// target is rewritten, only outside quotes, and a chain that changes
/// directory keeps its words. Every other byte of the command is kept.
pub(super) fn relative_saved_reads(
    command: String,
    targets: &[String],
    cwd: Option<&str>,
) -> String {
    let Some(root) = cwd
        .map(|root| root.trim_end_matches('/'))
        .filter(|root| root.starts_with('/') && !root.is_empty())
    else {
        return command;
    };
    let plain = |value: &str| {
        !value.is_empty()
            && !value.split('/').any(|part| matches!(part, "" | "." | ".."))
            && !value.contains([
                '\'', '"', '\\', '$', '`', '*', '?', '[', ']', '{', '}', '~', ' ',
            ])
    };
    let pairs: Vec<(String, String)> = targets
        .iter()
        .filter_map(|target| match target.strip_prefix(root) {
            Some(rest) => {
                let rest = rest.strip_prefix('/')?;
                plain(rest).then(|| (target.clone(), rest.to_owned()))
            }
            None => plain(target).then(|| (format!("{root}/{target}"), target.clone())),
        })
        .collect();
    // Any `cd`, `pushd` or `popd` name, even glued to a separator or quoted,
    // keeps every word as written.
    if pairs.is_empty()
        || command
            .split(|value: char| !(value.is_ascii_alphanumeric() || "_-".contains(value)))
            .any(|word| matches!(word, "cd" | "pushd" | "popd"))
    {
        return command;
    }
    let mut out = String::with_capacity(command.len());
    let mut word = String::new();
    // Whether the current word holds a quote, an escape or quoted text.
    let mut quoted = false;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let flush = |out: &mut String, word: &mut String, quoted: bool| {
        let relative = pairs
            .iter()
            .find(|(absolute, _)| !quoted && absolute.as_str() == word.as_str())
            .map(|(_, relative)| relative.as_str());
        out.push_str(relative.unwrap_or(word.as_str()));
        word.clear();
    };
    for value in command.chars() {
        if !escaped && quote.is_none() && (value.is_whitespace() || ";&|()<>".contains(value)) {
            flush(&mut out, &mut word, quoted);
            quoted = false;
            out.push(value);
            continue;
        }
        match (escaped, quote, value) {
            (true, _, _) => escaped = false,
            (false, Some('\''), '\'') => quote = None,
            (false, Some('\''), _) => {}
            (false, _, '\\') => escaped = true,
            (false, None, '\'' | '"') => quote = Some(value),
            (false, Some('"'), '"') => quote = None,
            _ => {}
        }
        quoted |= escaped || quote.is_some() || matches!(value, '\'' | '"');
        word.push(value);
    }
    flush(&mut out, &mut word, quoted);
    out
}
