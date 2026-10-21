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

/// A plan note filed in the harness home, spelled from `~` or from the root.
/// These are the only home paths a redirect may remove from a command.
pub(super) fn plan_note_output_target(target: &str, context: PathContext<'_>) -> bool {
    target.len() <= 4096
        && target.starts_with(['~', '/'])
        && target
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || "._-/+@%,=:~".contains(value))
        && !crate::pretool::sensitive_command(target)
        && crate::pretool::safe_writes::plan_note_write_target(
            target,
            context.home_dir,
            context.cwd,
        )
}

pub(super) fn safe_output_target(target: &str, context: PathContext<'_>) -> bool {
    // NTFS reads any later colon as a stream name, and `C:name` is relative
    // to that drive's own directory. The only colon a Windows target may
    // hold is the designator of a `C:/` drive path.
    #[cfg(windows)]
    if target.char_indices().any(|(index, value)| {
        value == ':'
            && !(index == 1
                && target.as_bytes()[0].is_ascii_alphabetic()
                && target.as_bytes().get(2) == Some(&b'/'))
    }) {
        return false;
    }
    if plan_note_output_target(target, context) {
        return true;
    }
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
            // `C:/...` is how Git Bash agents spell an absolute Windows path.
            #[cfg(windows)]
            std::path::Component::Prefix(prefix)
                if matches!(prefix.kind(), std::path::Prefix::Disk(_)) => {}
            _ => return false,
        }
    }
    // Hidden components cover dotfiles, `.git/hooks`, `.env` and harness
    // configuration. Only a plain scratch path the file-edit write check
    // accepts, such as `.tmp/log.txt`, passes.
    if hidden && !bounded_write(target, context) {
        return false;
    }
    // Agent instruction files in a repository beside the session keep their
    // review: a newly loaded one can redirect an agent, and no workspace
    // sandbox stands around a sibling repository to deny the write. This
    // runs before the temporary-root rule below, which would otherwise admit
    // the file when the home itself lies below `/tmp`, as a test host's does.
    if instruction_file(target) && sibling_target(target, context) {
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
        // Git Bash's `/tmp` is the profile's `AppData\Local\Temp`, which an
        // agent may also spell as a drive path. The temporary file proof
        // locates that folder from the canonical home and refuses links,
        // hidden parts and credential-shaped names.
        #[cfg(windows)]
        if crate::pretool::chain_temporary::temporary_file_target(
            target,
            context.home_dir,
            context.cwd,
        ) {
            return true;
        }
        if let Some(cwd) = cwd.filter(|cwd| path.starts_with(cwd)) {
            return path != cwd
                && path
                    .strip_prefix(cwd)
                    .is_ok_and(|rest| no_symlink_components(cwd, rest));
        }
        // A session started in a directory above its checkouts, or in a
        // sibling one, still writes the repository it works on. Instruction
        // files were refused above.
        // The root is resolved, and the home may be spelled through a
        // symlinked parent, so take the part below the root from the resolved
        // target. `sibling_repository_root` already required that part to be
        // spelled exactly as the hook spelled it below the home.
        return bounded_write(target, context)
            && sibling_repository_root(path, context).is_some_and(|root| {
                crate::pretool::worktree_writes::canonical_write_target(path).is_some_and(
                    |canonical| {
                        canonical
                            .strip_prefix(&root)
                            .is_ok_and(|rest| no_symlink_components(&root, rest))
                    },
                )
            });
    }
    cwd.is_some_and(|cwd| no_symlink_components(cwd, path))
}

/// Whether `target` is an absolute path in a repository beside the session's
/// directory, outside the workspace sandbox the session's own files run in.
pub(super) fn sibling_target(target: &str, context: PathContext<'_>) -> bool {
    let path = std::path::Path::new(target);
    path.is_absolute()
        && !context.cwd.is_some_and(|cwd| path.starts_with(cwd))
        && sibling_repository_root(path, context).is_some()
}

/// [`sibling_target`] for a quoted heredoc written beside the session's
/// directory. A repository session runs that heredoc inside the workspace
/// sandbox, which denies agent instruction files, and a sibling repository has
/// no such sandbox around it. Those files therefore keep the sandbox review a
/// heredoc into them gets from inside the repository instead of the no-op
/// stand-in that lets a heredoc into a source or notes file through.
pub(super) fn sibling_heredoc_target(target: &str, context: PathContext<'_>) -> bool {
    sibling_target(target, context) && !instruction_file(target)
}

fn instruction_file(target: &str) -> bool {
    std::path::Path::new(target)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            crate::harness_config_names::HARNESS_INSTRUCTION_FILES
                .contains(&name.to_ascii_lowercase().as_str())
        })
}

/// The root of the git repository below the verified home that holds the
/// absolute `path`. Callers separately require it to lie outside cwd. This is
/// the clone or worktree a file-edit tool already writes without review:
/// `bounded_native_file_write_target` screens the same target for protected
/// files, hidden parts, hard links and execution-control locations, and the
/// caller still refuses a symlink anywhere below the root.
fn sibling_repository_root(
    path: &std::path::Path,
    context: PathContext<'_>,
) -> Option<std::path::PathBuf> {
    let home = std::fs::canonicalize(context.home_dir?).ok()?;
    let canonical = crate::pretool::worktree_writes::canonical_write_target(path)?;
    let root = repository_below_home(&canonical, context.home_dir?, &home)?;
    // The repository must sit below the home itself, not merely below a
    // temporary directory the helper also accepts, and must be spelled the
    // way the filesystem resolves it, so no alias redirects the write. The
    // home's own spelling is not such an alias: a home reached through a
    // symlinked parent, as `/var/folders/...` is on macOS, resolves to a
    // different prefix than the one the hook was handed. Comparing the path
    // below the home keeps a symlink inside the home refused.
    (root != home
        && root.starts_with(&home)
        && spelling_survives_the_filesystem(path)
        && crate::pretool::safe_writes::home_spelling_matches_target(
            path,
            &canonical,
            context.home_dir,
            &home,
        )
        && validated_git_marker(&root))
    .then_some(root)
}

/// Whether every component of `path` names the file the filesystem will open.
/// On Windows a trailing dot or space is dropped when the file is created, so
/// `AGENTS.md.` lands on the protected name that `instruction_file` and
/// `write_target_protected` spell literally and would otherwise miss. Such a
/// target keeps its review rather than taking the sibling-repository route.
#[cfg(not(unix))]
fn spelling_survives_the_filesystem(path: &std::path::Path) -> bool {
    path.components().all(|component| match component {
        std::path::Component::Normal(name) => name
            .to_str()
            .is_some_and(|name| !name.ends_with('.') && !name.ends_with(' ')),
        _ => true,
    })
}

/// [`spelling_survives_the_filesystem`] on Unix, where a trailing dot or space
/// is part of the name and a screen that spells the protected name literally
/// already sees a different file.
#[cfg(unix)]
fn spelling_survives_the_filesystem(_path: &std::path::Path) -> bool {
    true
}

/// The nearest ancestor of the resolved `canonical` target that holds a `.git`
/// entry. On Unix this is the repository a `cd` into a sibling checkout is
/// contained to, which also requires the agent's user to own it.
#[cfg(unix)]
fn repository_below_home(
    canonical: &std::path::Path,
    home_dir: &str,
    _home: &std::path::Path,
) -> Option<std::path::PathBuf> {
    crate::pretool::contained_wrapper::sibling_project_root(canonical, home_dir)
}

/// Windows has no execution sink to contain a `cd` into a sibling checkout,
/// so that route stays closed, but a redirect writes one file the same way a
/// file-edit tool does. The resolved home must be a local disk path, so a
/// profile on a network share stays reviewed (a mapped drive or a link onto a
/// share resolves to its `\\?\UNC\` form), and the repository must be owned
/// by the agent's user, as on Unix. The caller still validates the marker and
/// screens the target.
#[cfg(not(unix))]
fn repository_below_home(
    canonical: &std::path::Path,
    _home_dir: &str,
    home: &std::path::Path,
) -> Option<std::path::PathBuf> {
    use std::path::{Component, Prefix};
    let local = matches!(
        home.components().next(),
        Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::VerbatimDisk(_))
    );
    if !local || !canonical.starts_with(home) {
        return None;
    }
    canonical
        .ancestors()
        .take_while(|directory| *directory != home)
        .find(|directory| directory.join(".git").symlink_metadata().is_ok())
        .filter(|root| guard_runtime_windows_process::owned_by_current_user(root))
        .map(std::path::Path::to_path_buf)
}

/// An empty `.git` marker is not a repository. Bound this check to Git's
/// structural metadata; linked worktrees additionally require the existing
/// admin-directory and backlink verification.
fn validated_git_marker(root: &std::path::Path) -> bool {
    let marker = root.join(".git");
    let Ok(meta) = std::fs::symlink_metadata(&marker) else {
        return false;
    };
    if meta.file_type().is_symlink() {
        return false;
    }
    if meta.is_file() {
        return crate::pretool::worktree_writes::linked_worktree_dirs(root).is_some();
    }
    if !meta.is_dir() {
        return false;
    }
    marker.join("HEAD").is_file()
        && marker.join("config").is_file()
        && marker.join("objects").is_dir()
        && marker.join("refs").is_dir()
}

pub(super) fn bounded_write(target: &str, context: PathContext<'_>) -> bool {
    use crate::pretool::safe_writes::{
        bounded_native_file_write_target, bounded_native_temporary_write_target,
        plan_note_write_target,
    };
    // A plan note filed in the harness home is a bounded write wherever the
    // session runs, spelled from `~` or from the root. The note check resolves
    // the path before it looks for an execute bit.
    if plan_note_write_target(target, context.home_dir, context.cwd) {
        return true;
    }
    // Home is outside the workspace even when it sits below a temporary
    // directory, as it does for disposable and CI accounts.
    let path = std::path::Path::new(target);
    // On Windows the profile's temporary folder lies below home, so prove it
    // before the home rule below admits only a sibling repository.
    #[cfg(windows)]
    if path.is_absolute()
        && bounded_native_temporary_write_target(target, context.home_dir, context.cwd)
    {
        return !crate::pretool::curl_reads::output_targets::existing_executable(
            target,
            context.cwd,
        );
    }
    let under = |base: Option<&str>| base.is_some_and(|base| path.starts_with(base));
    if path.is_absolute() && under(context.home_dir) && !under(context.cwd) {
        // Only a file in a repository beside the session's directory is a
        // workspace write; the rest of the home stays reviewed.
        return sibling_repository_root(path, context).is_some()
            && !crate::pretool::curl_reads::output_targets::existing_executable(
                target,
                context.cwd,
            )
            && bounded_native_file_write_target(target, context.home_dir, context.cwd);
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
