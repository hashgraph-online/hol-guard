//! A trailing `> <scratch log> 2>&1` the sink writes itself.
//!
//! Agents save a long run's output to a scratch file and print only a short
//! report: `tsc --noEmit > /tmp/tsc.log 2>&1 && echo CLEAN || echo FAILED`.
//! The workspace sandbox cannot open a file outside the workspace, so this
//! write used to send the whole command to review. The sink instead peels
//! the redirect, runs the core contained with its output captured, and
//! writes the capture to the file itself. Only a plain file name directly in
//! the system temporary directory, or in the user's private macOS one, is
//! taken, and only a regular file of the user's own with a single link is
//! ever replaced, so the write cannot reach a file the run could not have
//! made.

use std::path::PathBuf;

/// The longest file name the sink writes.
const NAME_LIMIT: usize = 128;
/// The extensions a scratch log may carry.
const LOG_EXTENSIONS: &[&str] = &[".log", ".txt", ".out"];

/// The trailing `> FILE`, `> FILE 2>&1` or `&> FILE` of `characters`: where
/// the redirect starts, the file it names, and whether standard error joins
/// standard output. `None` unless the redirect is the whole of what follows
/// the command and names a [`log_target`].
///
/// The `>` must stand alone after a blank, so `1>`, `2>`, `>>` and `>|`
/// are never read as this redirect, and the file must be spelled in plain
/// characters, so no quote or expansion can make the shell open another.
pub(super) fn log_redirect(characters: &[char]) -> Option<(usize, PathBuf, bool)> {
    let mut end = characters.len();
    while end > 0 && blank(characters[end - 1]) {
        end -= 1;
    }
    let mut merge = false;
    if end >= 5 && characters[end - 4..end] == ['2', '>', '&', '1'] && blank(characters[end - 5]) {
        merge = true;
        end -= 4;
        while end > 0 && blank(characters[end - 1]) {
            end -= 1;
        }
    }
    let mut word = end;
    while word > 0 && plain(characters[word - 1]) {
        word -= 1;
    }
    if word == end {
        return None;
    }
    let spelled: String = characters[word..end].iter().collect();
    let mut operator = word;
    while operator > 0 && blank(characters[operator - 1]) {
        operator -= 1;
    }
    if operator == 0 || characters[operator - 1] != '>' {
        return None;
    }
    let mut start = operator - 1;
    if start > 0 && characters[start - 1] == '&' && !merge {
        merge = true;
        start -= 1;
    }
    if start == 0 || !blank(characters[start - 1]) {
        return None;
    }
    let target = log_target(&spelled)?;
    while start > 0 && blank(characters[start - 1]) {
        start -= 1;
    }
    (start > 0).then_some((start, target, merge))
}

fn blank(character: char) -> bool {
    character == ' ' || character == '\t'
}

fn plain(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | '/')
}

/// `spelled` as the file the sink may write: an absolute path whose parent
/// resolves to the system temporary directory or the user's private macOS
/// one, named in plain characters with a log extension and no leading dot.
/// A file already there must be the user's own regular file with one link,
/// so neither a symlink nor a hard link planted in the shared directory can
/// carry the write elsewhere. `None` for anything else, which leaves the
/// redirect to the review it has always had.
#[cfg(unix)]
pub(in crate::pretool) fn log_target(spelled: &str) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let path = std::path::Path::new(spelled);
    let name = path.file_name()?.to_str()?;
    if !path.is_absolute()
        || name.len() > NAME_LIMIT
        || name.starts_with('.')
        || !name
            .chars()
            .all(|character| plain(character) && character != '/')
        || !LOG_EXTENSIONS
            .iter()
            .any(|extension| name.len() > extension.len() && name.ends_with(extension))
    {
        return None;
    }
    let parent = std::fs::canonicalize(path.parent()?).ok()?;
    let uid = nix::unistd::geteuid().as_raw();
    let scratch = std::fs::canonicalize("/tmp").is_ok_and(|tmp| parent == tmp)
        || crate::pretool::git_routes::private_temporary_base(&parent, uid)
            .is_some_and(|base| parent == base);
    if !scratch {
        return None;
    }
    let target = parent.join(name);
    match std::fs::symlink_metadata(&target) {
        Ok(metadata) => {
            (metadata.file_type().is_file() && metadata.uid() == uid && metadata.nlink() == 1)
                .then_some(target)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(target),
        Err(_) => None,
    }
}

#[cfg(not(unix))]
pub(in crate::pretool) fn log_target(_spelled: &str) -> Option<PathBuf> {
    None
}

/// Whether the sink writes `command`'s trailing scratch log itself, issued
/// from `context.cwd`: the peel takes the redirect, and the core runs from
/// the root of the workspace or of the sibling repository it names, where
/// the sink asks about the core again on its own. A directory below a root
/// runs the text whole in the workspace sandbox, which cannot open the file.
pub(in crate::pretool) fn sink_writes(
    command: &str,
    context: crate::pretool::PathContext<'_>,
) -> bool {
    let Some(workspace) = context.cwd else {
        return false;
    };
    let plan =
        crate::pretool::contained_wrapper_plan(command, workspace, None, context.home_dir, None);
    if plan.refusal.is_some() || plan.worktree_add.is_some() {
        return false;
    }
    let Some(peeled) = plan.plan else {
        return false;
    };
    if !peeled
        .output
        .as_ref()
        .is_some_and(|output| output.file.is_some())
    {
        return false;
    }
    let (Ok(inside), Ok(resolved)) = (
        std::fs::canonicalize(workspace),
        std::fs::canonicalize(&peeled.directory),
    ) else {
        return false;
    };
    let root = if resolved.starts_with(&inside) {
        Some(inside)
    } else {
        context
            .home_dir
            .and_then(|home| {
                super::contained_wrapper::project_root(
                    &peeled.directory,
                    home,
                    super::contained_wrapper::ProjectRoots::RepositoryOrPackage,
                )
            })
            .and_then(|root| std::fs::canonicalize(root).ok())
    };
    root.is_some_and(|root| peeled.directory == root)
}

#[cfg(test)]
#[path = "sink_peel_log_tests.rs"]
mod tests;
