//! Plain `cp` operands: one or more readable files copied to a bounded write
//! target. `cp a b dir/` and `cp a dir/` place each file at `dir/<name>`, so
//! every source and every resulting path gets the same screens a single
//! file-to-file copy gets. A leading `-c`, `-p` or `-v` changes neither what
//! is read nor where it lands. Other flags, recursive copies and directory
//! sources are proven elsewhere or stay reviewed. A source such as `saved/src/*.ts` is
//! expanded first, as the shell does, and each word it yields is screened as
//! a source and as `dir/<name>` like a literal operand.

use super::super::chain_temporary::absent_temporary_read_target;
use super::super::read_paths::{bounded_file_read_target, expand_home_read_path};
use super::super::safe_reads::glob_file_matches;
use super::super::PathContext;
use super::{
    autostart_write_target, bounded_native_file_write_target, bounded_temporary_copy_target,
    hooks_path, single_link_write_target,
};
use std::path::{Path, PathBuf};

/// More sources than this is not an ordinary hand-written copy.
const MAX_SOURCES: usize = 16;
/// Words a set of glob sources may expand to.
const MAX_EXPANDED_SOURCES: usize = 64;

pub(in crate::pretool) fn safe_copy_arguments(
    arguments: &[String],
    context: PathContext<'_>,
) -> bool {
    safe_copy_arguments_into(arguments, context, &[])
}

/// Like [`safe_copy_arguments`], for a chain whose earlier `mkdir` segments
/// create the scratch directories in `created`. A file placed directly inside
/// one has a parent that does not exist yet, so the ordinary temporary
/// destination screen cannot see it.
pub(in crate::pretool) fn safe_copy_arguments_into(
    arguments: &[String],
    context: PathContext<'_>,
    created: &[PathBuf],
) -> bool {
    let arguments = match arguments {
        [flag, rest @ ..] if attribute_flags(flag) => rest,
        _ => arguments,
    };
    let operands = match arguments {
        [separator, rest @ ..] if separator == "--" => rest,
        _ => arguments,
    };
    let Some((destination, sources)) = operands.split_last() else {
        return false;
    };
    if sources.is_empty() || sources.len() > MAX_SOURCES || destination.starts_with('-') {
        return false;
    }
    let expanded =
        expand_home_read_path(destination, context.home_dir).unwrap_or_else(|| destination.clone());
    let Some(resolved) = joined_destination(&expanded, context) else {
        return false;
    };
    // The expansion below is a superset of the shell's (it ignores case), so
    // its count never decides whether cp writes into a directory: a glob
    // copy must name one with a trailing slash or an existing directory.
    let named_directory = expanded.ends_with('/') || resolved.is_dir();
    if !named_directory && sources.iter().any(|source| source.contains(['*', '?'])) {
        return false;
    }
    let Some(sources) = shell_words(sources, context) else {
        return false;
    };
    // cp places every source inside the destination when it names a
    // directory. With several sources, or a trailing slash, it never writes
    // the destination path itself.
    let into_directory = sources.len() > 1 || named_directory;
    let absolute = Path::new(&expanded).is_absolute();
    sources.iter().all(|source| {
        let target = if into_directory {
            match Path::new(source).file_name() {
                Some(name) => resolved.join(name),
                None => return false,
            }
        } else {
            resolved.clone()
        };
        source_allowed(source, context) && target_allowed(&target, absolute, created, context)
    })
}

/// `-c` (a copy-on-write clone on macOS, SELinux context on GNU), `-p` (keep
/// mode and times) and `-v` (name each copy), alone or joined in one word.
fn attribute_flags(word: &str) -> bool {
    word.strip_prefix('-').is_some_and(|letters| {
        !letters.is_empty()
            && letters
                .chars()
                .all(|letter| matches!(letter, 'c' | 'p' | 'v'))
    })
}

/// Where `cp -R` may create a new tree outside the workspace: a path the
/// user spelled absolutely that does not exist yet, in a private directory
/// the user owns below a temporary root, or directly in the user's own macOS
/// temporary folder. Plain `cp` places a new file there under the same screen.
///
/// Directly in the shared `/tmp` or `/var/tmp` the tree stays in review.
/// Another local user can create the folder between this check and the copy
/// and plant a link inside it, and `cp` would write through that link when it
/// fills the folder. A private parent leaves no one else able to create it.
pub(in crate::pretool) fn new_temporary_tree_target(
    spelled: &str,
    target: &Path,
    context: PathContext<'_>,
) -> bool {
    Path::new(spelled).is_absolute()
        && !shared_temporary_parent(target)
        && matches!(
            target.symlink_metadata(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        )
        && target
            .to_str()
            .is_some_and(|text| bounded_temporary_copy_target(text, context))
        && spelled_folders_private(target, context)
}

/// Every folder between the temporary root and the new tree, read as the
/// command spells it rather than where it resolves, is a real folder the user
/// owns and no one else may write to.
///
/// The screen above resolves the path, so it inspects wherever a link points
/// now. A link another user owns in `/tmp`, or a shared folder above the
/// private one, passes that screen and can be swapped for a planted tree
/// after the check, and `cp` would then write through a link inside it.
/// Reading each spelled folder without following it leaves nothing above the
/// new tree that another user can replace. The system links in front of the
/// root, `/tmp` and `/var` on macOS, are not walked.
#[cfg(unix)]
fn spelled_folders_private(target: &Path, context: PathContext<'_>) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Some(owner) = context
        .home_dir
        .and_then(|home| std::fs::metadata(home).ok())
        .map(|metadata| metadata.uid())
    else {
        return false;
    };
    let Some(parent) = target.parent() else {
        return false;
    };
    let private = |folder: &Path| {
        folder.symlink_metadata().is_ok_and(|metadata| {
            metadata.is_dir() && metadata.uid() == owner && metadata.mode() & 0o022 == 0
        })
    };
    // The user's own macOS temporary folder, as the environment spells it
    // and as it resolves, counts as a root only when it is already private.
    // The spelling is checked too, without its trailing slash so the check
    // reads the last name itself: a link there is no root of its own.
    let user_temporary: PathBuf = std::env::temp_dir().components().collect();
    let user_roots = std::fs::canonicalize(&user_temporary)
        .ok()
        .filter(|root| {
            root.starts_with("/private/var/folders") && private(root) && private(&user_temporary)
        })
        .map(|root| [user_temporary, root])
        .into_iter()
        .flatten();
    ["/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp"]
        .into_iter()
        .map(PathBuf::from)
        .chain(user_roots)
        .filter(|root| parent.starts_with(root))
        .any(|root| {
            parent
                .ancestors()
                .take_while(|folder| *folder != root)
                .all(private)
        })
}

/// Windows keeps its own temporary-folder screen above.
#[cfg(not(unix))]
fn spelled_folders_private(_target: &Path, _context: PathContext<'_>) -> bool {
    true
}

/// Whether the folder that would hold `target` is `/tmp` or `/var/tmp`
/// itself, where every local user may create entries.
fn shared_temporary_parent(target: &Path) -> bool {
    let Some(parent) = target
        .parent()
        .and_then(|parent| std::fs::canonicalize(parent).ok())
    else {
        return true;
    };
    ["/tmp", "/var/tmp"]
        .into_iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .any(|root| parent == root)
}

/// The operands cp receives once the shell expands `*` and `?` sources.
fn shell_words(sources: &[String], context: PathContext<'_>) -> Option<Vec<String>> {
    let mut words = Vec::new();
    for source in sources {
        if source.contains(['*', '?']) {
            words.extend(glob_file_matches(source, context)?);
        } else {
            words.push(source.clone());
        }
    }
    (words.len() <= MAX_EXPANDED_SOURCES).then_some(words)
}

fn joined_destination(expanded: &str, context: PathContext<'_>) -> Option<PathBuf> {
    let destination = Path::new(expanded);
    if destination.is_absolute() {
        return Some(destination.to_path_buf());
    }
    let cwd = context.cwd?;
    let cwd = expand_home_read_path(cwd, context.home_dir).unwrap_or_else(|| cwd.to_owned());
    Some(Path::new(&cwd).join(destination))
}

fn source_allowed(source: &str, context: PathContext<'_>) -> bool {
    !source.starts_with('-')
        && source.trim() == source
        && (bounded_file_read_target(source, context.home_dir, context.cwd)
            || absent_temporary_read_target(source, context.home_dir, context.cwd))
}

/// cp follows a destination link, so the resulting path must not be one and
/// must not alias a protected inode through a hard link.
fn target_allowed(
    target: &Path,
    absolute: bool,
    created: &[PathBuf],
    context: PathContext<'_>,
) -> bool {
    let Some(text) = target.to_str() else {
        return false;
    };
    !target
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
        && single_link_write_target(target)
        && (bounded_native_file_write_target(text, context.home_dir, context.cwd)
            // The temporary carve-out is only for destinations the user
            // spelled absolutely. A relative destination joined onto a /tmp
            // workspace must not sidestep the workspace boundary check above.
            || (absolute
                && ((bounded_temporary_copy_target(text, context)
                    && spelled_folders_private(target, context))
                    || created_scratch_child(target, text, created, context))))
}

/// A new file directly inside a scratch directory the chain creates. The
/// directory itself passed the temporary-target screens, so only the name
/// and the write-target floors of the file remain.
fn created_scratch_child(
    target: &Path,
    text: &str,
    created: &[PathBuf],
    context: PathContext<'_>,
) -> bool {
    let (Some(parent), Some(name)) = (target.parent(), target.file_name().and_then(|n| n.to_str()))
    else {
        return false;
    };
    created
        .iter()
        .any(|directory| directory.as_path() == parent)
        && !name.starts_with('.')
        && !text.contains([
            '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '[', ']', '{', '}',
        ])
        && !super::super::sensitive_read_path_argument(text)
        && !autostart_write_target(target)
        && !hooks_path::configured_hooks_write(target, context.home_dir, context.cwd)
}
