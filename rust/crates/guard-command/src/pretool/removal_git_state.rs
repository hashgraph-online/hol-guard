//! Whether a temporary-file removal leaves the Git state a later read
//! depends on.
use super::safe_links::{removal_operands, temporary_removal_segment};
use super::search_scope_plain_skips::{git_directories, read_small};
use std::path::{Path, PathBuf};

/// Attributes that make Git run a configured program: a clean or smudge
/// filter, a diff driver or textconv, and a merge driver.
const PROGRAM_ATTRIBUTES: &[&str] = &["filter", "diff", "merge"];

/// Whether this step is a temporary-file removal (see
/// `temporary_removal_segments`) that leaves Git's configuration and
/// attributes as the probe read them, so a Git read after it keeps its own
/// helper proof.
///
/// Git reads a configuration entry only below a `[section]` header, so a
/// file with no `[` in it adds nothing to a configuration that includes it,
/// and removing it changes none. A file that names a program attribute can
/// be an attributes file whose override the probe relied on, so it keeps the
/// review. So does a dotfile, a file below a `.git` directory, below the Git
/// directory the read uses or below the directory the read runs in, which
/// can be an attributes, ignore or mailmap file that steers what the read
/// runs. The scan reads at most a bounded prefix, and a file that grows past
/// it keeps the review. A name that is already gone removes nothing.
pub(super) fn temporary_removal_leaves_git_config(
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    if !temporary_removal_segment(segment, context) {
        return false;
    }
    let read_root = context.cwd.and_then(|cwd| std::fs::canonicalize(cwd).ok());
    let Some(git_directories) = read_git_directories(read_root.as_deref()) else {
        return false;
    };
    removal_operands(&segment.arguments).all(|operand| {
        let path = Path::new(operand);
        let metadata = match path.symlink_metadata() {
            Err(error) => return error.kind() == std::io::ErrorKind::NotFound,
            Ok(metadata) => metadata,
        };
        let Ok(canonical) = std::fs::canonicalize(path) else {
            return false;
        };
        metadata.file_type().is_file()
            && !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_none_or(|name| name.starts_with('.'))
            && !canonical
                .components()
                .any(|part| part.as_os_str().eq_ignore_ascii_case(".git"))
            && read_root
                .as_ref()
                .is_none_or(|root| !canonical.starts_with(root))
            && !git_directories
                .iter()
                .any(|directory| canonical.starts_with(directory))
            && matches!(read_small(&canonical), Ok(Some(text)) if leaves_config_and_attributes(&text))
    })
}

/// The Git directories a read from `root` uses: the first `.git` entry in
/// `root` or above it, resolved through a `gitdir:` file and its common
/// directory. `None` when an entry cannot be read, so the removal keeps the
/// review.
fn read_git_directories(root: Option<&Path>) -> Option<Vec<PathBuf>> {
    let Some(root) = root else {
        return Some(Vec::new());
    };
    let Some(git) = root
        .ancestors()
        .map(|directory| directory.join(".git"))
        .find(|git| git.symlink_metadata().is_ok())
    else {
        return Some(Vec::new());
    };
    git_directories(&git)?
        .into_iter()
        .map(|directory| std::fs::canonicalize(directory).ok())
        .collect()
}

/// Whether removing a file with this text changes no configuration section
/// and no program attribute an attributes file could set or unset.
fn leaves_config_and_attributes(text: &str) -> bool {
    !text.contains('[')
        && !text.lines().any(|line| {
            line.split_whitespace().skip(1).any(|word| {
                let name = word.trim_start_matches(['-', '!']);
                let name = name.split('=').next().unwrap_or(name);
                PROGRAM_ATTRIBUTES
                    .iter()
                    .any(|attribute| name.eq_ignore_ascii_case(attribute))
            })
        })
}

#[cfg(test)]
mod tests {
    use super::leaves_config_and_attributes;

    #[test]
    fn program_attributes_keep_the_review() {
        for text in [
            "* -filter\n",
            "*.txt filter=lfs diff=lfs\n",
            "\"a b\" !diff\n",
            "*.bin -MERGE\n",
            "[core]\n\tpager = cat\n",
        ] {
            assert!(!leaves_config_and_attributes(text), "{text:?}");
        }
        for text in ["build finished\n", "filter\n", "*.txt text eol=lf\n", ""] {
            assert!(leaves_config_and_attributes(text), "{text:?}");
        }
    }
}
