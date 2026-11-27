//! Whether a temporary-file removal leaves the Git state a later read
//! depends on.
use super::removal_git_sources::{attribute_sources, SourceRoots};
use super::safe_links::{removal_operands, temporary_removal_segment};
use super::search_scope_plain_skips::{git_directories, read_small};
use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::path::{Path, PathBuf};

/// Attributes that make Git run a configured program: a clean or smudge
/// filter, a diff driver or textconv, and a merge driver, plus the built-in
/// `binary` macro, which unsets `diff` and `merge`.
const PROGRAM_ATTRIBUTES: &[&str] = &["filter", "diff", "merge", "binary"];

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
///
/// An attributes file Git reads, such as a linked `info/attributes` or the
/// file `core.attributesFile` names, keeps the review whatever it holds: a
/// macro defined elsewhere can make any word in it unset a filter.
pub(super) fn temporary_removal_leaves_git_config(
    segment: &CommandSegmentV1,
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> bool {
    if !temporary_removal_segment(segment, context) {
        return false;
    }
    let Some(read_roots) = read_roots(model, context.cwd) else {
        return false;
    };
    let mut git_directories = Vec::new();
    for root in &read_roots {
        let Some(directories) = read_git_directories(Some(root)) else {
            return false;
        };
        git_directories.extend(directories);
    }
    let home = context.home_dir.map(Path::new);
    let Some(attribute_sources) =
        attribute_sources(&SourceRoots::session(), home, &git_directories)
    else {
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
            && !read_roots.iter().any(|root| canonical.starts_with(root))
            && !git_directories
                .iter()
                .any(|directory| canonical.starts_with(directory))
            && !attribute_sources.contains(&canonical)
            && matches!(read_small(&canonical), Ok(Some(text)) if leaves_config_and_attributes(&text))
    })
}

/// The directories the chain's Git steps run in, resolved through links:
/// the working directory, moved by each step's `-C`. Git reads only the
/// repository its own directory is in. `None` when a step
/// names its repository, work tree or configuration another way, or a
/// directory cannot be resolved, so the removal keeps the review.
fn read_roots(model: &CanonicalCommandV1, cwd: Option<&str>) -> Option<Vec<PathBuf>> {
    let cwd = match cwd {
        Some(cwd) => Some(std::fs::canonicalize(cwd).ok()?),
        None => None,
    };
    let mut roots: Vec<PathBuf> = Vec::new();
    for segment in &model.segments {
        if segment.executable.as_deref() != Some("git") {
            continue;
        }
        let mut route = cwd.clone();
        let mut arguments = segment.arguments.iter();
        while let Some(argument) = arguments.next() {
            if argument == "-C" {
                let directory = Path::new(arguments.next()?);
                let joined = match &route {
                    Some(route) => route.join(directory),
                    None if directory.is_absolute() => directory.to_path_buf(),
                    None => return None,
                };
                route = Some(std::fs::canonicalize(joined).ok()?);
            } else if ["-c", "--git-dir", "--work-tree", "--config-env"]
                .iter()
                .any(|option| {
                    argument == option
                        || argument
                            .strip_prefix(option)
                            .is_some_and(|rest| rest.starts_with('='))
                })
            {
                return None;
            } else if argument == "--namespace" {
                arguments.next();
            } else if !argument.starts_with('-') {
                break;
            }
        }
        if let Some(route) = route {
            if !roots.contains(&route) {
                roots.push(route);
            }
        }
    }
    Some(roots)
}

/// The Git directories a read from `root` uses: the first `.git` entry in
/// `root` or above it, resolved through a `gitdir:` file and its common
/// directory, and every directory on the way up that can itself be a Git
/// directory, as a bare repository is to a read from its `refs`. `None` when
/// an entry cannot be read, so the removal keeps the review.
fn read_git_directories(root: Option<&Path>) -> Option<Vec<PathBuf>> {
    let Some(root) = root else {
        return Some(Vec::new());
    };
    let mut directories = Vec::new();
    for directory in root.ancestors() {
        let git = directory.join(".git");
        if git.symlink_metadata().is_ok() {
            directories.extend(git_directories(&git)?);
            break;
        }
        if can_be_git_directory(directory) {
            directories.push(directory.to_path_buf());
            match read_small(&directory.join("commondir")) {
                Ok(Some(common)) => directories.push(directory.join(common.trim())),
                Ok(None) => {}
                Err(()) => return None,
            }
        }
    }
    directories
        .into_iter()
        .map(|directory| std::fs::canonicalize(directory).ok())
        .collect()
}

/// Whether Git could take this directory for a Git directory: it holds a
/// `HEAD` entry beside `refs`, `objects` or a `commondir` file. Git asks
/// more of it, so this also counts some directories Git would pass over,
/// which only keeps more removals reviewed.
fn can_be_git_directory(directory: &Path) -> bool {
    directory.join("HEAD").symlink_metadata().is_ok()
        && ["refs", "objects", "commondir"]
            .iter()
            .any(|entry| directory.join(entry).symlink_metadata().is_ok())
}

/// Whether removing a file with this text changes no configuration section
/// and no program attribute an attributes file could set or unset.
fn leaves_config_and_attributes(text: &str) -> bool {
    !text.contains('[')
        && !text.lines().any(|line| {
            // Git reads a quoted pattern to its closing quote, and an
            // attribute may follow that quote directly, as in
            // `"*.txt"-filter`, so a quoted line is read word by word.
            let quoted = line.trim_start().starts_with('"');
            line.split(|character: char| character.is_whitespace() || character == '"')
                .filter(|word| !word.is_empty())
                .skip(usize::from(!quoted))
                .any(|word| {
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
            "*.json binary\n",
            "\"*.txt\"-filter\n",
            "  \"*.txt\"\t!diff\n",
            "[core]\n\tpager = cat\n",
        ] {
            assert!(!leaves_config_and_attributes(text), "{text:?}");
        }
        for text in ["build finished\n", "filter\n", "*.txt text eol=lf\n", ""] {
            assert!(leaves_config_and_attributes(text), "{text:?}");
        }
    }
}
