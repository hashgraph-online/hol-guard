//! Whether a temporary-file removal leaves the Git state a later read
//! depends on.
use super::safe_links::{removal_operands, temporary_removal_segment};
use super::search_scope_plain_skips::{git_directories, read_small};
use std::path::{Path, PathBuf};

/// Attributes that make Git run a configured program: a clean or smudge
/// filter, a diff driver or textconv, and a merge driver, plus the built-in
/// `binary` macro, which unsets `diff` and `merge`.
const PROGRAM_ATTRIBUTES: &[&str] = &["filter", "diff", "merge", "binary"];

/// More configuration files than this, counting the ones they include, keep
/// the review.
const MAX_CONFIG_FILES: usize = 16;

/// Configuration files Git reads outside the repository.
const SYSTEM_CONFIGS: &[&str] = &[
    "/etc/gitconfig",
    "/opt/homebrew/etc/gitconfig",
    "/usr/local/etc/gitconfig",
];

/// Attributes files Git reads outside the repository.
const SYSTEM_ATTRIBUTES: &[&str] = &[
    "/etc/gitattributes",
    "/opt/homebrew/etc/gitattributes",
    "/usr/local/etc/gitattributes",
];

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
    let home = context.home_dir.map(Path::new);
    let Some(attribute_sources) = attribute_sources(home, &git_directories) else {
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
            && !attribute_sources.contains(&canonical)
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

/// The attributes files Git reads outside the work tree, resolved through
/// links: each Git directory's `info/attributes`, the user and system files,
/// and every `core.attributesFile` the configuration names, following its
/// includes. `None` when a setting names a file this cannot place or a
/// configuration file cannot be read.
fn attribute_sources(home: Option<&Path>, git_directories: &[PathBuf]) -> Option<Vec<PathBuf>> {
    let xdg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let mut configs: Vec<PathBuf> = SYSTEM_CONFIGS.iter().map(PathBuf::from).collect();
    let mut sources: Vec<PathBuf> = SYSTEM_ATTRIBUTES.iter().map(PathBuf::from).collect();
    if let Some(home) = home {
        configs.extend([home.join(".gitconfig"), home.join(".config/git/config")]);
        sources.push(home.join(".config/git/attributes"));
    }
    if let Some(xdg) = &xdg {
        configs.push(xdg.join("git/config"));
        sources.push(xdg.join("git/attributes"));
    }
    for directory in git_directories {
        configs.extend([directory.join("config"), directory.join("config.worktree")]);
        sources.push(directory.join("info/attributes"));
    }
    let named = configs.len();
    let mut index = 0;
    while let Some(config) = configs.get(index).cloned() {
        index += 1;
        let Some(text) = read_small(&config).ok()? else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with(['#', ';']) {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim().trim_matches('"').trim();
            let placed = match (value.strip_prefix("~/"), home) {
                (Some(rest), Some(home)) => Some(home.join(rest)),
                _ if Path::new(value).is_absolute() => Some(PathBuf::from(value)),
                _ => None,
            };
            match key.trim().to_ascii_lowercase().as_str() {
                // Git resolves a relative attributes path against the
                // directory it runs in, which a later step may change.
                "attributesfile" => sources.push(placed?),
                // An include, also under `includeIf`, is read relative to the
                // file that names it. Reading every `path` can only add files.
                "path" => {
                    if configs.len() >= named + MAX_CONFIG_FILES {
                        return None;
                    }
                    configs.push(match placed {
                        Some(path) => path,
                        None => config.parent()?.join(value),
                    });
                }
                _ => {}
            }
        }
    }
    Some(
        sources
            .iter()
            .filter_map(|source| std::fs::canonicalize(source).ok())
            .collect(),
    )
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
    use super::{attribute_sources, leaves_config_and_attributes};
    use std::path::{Path, PathBuf};

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(name: &str) -> Scratch {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/removal-git-state")
            .join(format!("{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("home")).unwrap();
        std::fs::create_dir_all(root.join("git")).unwrap();
        Scratch(std::fs::canonicalize(root).unwrap())
    }

    #[test]
    fn configured_and_included_attributes_files_are_sources() {
        let scratch = scratch("sources");
        let home = scratch.0.join("home");
        let git = scratch.0.join("git");
        std::fs::write(scratch.0.join("global.attrs"), "*.txt quiet\n").unwrap();
        std::fs::write(scratch.0.join("included.attrs"), "*.md quiet\n").unwrap();
        std::fs::write(
            home.join(".gitconfig"),
            "[core]\n\tattributesFile = ~/../global.attrs\n[include]\n\tpath = ../extra.conf\n",
        )
        .unwrap();
        std::fs::write(
            scratch.0.join("extra.conf"),
            format!(
                "[core]\n\tattributesfile = \"{}\"\n",
                scratch.0.join("included.attrs").display()
            ),
        )
        .unwrap();
        let sources = attribute_sources(Some(&home), std::slice::from_ref(&git)).unwrap();
        assert!(
            sources.contains(&scratch.0.join("global.attrs")),
            "{sources:?}"
        );
        assert!(
            sources.contains(&scratch.0.join("included.attrs")),
            "{sources:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_info_attributes_file_is_its_target() {
        let scratch = scratch("linked");
        let git = scratch.0.join("git");
        std::fs::write(scratch.0.join("quiet.txt"), "*.txt quiet\n").unwrap();
        std::fs::create_dir(git.join("info")).unwrap();
        std::os::unix::fs::symlink(scratch.0.join("quiet.txt"), git.join("info/attributes"))
            .unwrap();
        let sources = attribute_sources(Some(&scratch.0.join("home")), &[git]).unwrap();
        assert!(
            sources.contains(&scratch.0.join("quiet.txt")),
            "{sources:?}"
        );
    }

    #[test]
    fn an_attributes_path_that_cannot_be_placed_keeps_the_review() {
        let scratch = scratch("unplaced");
        let git = scratch.0.join("git");
        std::fs::write(git.join("config"), "[core]\n\tattributesFile = attrs\n").unwrap();
        assert_eq!(
            attribute_sources(Some(&scratch.0.join("home")), &[git]),
            None
        );
    }

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
