//! New links and single-file removals inside the workspace.
//!
//! Both mirror the `mv` proof: every path is screened with the same bounded
//! write target, so a link or removal never reaches a hidden, sensitive or
//! autostart location, and never leaves the workspace or a sibling worktree
//! of the same repository.
use super::read_paths::{existing_regular_read_target, expand_home_read_path};
use super::safe_writes::{absent_move_destination, bounded_file_write_target};

/// `ln -s SOURCE LINK` that only adds a new link inside the workspace or a
/// sibling worktree of the same repository.
///
/// A relative source resolves against the link's directory, not the cwd.
/// Containment uses the canonical target. The read screen keeps the source's
/// own names, so a symlink in that spelling stays reviewed. The source may be
/// a directory but never the home directory or one
/// of its ancestors, and never a path that contains the workspace: later reads
/// through the link still resolve to the target, yet a link that exposes the
/// whole home is not routine.
pub(super) fn safe_symlink_arguments(
    source: &str,
    destination: &str,
    context: super::PathContext<'_>,
) -> bool {
    if source.starts_with('-')
        || destination.starts_with('-')
        || source.trim() != source
        || !workspace_below_home(context)
    {
        return false;
    }
    let Some(screened) = screened_source(source, destination, context) else {
        return false;
    };
    let Ok(target) = std::fs::canonicalize(&screened.absolute) else {
        return false;
    };
    let contains_session_root = [context.home_dir, context.cwd]
        .into_iter()
        .flatten()
        .filter_map(|root| {
            let root =
                expand_home_read_path(root, context.home_dir).unwrap_or_else(|| root.to_owned());
            std::fs::canonicalize(root).ok()
        })
        .any(|root| root.starts_with(&target));
    !contains_session_root
        && super::read_paths::bounded_read_target(
            &screened.as_screened,
            context.home_dir,
            context.cwd,
            true,
        )
        && bounded_file_write_target(destination, context.home_dir, context.cwd)
        && absent_move_destination(destination, context)
}

/// The two spellings of a link's source: the absolute path the link will point
/// at, and the path the bounded read target screens.
struct ScreenedSource {
    absolute: String,
    as_screened: String,
}

/// Resolve a link's source the way the kernel will resolve it.
///
/// An absolute or `~/` source is screened as written. A relative source
/// resolves against the directory holding the new link, which is where the
/// kernel resolves it from, so the screens run on the path the link actually
/// reaches rather than on a spelling that means nothing on its own.
///
/// Only the leading directory is resolved, and each `..` is taken off a
/// directory proven not to be a link. The source's own names stay as written,
/// because the read screen reads them: a link inside the spelling still has to
/// prove itself there, exactly as one inside an absolute source does, and a
/// name below the home directory still has to be spelled that way to pass for
/// an installed package's file. Handing the screen a canonical path instead
/// would answer both of those questions by erasing them.
fn screened_source(
    source: &str,
    destination: &str,
    context: super::PathContext<'_>,
) -> Option<ScreenedSource> {
    if let Some(absolute) = expand_home_read_path(source, context.home_dir) {
        return Some(ScreenedSource {
            absolute,
            as_screened: source.to_owned(),
        });
    }
    if std::path::Path::new(source).is_absolute() {
        return Some(ScreenedSource {
            absolute: source.to_owned(),
            as_screened: source.to_owned(),
        });
    }
    let joined = link_directory(destination, context)?.join(source);
    let walked = walked_source_path(&joined)?;
    Some(ScreenedSource {
        absolute: std::fs::canonicalize(&joined).ok()?.to_str()?.to_owned(),
        as_screened: walked.to_str()?.to_owned(),
    })
}

/// `path` with its `.` and `..` components taken off, leaving every name it
/// walks through as written.
///
/// The kernel resolves `..` against what the preceding component really is,
/// so a `..` after a link lands beside the link's target rather than beside
/// the link. Each `..` therefore has to come off a directory this walk has
/// proven is not a link; anything else leaves no spelling to screen, and the
/// link keeps its review.
fn walked_source_path(path: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut walked = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                let metadata = std::fs::symlink_metadata(&walked).ok()?;
                if !metadata.is_dir() || !walked.pop() {
                    return None;
                }
            }
            other => walked.push(other.as_os_str()),
        }
    }
    Some(walked)
}

/// The directory that will hold the new link: a relative destination resolves
/// against the cwd, an absolute one is taken as written.
fn link_directory(
    destination: &str,
    context: super::PathContext<'_>,
) -> Option<std::path::PathBuf> {
    let destination = expand_home_read_path(destination, context.home_dir)
        .unwrap_or_else(|| destination.to_owned());
    let destination = std::path::PathBuf::from(destination);
    let destination = if destination.is_absolute() {
        destination
    } else {
        let cwd = context.cwd?;
        let cwd = expand_home_read_path(cwd, context.home_dir).unwrap_or_else(|| cwd.to_owned());
        std::path::PathBuf::from(cwd).join(destination)
    };
    std::fs::canonicalize(destination.parent()?).ok()
}

/// `rm [-f] [--] FILE...` over a few existing regular files in the workspace.
///
/// Each operand must be the file itself, not a link, so the screen applies to
/// the entry that is removed. The one link admitted is one at the root of a
/// linked worktree of the session's repository, such as a shared
/// `node_modules`: removing it leaves its target alone. Directories,
/// recursion and home-wide paths stay under review.
pub(super) fn safe_remove_arguments(arguments: &[String], context: super::PathContext<'_>) -> bool {
    if !workspace_below_home(context) {
        return false;
    }
    let mut options = true;
    let mut operands = 0;
    for argument in arguments {
        if options && argument == "--" {
            options = false;
            continue;
        }
        if options && argument == "-f" {
            continue;
        }
        if argument.starts_with('-') {
            return false;
        }
        options = false;
        operands += 1;
        if operands > 16
            || !(removable_regular_file(argument, context)
                || super::directory_targets::sibling::removable_link(argument, context))
        {
            return false;
        }
    }
    operands > 0
}

fn removable_regular_file(value: &str, context: super::PathContext<'_>) -> bool {
    let expanded =
        expand_home_read_path(value, context.home_dir).unwrap_or_else(|| value.to_owned());
    let supplied = std::path::Path::new(&expanded);
    let entry = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else if let Some(cwd) = context.cwd {
        std::path::Path::new(
            &expand_home_read_path(cwd, context.home_dir).unwrap_or_else(|| cwd.to_owned()),
        )
        .join(supplied)
    } else {
        return false;
    };
    entry
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_file())
        && existing_regular_read_target(value, context.home_dir, context.cwd)
        && bounded_file_write_target(value, context.home_dir, context.cwd)
}

/// A session started in the home directory, or above it, has no workspace
/// boundary: every visible file in the home would count as a workspace file.
fn workspace_below_home(context: super::PathContext<'_>) -> bool {
    let (Some(home), Some(cwd)) = (context.home_dir, context.cwd) else {
        return false;
    };
    let cwd = expand_home_read_path(cwd, Some(home)).unwrap_or_else(|| cwd.to_owned());
    match (std::fs::canonicalize(home), std::fs::canonicalize(cwd)) {
        (Ok(home), Ok(cwd)) => !home.starts_with(cwd),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::screened_source;

    /// A home with a workspace below it, a hidden store beside the workspace,
    /// and a link in the workspace that reaches that store. The root is
    /// canonicalized so the temporary area's own links (`/var` on macOS) do
    /// not stand in for the one under test.
    #[cfg(unix)]
    fn fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let root = tempfile::Builder::new()
            .prefix("guard-link-source")
            .tempdir()
            .expect("temporary root");
        let home = std::fs::canonicalize(root.path())
            .expect("canonical root")
            .join("home");
        let workspace = home.join("ws");
        let store = home.join(".config").join("app");
        std::fs::create_dir_all(workspace.join("pkg")).expect("workspace");
        std::fs::create_dir_all(&store).expect("store");
        std::fs::write(store.join("settings.json"), "{}\n").expect("settings");
        std::fs::write(workspace.join("pkg").join("file.txt"), "x\n").expect("file");
        std::os::unix::fs::symlink(&store, workspace.join("alias")).expect("alias");
        (root, home, workspace)
    }

    /// The screened spelling keeps the source's own components, so a link
    /// inside a relative source still reaches the read screen as a link. A
    /// canonical spelling would answer the screen's question for it: nothing
    /// in it is a link any more, and a store below the home directory ends up
    /// spelled the way an installed package's own file is spelled.
    ///
    /// Only the test is Unix-only, for the symlink it plants; the screened
    /// spelling itself is built the same way on every platform.
    #[test]
    #[cfg(unix)]
    fn a_relative_source_is_screened_with_its_own_components() {
        let (_root, home, workspace) = fixture();
        let context = super::super::PathContext {
            home_dir: home.to_str(),
            cwd: workspace.to_str(),
            ..Default::default()
        };

        let screened = screened_source("alias/settings.json", "link", context).expect("screened");
        assert_eq!(
            screened.as_screened,
            workspace
                .join("alias")
                .join("settings.json")
                .to_string_lossy()
        );
        assert!(guard_secure_fs::contains_symlink_component(
            std::path::Path::new(&screened.as_screened)
        ));
        assert_eq!(
            screened.absolute,
            home.join(".config")
                .join("app")
                .join("settings.json")
                .to_string_lossy()
        );

        let plain = screened_source("pkg/file.txt", "link", context).expect("screened");
        assert_eq!(
            plain.as_screened,
            workspace.join("pkg").join("file.txt").to_string_lossy()
        );
        assert!(!guard_secure_fs::contains_symlink_component(
            std::path::Path::new(&plain.as_screened)
        ));

        // The admission is the decision under review: the link spelling stays
        // reviewed, and a relative source with no link in it stays allowed.
        assert!(!super::safe_symlink_arguments(
            "alias/settings.json",
            "from-alias",
            context,
        ));
        assert!(super::safe_symlink_arguments(
            "pkg/file.txt",
            "from-pkg",
            context,
        ));
        std::fs::create_dir_all(workspace.join("web")).expect("web");
        assert!(!super::safe_symlink_arguments(
            "../alias/settings.json",
            "web/from-alias",
            context,
        ));
        assert!(super::safe_symlink_arguments(
            "../pkg/file.txt",
            "web/from-pkg",
            context,
        ));
        let absolute = workspace.join("alias").join("settings.json");
        assert!(!super::safe_symlink_arguments(
            absolute.to_str().expect("utf8"),
            "from-absolute",
            context,
        ));

        // A `..` the kernel would resolve against a link's target leaves no
        // spelling to screen, so the walk gives one back.
        assert!(screened_source("alias/../pkg/file.txt", "link", context).is_none());
    }
}
