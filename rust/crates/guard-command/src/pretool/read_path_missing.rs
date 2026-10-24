//! Whether a shell read of an absolute path with nothing at it is bounded.

use super::resolved_path_allowed_for_operation;

/// `path` with its deepest existing ancestor canonicalized and the missing
/// components appended, the spelling the kernel would walk.
///
/// `std::fs::canonicalize` fails outright on a missing component, so a path
/// with nothing at it has no resolved form for the location screens to read.
fn weak_canonical_path(path: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut missing: Vec<&std::ffi::OsStr> = Vec::new();
    let mut prefix = path;
    loop {
        match std::fs::canonicalize(prefix) {
            Ok(mut resolved) => {
                resolved.extend(missing.iter().rev());
                return Some(resolved);
            }
            // Only a component the kernel reports absent may be appended and
            // the walk continued. Any other error leaves the rest of the path
            // unresolved: a link inside it could name anywhere, so there is no
            // spelling to screen and the read keeps its review.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return None,
        }
        missing.push(prefix.file_name()?);
        prefix = prefix.parent()?;
    }
}

/// Whether nothing is at `path`, as opposed to something this process may not
/// look at. Any error other than `ENOENT` leaves what is there unknown, and an
/// unknown file is not a missing one.
fn is_absent(path: &std::path::Path) -> bool {
    matches!(
        std::fs::symlink_metadata(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}

/// A shell read of an absolute path with no file at it.
///
/// The open fails with `ENOENT`, so the read returns nobody's bytes, and the
/// workspace-relative spelling of the same unresolvable path already passes
/// its own lexical floor. The path the kernel would walk still takes every
/// screen an existing file takes, so a missing name inside a credential
/// store or another guarded location keeps its review rather than answering
/// whether it is there.
pub(super) fn missing_absolute_read_allowed(
    path: &std::path::Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    weak_canonical_path(path).is_some_and(|resolved| {
        is_absent(&resolved)
            && resolved_path_allowed_for_operation(&resolved, home_dir, cwd, false, true)
    })
}

#[cfg(test)]
mod tests {
    use super::{missing_absolute_read_allowed, weak_canonical_path};
    use std::path::{Path, PathBuf};

    /// A home with a workspace below it, under a temporary root whose name is
    /// visible: a hidden component of its own would fail a different screen.
    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::Builder::new()
            .prefix("guard-missing-read")
            .tempdir()
            .expect("temporary directory");
        let home = std::fs::canonicalize(root.path()).expect("canonical root");
        let workspace = home.join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        (root, home, workspace)
    }

    #[test]
    fn resolves_the_existing_prefix_of_a_missing_path() {
        let (_root, _home, workspace) = fixture();
        let target = workspace.join("absent").join("notes.md");
        let resolved = weak_canonical_path(&target).expect("weak canonical path");
        assert_eq!(resolved, workspace.join("absent").join("notes.md"));
        assert_eq!(weak_canonical_path(&workspace), Some(workspace.clone()));
    }

    #[test]
    fn admits_a_missing_absolute_path_inside_the_workspace() {
        let (_root, home, workspace) = fixture();
        assert!(missing_absolute_read_allowed(
            &workspace.join("absent-notes.md"),
            home.to_str(),
            workspace.to_str()
        ));
        assert!(missing_absolute_read_allowed(
            &workspace.join("absent").join("notes.md"),
            home.to_str(),
            workspace.to_str()
        ));
    }

    #[test]
    fn refuses_a_file_that_is_there_and_a_guarded_location() {
        let (_root, home, workspace) = fixture();
        let present = workspace.join("present.md");
        std::fs::write(&present, "notes").expect("write");
        assert!(!missing_absolute_read_allowed(
            &present,
            home.to_str(),
            workspace.to_str()
        ));
        assert!(!missing_absolute_read_allowed(
            &workspace.join("secrets").join("absent.txt"),
            home.to_str(),
            workspace.to_str()
        ));
        assert!(!missing_absolute_read_allowed(
            Path::new("/etc/absent-9183.conf"),
            home.to_str(),
            workspace.to_str()
        ));
    }

    /// The admission is proven only while the path stays missing: a peer step
    /// that writes, links or creates a directory would put something there
    /// before the read opens it, so the whole command must create nothing.
    #[test]
    fn a_peer_step_that_could_plant_the_path_keeps_the_review() {
        let (_root, home, workspace) = fixture();
        let w = workspace.display();
        let context = crate::pretool::PathContext {
            home_dir: home.to_str(),
            cwd: workspace.to_str(),
            ..Default::default()
        };
        // `(command, the read's segment, whether the whole command is proven)`.
        // A planter runs before the read in some and after it in others: the
        // shell plants the path either way before the read opens it, so the
        // read's own segment must lose its proof in both orders.
        for (command, read, proven) in [
            (format!("cat {w}/absent-notes.md"), 0, true),
            (format!("head -5 {w}/absent/notes.md"), 0, true),
            (
                format!("ln -s {w}/present {w}/cfg && cat {w}/cfg/absent-notes.md"),
                1,
                false,
            ),
            (
                format!("mkdir -p {w}/cfg && cat {w}/cfg/notes.md"),
                1,
                false,
            ),
            (
                format!("touch {w}/absent-notes.md && cat {w}/absent-notes.md"),
                1,
                false,
            ),
            (
                format!("cat {w}/cfg/absent-notes.md; ln -s {w}/present {w}/cfg"),
                0,
                false,
            ),
            (
                format!("cat {w}/absent-notes.md && touch {w}/absent-notes.md"),
                0,
                false,
            ),
        ] {
            let model = crate::parse_command(&crate::CommandModelRequestV1 {
                command: command.clone(),
                dialect: "posix".to_owned(),
                transport: "shell_string".to_owned(),
                extraction_provenance: "guard-shell".to_owned(),
            })
            .expect("command model");
            let covered = crate::pretool::benign_command_segments(&model, context);
            assert_eq!(covered.len() == model.segments.len(), proven, "{command}");
            // Not merely fewer proofs than segments: the read itself is the
            // segment that must keep its review when anything could plant it.
            assert_eq!(covered.contains(&read), proven, "{command}");
        }
    }

    /// A link whose destination cannot be traversed resolves to nothing the
    /// screens can read. Reporting that as absence would let the read's own
    /// spelling stand in for a destination nobody screened.
    #[cfg(unix)]
    #[test]
    fn a_link_whose_destination_cannot_be_traversed_keeps_the_review() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let (_root, home, workspace) = fixture();
        let locked = workspace.join("locked");
        std::fs::create_dir_all(locked.join("inner")).expect("inner directory");
        symlink(locked.join("inner"), workspace.join("cfg")).expect("link");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("lock");
        let blocked = std::fs::read_dir(&locked).is_err();
        let allowed = missing_absolute_read_allowed(
            &workspace.join("cfg").join("absent-notes.md"),
            home.to_str(),
            workspace.to_str(),
        );
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).expect("unlock");
        // A container that runs this as root traverses the directory anyway,
        // and then the path is an ordinary missing name under the workspace.
        if blocked {
            assert!(!allowed);
        }
    }
}
