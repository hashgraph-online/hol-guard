//! Preserve linked-destination refusals when trying broader containment.

use crate::CanonicalCommandV1;
use std::path::Path;

#[path = "workspace_contained_cwd.rs"]
mod cwd;

#[cfg(unix)]
fn linked_file(path: &Path, workspace: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    // A parent symlink is followed by the write, while the lexical path still
    // looks workspace-relative. Absence of a later component stops the walk;
    // any other inspection failure cannot establish a safe destination.
    match symlink_parent(path, workspace) {
        Some(false) => {}
        Some(true) | None => return true,
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => true,
        Ok(metadata) => metadata.is_file() && metadata.nlink() != 1,
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    }
}

/// `Some(true)` when a parent of `path` is a symlink or cannot be inspected.
/// `None` means `path` is not under `workspace`, which also declines.
#[cfg(unix)]
fn symlink_parent(path: &Path, workspace: &Path) -> Option<bool> {
    let relative = path.strip_prefix(workspace).ok()?;
    let mut current = workspace.to_path_buf();
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            break;
        }
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Some(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Some(true),
        }
    }
    Some(false)
}

#[cfg(not(unix))]
fn linked_file(_path: &Path, _workspace: &Path) -> bool {
    // Workspace containment is not admitted on non-Unix platforms.
    false
}

pub(super) fn unbounded_linked_writes(model: &CanonicalCommandV1, workspace: &Path) -> bool {
    if !model.segments.iter().any(|segment| {
        segment
            .executable
            .as_deref()
            .is_some_and(|name| matches!(super::super::executable_basename(name), "cp" | "touch"))
    }) {
        return false;
    }
    let Some(locations) = cwd::locations(model, workspace) else {
        return true;
    };
    model
        .segments
        .iter()
        .zip(locations)
        .any(|(segment, locations)| {
            let name = super::super::executable_basename(
                segment.executable.as_deref().unwrap_or_default(),
            );
            locations
                .iter()
                .any(|cwd| mutates_linked_destination(name, &segment.arguments, cwd))
        })
}

fn mutates_linked_destination(name: &str, arguments: &[String], workspace: &Path) -> bool {
    if arguments.iter().any(|value| {
        value
            .chars()
            .any(|c| matches!(c, '*' | '?' | '[' | ']' | '$' | '\u{60}' | '{' | '}'))
    }) {
        return true;
    }
    match name {
        "cp" => copy_targets(arguments, workspace).unwrap_or(true),
        "touch" => touch_targets(arguments)
            .map(|targets| {
                targets
                    .iter()
                    .any(|target| linked_file(&workspace.join(target), workspace))
            })
            .unwrap_or(true),
        _ => false,
    }
}

fn touch_targets(arguments: &[String]) -> Option<Vec<&str>> {
    let mut targets = Vec::new();
    let mut options = true;
    let mut args = arguments.iter();
    while let Some(arg) = args.next() {
        if options && arg == "--" {
            options = false;
            continue;
        }
        if options && arg.starts_with('-') {
            match arg.as_str() {
                "-d" | "-t" | "-r" | "--date" | "--reference" | "--time" => {
                    args.next()?;
                }
                "--no-create" | "--no-dereference" => {}
                value
                    if value.starts_with("--date=")
                        || value.starts_with("--reference=")
                        || value.starts_with("--time=") => {}
                value
                    if value.starts_with('-')
                        && !value.starts_with("--")
                        && value.len() > 1
                        && value[1..].chars().all(|c| "amch".contains(c)) => {}
                _ => return None,
            }
        } else {
            targets.push(arg.as_str());
        }
    }
    (!targets.is_empty()).then_some(targets)
}

fn copy_targets(arguments: &[String], workspace: &Path) -> Option<bool> {
    let mut paths = Vec::new();
    let mut target_directory = None;
    let mut recursive = false;
    let mut no_target_directory = false;
    let mut options = true;
    let mut args = arguments.iter();
    while let Some(arg) = args.next() {
        if options && arg == "--" {
            options = false;
            continue;
        }
        if options && arg.starts_with('-') {
            match arg.as_str() {
                "-t" | "--target-directory" => {
                    target_directory = Some(args.next()?.as_str());
                }
                "-S" | "--suffix" => {
                    args.next()?;
                }
                "-T" | "--no-target-directory" => no_target_directory = true,
                "--recursive" | "--archive" => recursive = true,
                "--force"
                | "--interactive"
                | "--no-clobber"
                | "--preserve"
                | "--verbose"
                | "--dereference"
                | "--no-dereference"
                | "--remove-destination" => {}
                value if value.starts_with("--target-directory=") => {
                    target_directory = Some(value.strip_prefix("--target-directory=")?);
                }
                value if value.starts_with("--preserve=") || value.starts_with("--suffix=") => {}
                value
                    if value.starts_with('-')
                        && !value.starts_with("--")
                        && value.len() > 1
                        && value[1..].chars().all(|c| "afHiLnPpRrvXbuc".contains(c)) =>
                {
                    recursive |= value[1..].chars().any(|c| "aRr".contains(c));
                }
                _ => return None,
            }
        } else {
            paths.push(arg.as_str());
        }
    }
    let destination = if let Some(directory) = target_directory {
        if no_target_directory {
            return None;
        }
        workspace.join(directory)
    } else {
        workspace.join(paths.pop()?)
    };
    if paths.is_empty() {
        return None;
    }
    let directory = target_directory.is_some() || (!no_target_directory && destination.is_dir());
    let mut remaining = 4096;
    for source in paths {
        let source_path = workspace.join(source);
        let target = if directory {
            destination.join(source_path.file_name()?)
        } else {
            destination.clone()
        };
        if linked_copy_tree(&source_path, &target, workspace, recursive, &mut remaining)? {
            return Some(true);
        }
    }
    Some(false)
}

fn linked_copy_tree(
    source: &Path,
    destination: &Path,
    workspace: &Path,
    recursive: bool,
    remaining: &mut usize,
) -> Option<bool> {
    if linked_file(destination, workspace) {
        return Some(true);
    }
    if !recursive || !source.is_dir() || !destination.exists() {
        return Some(false);
    }
    if source.symlink_metadata().ok()?.file_type().is_symlink() {
        return None;
    }
    for child in std::fs::read_dir(source).ok()? {
        *remaining = remaining.checked_sub(1)?;
        let child = child.ok()?;
        if linked_copy_tree(
            &child.path(),
            &destination.join(child.file_name()),
            workspace,
            true,
            remaining,
        )? {
            return Some(true);
        }
    }
    Some(false)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Workspace(PathBuf);

    impl Drop for Workspace {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn linked_destinations_are_refused_but_sources_and_plain_writes_stay_available() {
        let mut root = Workspace(std::env::temp_dir().join(format!(
            "guard-linked-write-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        )));
        std::fs::create_dir(&root.0).unwrap();
        root.0 = root.0.canonicalize().unwrap();
        let workspace = root.0.as_path();
        std::fs::write(workspace.join("protected"), b"sentinel").unwrap();
        std::fs::hard_link(workspace.join("protected"), workspace.join("linked")).unwrap();
        std::fs::write(workspace.join("source"), b"ordinary").unwrap();
        std::fs::write(workspace.join("second"), b"ordinary").unwrap();
        std::fs::create_dir(workspace.join("destination")).unwrap();
        std::fs::hard_link(
            workspace.join("protected"),
            workspace.join("destination/source"),
        )
        .unwrap();
        for (name, args, expected) in [
            ("cp", vec!["source", "linked"], true),
            ("cp", vec!["--", "source", "linked"], true),
            ("touch", vec!["linked"], true),
            ("touch", vec!["--", "linked"], true),
            ("cp", vec!["-fp", "source", "linked"], true),
            ("cp", vec!["--force", "source", "linked"], true),
            ("cp", vec!["source", "second", "destination"], true),
            ("cp", vec!["-t", "destination", "source"], true),
            ("touch", vec!["-cm", "linked"], true),
            ("touch", vec!["source", "linked"], true),
            ("cp", vec!["--unknown", "source", "new"], true),
            ("cp", vec!["source", "linked*"], true),
            ("cp", vec!["linked", "new"], false),
            ("cp", vec!["-fp", "source", "new"], false),
            ("touch", vec!["new"], false),
            ("touch", vec!["-m", "new"], false),
            ("touch", vec!["-r", "linked", "source"], false),
            ("echo", vec!["linked"], false),
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert_eq!(mutates_linked_destination(name, &args, workspace), expected);
            let model = crate::parse_command(&crate::CommandModelRequestV1 {
                command: format!("{name} {}", args.join(" ")),
                dialect: "posix".into(),
                transport: "shell_string".into(),
                extraction_provenance: "pre-tool-generic".into(),
            })
            .unwrap();
            assert_eq!(
                super::super::command_shape(&model, workspace, None).is_none(),
                expected,
            );
        }
        std::fs::create_dir(workspace.join("sub")).unwrap();
        std::fs::write(workspace.join("sub/source"), b"ordinary").unwrap();
        std::fs::hard_link(workspace.join("protected"), workspace.join("sub/linked")).unwrap();
        std::fs::create_dir_all(workspace.join("tree/nested")).unwrap();
        std::fs::write(workspace.join("tree/nested/file"), b"ordinary").unwrap();
        std::fs::create_dir_all(workspace.join("destination/tree/nested")).unwrap();
        std::fs::hard_link(
            workspace.join("protected"),
            workspace.join("destination/tree/nested/file"),
        )
        .unwrap();
        for (command, refused) in [
            ("cd sub && cp -f source linked", true),
            ("cd sub && touch -m linked", true),
            ("cd sub && cp -fp source new", false),
            ("cd sub && touch -m new", false),
            ("cd sub && cd - && touch linked", true),
            ("cd missing && touch linked", true),
            ("cd ~ && touch linked", true),
            ("pushd +1 && touch linked", true),
            ("false && cd sub && true; touch linked", true),
            ("cd sub | touch linked", true),
            ("cp -R tree destination", true),
            ("cp -R tree new-directory", false),
        ] {
            let model = crate::parse_command(&crate::CommandModelRequestV1 {
                command: command.into(),
                dialect: "posix".into(),
                transport: "shell_string".into(),
                extraction_provenance: "pre-tool-generic".into(),
            })
            .unwrap();
            assert_eq!(
                super::super::command_shape(&model, workspace, None).is_none(),
                refused,
                "{command}"
            );
        }
    }
    #[test]
    fn a_symlinked_parent_cannot_hide_an_outside_destination() {
        let mut root = Workspace(std::env::temp_dir().join(format!(
            "guard-linked-parent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        )));
        std::fs::create_dir_all(&root.0).unwrap();
        root.0 = root.0.canonicalize().unwrap();
        let outside = root.0.join("outside");
        let workspace = root.0.join("workspace");
        std::fs::create_dir(&outside).unwrap();
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(outside.join("existing"), b"sentinel").unwrap();
        std::os::unix::fs::symlink(&outside, workspace.join("alias")).unwrap();
        std::fs::write(workspace.join("source"), b"ordinary").unwrap();
        std::fs::create_dir(workspace.join("sub")).unwrap();
        std::os::unix::fs::symlink(&outside, workspace.join("sub/alias")).unwrap();
        for (name, args) in [
            ("touch", vec!["alias/existing"]),
            ("touch", vec!["alias/new"]),
            ("cp", vec!["source", "alias/existing"]),
            ("cp", vec!["source", "alias/plain"]),
        ] {
            let owned = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
            assert!(
                mutates_linked_destination(name, &owned, &workspace),
                "{name} {args:?}"
            );
            let model = crate::parse_command(&crate::CommandModelRequestV1 {
                command: format!("{name} {}", args.join(" ")),
                dialect: "posix".into(),
                transport: "shell_string".into(),
                extraction_provenance: "pre-tool-generic".into(),
            })
            .unwrap();
            assert!(
                super::super::command_shape(&model, &workspace, None).is_none(),
                "{name} {args:?}"
            );
        }
        let nested = vec!["sub/new".to_owned()];
        assert!(!mutates_linked_destination("touch", &nested, &workspace));
        let model = crate::parse_command(&crate::CommandModelRequestV1 {
            command: "touch sub/new".into(),
            dialect: "posix".into(),
            transport: "shell_string".into(),
            extraction_provenance: "pre-tool-generic".into(),
        })
        .unwrap();
        assert!(super::super::command_shape(&model, &workspace, None).is_some());
        let model = crate::parse_command(&crate::CommandModelRequestV1 {
            command: "cd sub && touch alias/new".into(),
            dialect: "posix".into(),
            transport: "shell_string".into(),
            extraction_provenance: "pre-tool-generic".into(),
        })
        .unwrap();
        assert!(super::super::command_shape(&model, &workspace, None).is_none());
    }
}
