//! Preserve linked-destination refusals when trying broader containment.

use crate::CanonicalCommandV1;
use std::path::Path;

use super::cwd;
#[path = "workspace_contained_glob.rs"]
mod glob;

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
    // A command that changes how the shell expands a pattern changes which
    // entries the copy receives. `shopt -s dotglob` adds the hidden names
    // this expansion leaves out, `GLOBIGNORE` takes names away, and either
    // can put a file in front of the copy that the scan never weighed.
    if model.segments.iter().any(expands_patterns_differently)
        && model.segments.iter().any(|segment| {
            segment
                .arguments
                .iter()
                .any(|argument| glob::pattern(argument))
        })
    {
        return true;
    }
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
                .any(|cwd| mutates_linked_destination(name, &segment.arguments, &segment.text, cwd))
        })
}

fn expands_patterns_differently(segment: &crate::CommandSegmentV1) -> bool {
    let mut name =
        super::super::executable_basename(segment.executable.as_deref().unwrap_or_default());
    let mut arguments = segment.arguments.as_slice();
    // The parser leaves `builtin` in place, so `builtin shopt` arrives with
    // `shopt` as an argument rather than as the executable.
    if name == "builtin" {
        let Some((first, rest)) = arguments.split_first() else {
            return false;
        };
        name = first.as_str();
        arguments = rest;
    }
    name == "shopt"
        || segment.text.contains("GLOBIGNORE")
        || (name == "set"
            && arguments
                .iter()
                .any(|argument| argument == "-o" || argument == "+o"))
}

fn mutates_linked_destination(
    name: &str,
    arguments: &[String],
    text: &str,
    workspace: &Path,
) -> bool {
    if !matches!(name, "cp" | "touch") {
        return false;
    }
    // Quoting is spent by the time an argument reaches here, so `cp src "dest/*"`
    // and `cp src dest/*` arrive the same. One names a file the shell leaves
    // alone and the other names whatever the directory holds, and a command
    // carrying either quote or an escape no longer says which it is.
    if arguments.iter().any(|argument| glob::pattern(argument)) && text.contains(['\'', '"', '\\'])
    {
        return true;
    }
    // The shell expands a pattern before the command runs, so the entries it
    // names are the writes to weigh. An expansion this scan cannot read
    // leaves the destinations unknown.
    let Some(expanded) = glob::expand_arguments(arguments, workspace) else {
        return true;
    };
    let expanded = expanded.as_slice();
    match name {
        "cp" => copy_targets(arguments, expanded, workspace).unwrap_or(true),
        "touch" => touch_targets(expanded)
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

/// What `cp` reads from its arguments: the operands, an explicit target
/// directory, and the two options that decide how the operands are read.
struct Copy<'a> {
    paths: Vec<&'a str>,
    target_directory: Option<&'a str>,
    recursive: bool,
    no_target_directory: bool,
}

fn parse_copy(arguments: &[String]) -> Option<Copy<'_>> {
    let mut parsed = Copy {
        paths: Vec::new(),
        target_directory: None,
        recursive: false,
        no_target_directory: false,
    };
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
                    parsed.target_directory = Some(args.next()?.as_str());
                }
                "-S" | "--suffix" => {
                    args.next()?;
                }
                "-T" | "--no-target-directory" => parsed.no_target_directory = true,
                "--recursive" | "--archive" => parsed.recursive = true,
                "--force"
                | "--interactive"
                | "--no-clobber"
                | "--preserve"
                | "--verbose"
                | "--dereference"
                | "--no-dereference"
                | "--remove-destination" => {}
                value if value.starts_with("--target-directory=") => {
                    parsed.target_directory = Some(value.strip_prefix("--target-directory=")?);
                }
                value if value.starts_with("--preserve=") || value.starts_with("--suffix=") => {}
                value
                    if value.starts_with('-')
                        && !value.starts_with("--")
                        && value.len() > 1
                        && value[1..].chars().all(|c| "afHiLnPpRrvXbuc".contains(c)) =>
                {
                    parsed.recursive |= value[1..].chars().any(|c| "aRr".contains(c));
                }
                _ => return None,
            }
        } else {
            parsed.paths.push(arg.as_str());
        }
    }
    Some(parsed)
}

fn copy_targets(arguments: &[String], expanded: &[String], workspace: &Path) -> Option<bool> {
    // The last operand is the destination, and a pattern there leaves which
    // entry that is to the shell's collation order rather than to the order
    // the entries were read in. The copy would then write a file this scan
    // weighed as a source.
    let unexpanded = parse_copy(arguments)?;
    let named = unexpanded
        .target_directory
        .or_else(|| unexpanded.paths.last().copied())?;
    if glob::pattern(named) {
        return Some(true);
    }
    let Copy {
        mut paths,
        target_directory,
        recursive,
        no_target_directory,
    } = parse_copy(expanded)?;
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
            crate::unique_nanos::unique_nanos(),
        )));
        std::fs::create_dir(&root.0).unwrap();
        root.0 = root.0.canonicalize().unwrap();
        let workspace = root.0.as_path();
        std::fs::write(workspace.join("protected"), b"sentinel").unwrap();
        std::fs::hard_link(workspace.join("protected"), workspace.join("linked")).unwrap();
        std::fs::write(workspace.join("source"), b"ordinary").unwrap();
        std::fs::write(workspace.join("second"), b"ordinary").unwrap();
        std::fs::create_dir(workspace.join("destination")).unwrap();
        // Bytewise, `Zlink` sorts before `alink`; a UTF-8 locale's collation
        // puts them the other way round.
        std::fs::create_dir(workspace.join("plain")).unwrap();
        std::fs::write(workspace.join("plain/alink"), b"ordinary").unwrap();
        std::fs::hard_link(workspace.join("protected"), workspace.join("plain/Zlink")).unwrap();
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
            let text = format!("{name} {}", args.join(" "));
            assert_eq!(
                mutates_linked_destination(name, &args, &text, workspace),
                expected
            );
            let model = crate::parse_command(&crate::CommandModelRequestV1 {
                command: text.clone(),
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
            // A pattern weighs the entries the shell expands it into: the
            // copy out of `sub` lands on a hard link, the one out of `tree`
            // writes a directory that is not there yet, and a pattern that
            // matches nothing reaches `cp` as the pattern itself.
            ("cp -f sub/* destination", true),
            ("cp -R tree/* new-directory", false),
            ("cp -R missing/* destination", true),
            // A pattern naming the destination leaves which entry that is to
            // the shell's collation order, not to the order these were read
            // in. A pattern naming sources is read here instead.
            ("cp -f source plain/[aZ]link", true),
            ("cp -f plain/[aZ]link destination", false),
            // Quoting is gone by the time the arguments are weighed, so a
            // pattern beside a quote could be the name of one file.
            ("cp -R tree/* \"new-directory\"", true),
            // `dotglob` hands the copy the hidden names this leaves out.
            ("shopt -s dotglob && cp -R tree/* new-directory", true),
            (
                "builtin shopt -s dotglob && cp -R tree/* new-directory",
                true,
            ),
            ("builtin set -o noglob && cp -R tree/* new-directory", true),
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
            crate::unique_nanos::unique_nanos(),
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
            let text = format!("{name} {}", args.join(" "));
            assert!(
                mutates_linked_destination(name, &owned, &text, &workspace),
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
        assert!(!mutates_linked_destination(
            "touch",
            &nested,
            "touch sub/new",
            &workspace
        ));
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
