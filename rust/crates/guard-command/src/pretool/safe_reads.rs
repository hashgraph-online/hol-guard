pub(super) fn safe_sleep_arguments(arguments: &[String]) -> bool {
    const MAX_SAFE_SLEEP_SECONDS: f64 = 60.0;

    let [duration] = arguments else {
        return false;
    };
    if duration.is_empty()
        || duration.len() > 16
        || !duration
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || duration.bytes().filter(|byte| *byte == b'.').count() > 1
    {
        return false;
    }
    duration
        .parse::<f64>()
        .is_ok_and(|seconds| (0.0..=MAX_SAFE_SLEEP_SECONDS).contains(&seconds))
}

pub(super) fn safe_date_arguments(arguments: &[String]) -> bool {
    let mut saw_format = false;
    let mut expect_epoch = false;
    for argument in arguments {
        if expect_epoch {
            if !(argument.starts_with('@')
                && argument.len() > 1
                && argument.len() <= 21
                && argument.bytes().skip(1).all(|byte| byte.is_ascii_digit()))
            {
                return false;
            }
            expect_epoch = false;
            continue;
        }
        if matches!(
            argument.as_str(),
            "-u" | "--utc"
                | "--universal"
                | "-R"
                | "--rfc-email"
                | "--rfc-2822"
                | "-I"
                | "--iso-8601"
                | "--rfc-3339"
        ) || ((argument.starts_with("--iso-8601=") || argument.starts_with("--rfc-3339="))
            && argument.len() <= 40
            && !argument.contains('\n'))
        {
            continue;
        }
        if matches!(argument.as_str(), "-d" | "--date") {
            expect_epoch = true;
            continue;
        }
        if let Some(value) = argument.strip_prefix("--date=") {
            if !(value.starts_with('@')
                && value.len() > 1
                && value.len() <= 21
                && value.bytes().skip(1).all(|byte| byte.is_ascii_digit()))
            {
                return false;
            }
            continue;
        }
        if argument.starts_with('+') && argument.len() <= 256 && !argument.contains('\n') {
            if saw_format {
                return false;
            }
            saw_format = true;
            continue;
        }
        return false;
    }
    !expect_epoch
}

pub(super) fn safe_read_target(argument: &str) -> bool {
    let Some(normalized) = lexical_read_path(argument) else {
        return false;
    };
    let lowered = normalized.to_ascii_lowercase();
    const ROOTS: [&str; 7] = [
        "/etc",
        "/dev",
        "/proc",
        "/sys",
        "/var",
        "/private/etc",
        "/private/var",
    ];
    if lowered.starts_with('/')
        || ROOTS
            .iter()
            .any(|prefix| lowered == *prefix || lowered.starts_with(&format!("{prefix}/")))
        || lowered.starts_with('~')
        || super::sensitive_command(argument)
        || super::sensitive_command(&normalized)
        || super::sensitive_read_path_argument(&normalized)
    {
        return false;
    }
    true
}

/// Share canonical path-risk checks between structured reads and shell reads.
/// Absolute/home-relative targets must resolve; sensitive symlink destinations
/// stay guarded. Unresolved relative targets retain the legacy lexical floor.
pub(super) fn bounded_file_read_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    bounded_read_target(value, home_dir, cwd, false)
}

pub(super) fn existing_regular_read_target(
    value: &str,
    home: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    if value.trim() != value || !bounded_file_read_target(value, home, cwd) {
        return false;
    }
    let expanded = expand_home_read_path(value, home).unwrap_or_else(|| value.to_owned());
    let path = std::path::Path::new(&expanded);
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else if let Some(cwd) = cwd {
        std::path::Path::new(&expand_home_read_path(cwd, home).unwrap_or_else(|| cwd.to_owned()))
            .join(path)
    } else {
        return false;
    };
    std::fs::canonicalize(candidate).is_ok_and(|path| path.is_file())
}

pub(super) fn bounded_read_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    allow_directory: bool,
) -> bool {
    let path = value.trim();
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    if path.is_empty() || path.len() > 4096 {
        return false;
    }
    if path.contains([
        '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '[', ']', '{', '}',
    ]) {
        return false;
    }
    if path.split(['/', '\\']).any(|part| part == "..") {
        return false;
    }
    if path.starts_with('~') && expand_home_read_path(path, home_dir).is_none() {
        return false;
    }
    let expanded = expand_home_read_path(path, home_dir).unwrap_or_else(|| path.to_owned());
    let expanded_path = std::path::Path::new(&expanded);
    let candidate = if expanded_path.is_absolute() {
        expanded_path.to_path_buf()
    } else if let Some(root) = cwd
        .and_then(|root| expand_home_read_path(root, home_dir).or_else(|| Some(root.to_owned())))
        .filter(|root| std::path::Path::new(root).is_absolute())
    {
        std::path::Path::new(&root).join(expanded_path)
    } else {
        return safe_read_target(path);
    };
    if let Ok(canonical) = std::fs::canonicalize(&candidate) {
        return (canonical.is_file() || (allow_directory && canonical.is_dir()))
            && resolved_path_allowed(&canonical, home_dir, cwd);
    }
    // An unresolvable absolute or `~` target cannot prove a bounded file;
    // a workspace-relative spelling keeps the pre-existing lexical floor.
    if expanded_path.is_absolute() {
        return false;
    }
    safe_read_target(path)
}

pub(super) fn verified_path_context(home_dir: Option<&str>, cwd: Option<&str>) -> bool {
    let (Some(home_dir), Some(cwd)) = (home_dir, cwd) else {
        return false;
    };
    context_root_is_absolute(home_dir, Some(home_dir))
        && context_root_is_absolute(cwd, Some(home_dir))
}

pub(super) fn verified_cwd_target(value: &str, context: super::PathContext<'_>) -> Option<String> {
    if context.0.is_none() || context.1.is_none() || !super::safe_directory_target(value) {
        return None;
    }
    let supplied = std::path::Path::new(value);
    if !supplied.is_absolute() {
        return None;
    }
    let canonical = std::fs::canonicalize(supplied).ok()?;
    // Absolute, non-aliased targets avoid CDPATH and logical/physical cwd ambiguity.
    if canonical != supplied
        || !canonical.is_dir()
        || !resolved_path_allowed(&canonical, context.0, context.1)
    {
        return None;
    }
    canonical.to_str().map(str::to_owned)
}

fn context_root_is_absolute(root: &str, home_dir: Option<&str>) -> bool {
    if root.is_empty() || root.trim() != root {
        return false;
    }
    let expanded = if std::path::Path::new(root).is_absolute() {
        Some(root.to_owned())
    } else {
        expand_home_read_path(root, home_dir)
    };
    expanded.is_some_and(|root| {
        let path = std::path::Path::new(&root);
        path.is_absolute() && std::fs::canonicalize(path).is_ok_and(|canonical| canonical.is_dir())
    })
}

/// Location outside the workspace is not itself a risk. The resolved regular
/// file must still clear every sensitive-path screen.
fn resolved_path_allowed(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    resolved_path_allowed_in_scope(canonical, home_dir, cwd, false)
}

fn resolved_path_allowed_in_scope(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    verified_temporary: bool,
) -> bool {
    let rendered = canonical.to_string_lossy().replace('\\', "/");
    let lowered = rendered.to_ascii_lowercase();
    const ROOTS: [&str; 7] = [
        "/etc",
        "/dev",
        "/proc",
        "/sys",
        "/var",
        "/private/etc",
        "/private/var",
    ];
    if (!verified_temporary
        && ROOTS
            .iter()
            .any(|prefix| lowered == *prefix || lowered.starts_with(&format!("{prefix}/"))))
        || foreign_user_home(canonical, home_dir, cwd)
        || guard_secure_fs::sensitive_path_family(canonical).is_some()
        || guard_secure_fs::credential_named_path(canonical)
        || !(guard_secure_fs::hidden_read_parts_allowed(canonical)
            || guard_safety_doc(canonical, home_dir)
            || agent_skill_document(canonical, home_dir))
    {
        return false;
    }
    true
}

pub(super) fn bounded_file_write_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    bounded_write_target(value, home_dir, cwd, false, false)
}

pub(super) fn bounded_native_file_write_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    bounded_write_target(value, home_dir, cwd, false, true)
}

fn bounded_write_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    directory: bool,
    allow_home: bool,
) -> bool {
    let Some(workspace) = cwd.and_then(|root| {
        let expanded = expand_home_read_path(root, home_dir).unwrap_or_else(|| root.to_owned());
        std::fs::canonicalize(expanded).ok()
    }) else {
        return false;
    };
    if value.is_empty()
        || value.len() > 4096
        || value.contains([
            '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '[', ']', '{', '}',
        ])
        || value.split(['/', '\\']).any(|part| part == "..")
    {
        return false;
    }
    if value.starts_with('~') && expand_home_read_path(value, home_dir).is_none() {
        return false;
    }
    let expanded = expand_home_read_path(value, home_dir).unwrap_or_else(|| value.to_owned());
    let supplied = std::path::Path::new(&expanded);
    let target = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        workspace.join(supplied)
    };
    let canonical = if directory && target.is_dir() {
        std::fs::canonicalize(&target).ok()
    } else {
        super::worktree_writes::canonical_write_target(&target)
    };
    let Some(canonical) = canonical else {
        return false;
    };
    let inside_verified_home = allow_home
        && home_dir
            .and_then(|home| std::fs::canonicalize(home).ok())
            .is_some_and(|home| {
                // A filesystem root must never turn into an unrestricted write scope.
                home.parent().and_then(std::path::Path::parent).is_some()
                    && canonical.starts_with(&home)
                    // Keep symlink and dot-segment aliases fail-closed: the
                    // reviewed spelling must name the reviewed write target.
                    && canonical == target
                    && single_link_write_target(&target)
                    && !home_execution_control_target(&canonical, &home, &workspace)
            });
    (canonical.starts_with(&workspace)
        || super::worktree_writes::same_repository_worktree(&workspace, &canonical)
        || inside_verified_home)
        && guard_secure_fs::hidden_read_parts_allowed(&canonical)
        && resolved_path_allowed(&canonical, home_dir, workspace.to_str())
        && !autostart_write_target(&canonical)
}

pub(super) fn safe_copy_arguments(arguments: &[String], context: super::PathContext<'_>) -> bool {
    let paths = match arguments {
        [source, destination] => (source, destination),
        [separator, source, destination] if separator == "--" => (source, destination),
        _ => return false,
    };
    let expanded = expand_home_read_path(paths.1, context.0).unwrap_or_else(|| paths.1.clone());
    let destination = std::path::Path::new(&expanded);
    let destination = if destination.is_absolute() {
        destination.to_path_buf()
    } else if let Some(cwd) = context.1 {
        std::path::Path::new(
            &expand_home_read_path(cwd, context.0).unwrap_or_else(|| cwd.to_owned()),
        )
        .join(destination)
    } else {
        return false;
    };
    let destination = if destination.is_dir() {
        let Some(name) = std::path::Path::new(paths.0).file_name() else {
            return false;
        };
        destination.join(name)
    } else {
        destination
    };
    let Some(destination_text) = destination.to_str() else {
        return false;
    };
    if destination
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return false;
    }
    // Only a single file-to-file copy. Flags, directory destinations and
    // recursive copies need separate evaluation; cp follows destination links.
    !paths.0.starts_with('-')
        && !paths.1.starts_with('-')
        && paths.0.trim() == paths.0
        && bounded_file_read_target(paths.0, context.0, context.1)
        && (bounded_file_write_target(destination_text, context.0, context.1)
            || bounded_temporary_copy_target(destination_text, context))
}

pub(super) fn safe_file_mutation_arguments(
    command: &str,
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    match (command, arguments) {
        ("mkdir", [target]) => {
            !target.starts_with('-')
                && bounded_write_target(target, context.0, context.1, true, false)
        }
        ("mkdir", [flag, target]) if matches!(flag.as_str(), "-p" | "--parents" | "--") => {
            !target.starts_with('-')
                && bounded_write_target(target, context.0, context.1, true, false)
        }
        ("touch", [target]) => {
            !target.starts_with('-') && bounded_file_write_target(target, context.0, context.1)
        }
        ("touch", [flag, target]) if flag == "--" => {
            !target.starts_with('-') && bounded_file_write_target(target, context.0, context.1)
        }
        ("mv", [source, destination]) => {
            existing_regular_read_target(source, context.0, context.1)
                && bounded_file_write_target(source, context.0, context.1)
                && bounded_file_write_target(destination, context.0, context.1)
                && absent_move_destination(destination, context)
                && safe_copy_arguments(arguments, context)
        }
        _ => false,
    }
}

fn absent_move_destination(value: &str, context: super::PathContext<'_>) -> bool {
    let expanded = expand_home_read_path(value, context.0).unwrap_or_else(|| value.to_owned());
    let supplied = std::path::Path::new(&expanded);
    let target = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else if let Some(cwd) = context.1 {
        std::path::Path::new(
            &expand_home_read_path(cwd, context.0).unwrap_or_else(|| cwd.to_owned()),
        )
        .join(supplied)
    } else {
        return false;
    };
    matches!(target.symlink_metadata(), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
}

#[cfg(unix)]
fn bounded_temporary_copy_target(value: &str, context: super::PathContext<'_>) -> bool {
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    let Some(owner) = context
        .0
        .and_then(|home| std::fs::metadata(home).ok())
        .map(|m| m.uid())
    else {
        return false;
    };
    let path = Path::new(value);
    if !path.is_absolute()
        || value.len() > 4096
        || value.contains([
            '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '[', ']', '{', '}',
        ])
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return false;
    }
    let Some(parent) = path.parent().and_then(|p| std::fs::canonicalize(p).ok()) else {
        return false;
    };
    let Ok(parent_metadata) = parent.metadata() else {
        return false;
    };
    let roots = [Path::new("/tmp"), Path::new("/var/tmp")];
    let in_scope = roots
        .iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .any(|root| {
            parent.starts_with(&root)
                && (parent == root
                    || (parent_metadata.uid() == owner && parent_metadata.mode() & 0o022 == 0))
        });
    if !in_scope || !parent_metadata.is_dir() {
        return false;
    }
    // Do not follow a pre-existing leaf symlink or overwrite another user's
    // file (including a hard-link alias) in a shared temporary directory.
    match path.symlink_metadata() {
        Ok(metadata) if !metadata.is_file() || metadata.uid() != owner || metadata.nlink() != 1 => {
            return false
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return false,
    }
    let Some(target) = path.file_name().map(|name| parent.join(name)) else {
        return false;
    };
    resolved_path_allowed_in_scope(&target, context.0, context.1, true)
        && guard_secure_fs::hidden_read_parts_allowed(&target)
        && !autostart_write_target(&target)
}

#[cfg(not(unix))]
fn bounded_temporary_copy_target(_value: &str, _context: super::PathContext<'_>) -> bool {
    false
}

fn autostart_write_target(path: &std::path::Path) -> bool {
    let rendered = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let parts: Vec<&str> = rendered
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    parts.windows(2).any(|pair| {
        matches!(
            pair,
            ["library", "launchagents"]
                | ["library", "launchdaemons"]
                | [".config", "autostart"]
                | [".config", "systemd"]
        )
    }) || parts
        .windows(3)
        .any(|parts| parts == ["start menu", "programs", "startup"])
}

fn single_link_write_target(path: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        match path.symlink_metadata() {
            Ok(metadata) => !metadata.is_file() || metadata.nlink() == 1,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => false,
        }
    }
    #[cfg(windows)]
    {
        match path.symlink_metadata() {
            Ok(metadata) if !metadata.is_file() => false,
            Ok(_) => guard_runtime_windows_process::is_single_link_file(path).unwrap_or(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => false,
        }
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = path;
        false
    }
}

fn home_execution_control_target(
    path: &std::path::Path,
    home: &std::path::Path,
    workspace: &std::path::Path,
) -> bool {
    if path.starts_with(workspace) {
        return false;
    }
    let parts: Vec<String> = path
        .strip_prefix(home)
        .ok()
        .into_iter()
        .flat_map(std::path::Path::components)
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => {
                Some(value.to_string_lossy().to_ascii_lowercase())
            }
            _ => None,
        })
        .collect();
    parts.iter().any(|part| part == "bin" || part == "appdata")
        || parts.windows(2).any(|pair| {
            matches!(
                pair,
                [first, second]
                    if first == "library"
                        && matches!(second.as_str(), "application support" | "application scripts")
                        || (first == ".local" && second == "bin")
                        || (first == ".github" && second == "workflows")
            )
        })
}

fn agent_skill_document(canonical: &std::path::Path, home_dir: Option<&str>) -> bool {
    let Some(home) = home_dir.and_then(|root| std::fs::canonicalize(root).ok()) else {
        return false;
    };
    let Ok(skills) = std::fs::canonicalize(home.join(".agents/skills")) else {
        return false;
    };
    let Ok(relative) = canonical.strip_prefix(skills) else {
        return false;
    };
    canonical.extension().is_some_and(|extension| extension == "md")
        && relative.components().count() >= 2
        && relative.components().all(|component| {
            matches!(component, std::path::Component::Normal(part) if !part.to_string_lossy().starts_with('.'))
        })
}

/// `~/.hol-support/SAFETY.md` is the harness-facing safety guide that agents
/// are instructed to read before acting; it gets the same explicit allowance
/// the Python source-path classifier grants.
fn guard_safety_doc(canonical: &std::path::Path, home_dir: Option<&str>) -> bool {
    home_dir
        .and_then(|root| std::fs::canonicalize(root).ok())
        .is_some_and(|home| canonical == home.join(".hol-support/SAFETY.md"))
}

fn foreign_user_home(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let user_root = ["/home", "/Users"].iter().find_map(|root| {
        let relative = canonical.strip_prefix(root).ok()?;
        let user = relative.components().next()?;
        Some(std::path::Path::new(root).join(user.as_os_str()))
    });
    user_root.is_some_and(|user_root| {
        ![home_dir, cwd]
            .into_iter()
            .flatten()
            .any(|root| std::fs::canonicalize(root).is_ok_and(|root| root.starts_with(&user_root)))
    })
}

fn expand_home_read_path(path: &str, home_dir: Option<&str>) -> Option<String> {
    let rest = path.strip_prefix('~')?;
    if !rest.is_empty() && !rest.starts_with('/') {
        return None;
    }
    let home = home_dir?.trim();
    if home.is_empty() || !std::path::Path::new(home).is_absolute() {
        return None;
    }
    if rest.is_empty() {
        return Some(home.to_owned());
    }
    #[cfg(windows)]
    let rest = rest.trim_start_matches('/').replace('/', "\\");
    #[cfg(not(windows))]
    let rest = rest.trim_start_matches('/');
    Some(
        std::path::Path::new(home)
            .join(rest)
            .to_string_lossy()
            .into_owned(),
    )
}

fn lexical_read_path(value: &str) -> Option<String> {
    if value.is_empty() || value.contains(['\0', '\n', '\r', '%', '*', '?', '[', ']', '{', '}']) {
        return None;
    }
    let unified = value.replace('\\', "/");
    let absolute = unified.starts_with('/');
    let mut parts = Vec::new();
    for part in unified.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." || part.starts_with('~') {
            return None;
        }
        parts.push(part);
    }
    if parts.is_empty() {
        return None;
    }
    let mut normalized = String::new();
    if absolute {
        normalized.push('/');
    }
    normalized.push_str(&parts.join("/"));
    Some(normalized)
}

pub(super) fn safe_listing_arguments(
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    arguments.iter().all(|argument| {
        if argument == "-" || argument == "-R" || argument == "--recursive" {
            return false;
        }
        if argument.starts_with('-') {
            return !argument.contains('R');
        }
        command_read_target(argument, context, true)
    })
}

fn command_read_target(
    value: &str,
    context: super::PathContext<'_>,
    allow_directory: bool,
) -> bool {
    if context.0.is_some() || context.1.is_some() {
        bounded_read_target(value, context.0, context.1, allow_directory)
    } else {
        safe_read_target(value)
    }
}

pub(super) fn safe_sed_arguments(
    arguments: &[String],
    piped_input: bool,
    context: super::PathContext<'_>,
) -> bool {
    let (quiet, rest) = if arguments.first().is_some_and(|arg| arg == "-n") {
        (true, &arguments[1..])
    } else {
        (false, arguments)
    };
    let Some((program, targets)) = rest.split_first() else {
        return false;
    };
    if program.len() > 256 || program.contains(['\n', '\r', '\\', ';']) {
        return false;
    }
    let bounded_print = quiet
        && program.strip_suffix('p').is_some_and(|range| {
            let counts: Vec<_> = range.split(',').collect();
            (1..=2).contains(&counts.len())
                && counts.iter().all(|count| {
                    !count.is_empty()
                        && count.len() <= 6
                        && count.bytes().all(|byte| byte.is_ascii_digit())
                        && count.parse::<u32>().is_ok_and(|count| count > 0)
                })
        });
    // Exactly one substitution with inert flags. No e/w commands, program
    // files, in-place edits, or additional statements can enter this proof.
    let substitution = !quiet
        && program.strip_prefix("s/").is_some_and(|body| {
            let parts: Vec<_> = body.split('/').collect();
            parts.len() == 3 && matches!(parts[2], "" | "g")
        });
    (bounded_print || substitution)
        && (matches!(targets, [target] if !target.starts_with('-') && command_read_target(target, context, false))
            || (targets.is_empty() && piped_input))
}

pub(super) fn safe_plain_file_arguments(
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    let mut saw_target = false;
    let mut after_options = false;
    for argument in arguments {
        if after_options {
            if argument == "-" || !command_read_target(argument, context, false) || saw_target {
                return false;
            }
            saw_target = true;
            continue;
        }
        if argument == "--" {
            after_options = true;
            continue;
        }
        if argument == "-" || argument.starts_with("--") {
            return false;
        }
        if argument.starts_with('-') {
            if argument
                .bytes()
                .skip(1)
                .all(|byte| matches!(byte, b'A' | b'b' | b'E' | b'n' | b's' | b'T' | b'v'))
            {
                continue;
            }
            return false;
        }
        if !command_read_target(argument, context, false) {
            return false;
        }
        if saw_target {
            return false;
        }
        saw_target = true;
    }
    saw_target
}

pub(super) fn safe_head_tail_arguments(
    arguments: &[String],
    piped_input: bool,
    context: super::PathContext<'_>,
) -> bool {
    safe_head_tail_with_targets(arguments, piped_input, context, true)
}

pub(super) fn safe_head_tail_stdin_arguments(arguments: &[String]) -> bool {
    safe_head_tail_with_targets(arguments, true, (None, None), false)
}

pub(super) fn safe_jq_stdin_arguments(arguments: &[String]) -> bool {
    let mut filter = None;
    for argument in arguments {
        if filter.is_none()
            && matches!(
                argument.as_str(),
                "-r" | "-c"
                    | "-e"
                    | "-M"
                    | "--raw-output"
                    | "--compact-output"
                    | "--exit-status"
                    | "--monochrome-output"
            )
        {
            continue;
        }
        if filter.replace(argument.as_str()).is_some() {
            return false;
        }
    }
    let Some(filter) = filter else { return false };
    // Only field/index projections: no functions, file operands, modules or env access.
    if filter.len() > 256 || !filter.starts_with('.') {
        return false;
    }
    let bytes = filter.as_bytes();
    let mut index = 1;
    while index < bytes.len() {
        if bytes[index] == b'[' {
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            if bytes.get(index) != Some(&b']') {
                return false;
            }
            index += 1;
            if index < bytes.len() && !matches!(bytes[index], b'.' | b'[') {
                return false;
            }
        } else {
            if bytes[index] == b'.' {
                if index == 1 {
                    return false;
                }
                index += 1;
            }
            if index >= bytes.len() || !(bytes[index].is_ascii_alphabetic() || bytes[index] == b'_')
            {
                return false;
            }
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            if index < bytes.len() && !matches!(bytes[index], b'.' | b'[') {
                return false;
            }
        }
    }
    true
}

fn safe_head_tail_with_targets(
    arguments: &[String],
    piped_input: bool,
    context: super::PathContext<'_>,
    allow_target: bool,
) -> bool {
    let mut saw_target = false;
    let mut expect_count = false;
    let mut after_options = false;
    for argument in arguments {
        if expect_count {
            if !argument.bytes().all(|byte| byte.is_ascii_digit())
                || argument.is_empty()
                || argument.len() > 6
            {
                return false;
            }
            expect_count = false;
            continue;
        }
        if after_options {
            if !allow_target
                || argument == "-"
                || !command_read_target(argument, context, false)
                || saw_target
            {
                return false;
            }
            saw_target = true;
            continue;
        }
        if argument == "--" {
            after_options = true;
            continue;
        }
        if matches!(argument.as_str(), "-n" | "--lines" | "-c" | "--bytes") {
            expect_count = true;
            continue;
        }
        if let Some(value) = argument
            .strip_prefix("--lines=")
            .or_else(|| argument.strip_prefix("--bytes="))
        {
            if value.is_empty()
                || value.len() > 6
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return false;
            }
            continue;
        }
        if argument.starts_with('-')
            && argument.len() > 1
            && argument.len() <= 7
            && argument.bytes().skip(1).all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        if argument.starts_with('-') {
            return false;
        }
        if !allow_target || !command_read_target(argument, context, false) {
            return false;
        }
        if saw_target {
            return false;
        }
        saw_target = true;
    }
    (saw_target || piped_input) && !expect_count
}
