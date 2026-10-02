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

/// Structured file-tool read floor. `home_dir`/`cwd` are the envelope's
/// verified roots; `~` expands against `home_dir`. Absolute and anchored
/// candidates must canonicalize to an existing regular file — symlinks
/// resolve to their real target — and stay
/// outside the sensitive roots, credential families, sensitive filenames,
/// and hidden directories. Workspace-relative paths keep the legacy
/// lexical allowance, but when `cwd` is known and the file resolves, the
/// canonical check applies to them as well. Directories and unresolvable
/// absolute/`~` targets are not provable here and stay under review.
pub(super) fn bounded_file_read_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let path = value.trim();
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
    } else if let Some(root) = cwd.map(str::trim).filter(|root| root.starts_with('/')) {
        std::path::Path::new(root).join(expanded_path)
    } else {
        return safe_read_target(path);
    };
    if let Ok(canonical) = std::fs::canonicalize(&candidate) {
        return resolved_file_read_allowed(&canonical, home_dir, cwd);
    }
    // An unresolvable absolute or `~` target cannot prove a bounded file;
    // a workspace-relative spelling keeps the pre-existing lexical floor.
    if expanded.starts_with('/') {
        return false;
    }
    safe_read_target(path)
}

/// Location outside the workspace is not itself a risk. The resolved regular
/// file must still clear every sensitive-path screen.
fn resolved_file_read_allowed(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    if !canonical.is_file() {
        return false;
    }
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
    if ROOTS
        .iter()
        .any(|prefix| lowered == *prefix || lowered.starts_with(&format!("{prefix}/")))
        || foreign_user_home(canonical, home_dir, cwd)
        || super::sensitive_command(&rendered)
        || guard_secure_fs::sensitive_path_family(canonical).is_some()
        || guard_secure_fs::sensitive_external_filename(canonical)
        || canonical.components().any(|component| {
            matches!(component, std::path::Component::Normal(part) if {
                let part = part.to_string_lossy().to_ascii_lowercase();
                guard_secure_fs::EXTERNAL_SENSITIVE_PARTS.contains(&part.as_str())
            })
        })
        || !(guard_secure_fs::hidden_read_parts_allowed(canonical)
            || guard_safety_doc(canonical, home_dir)
            || agent_skill_document(canonical, home_dir))
    {
        return false;
    }
    true
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
    let home = home_dir?.trim().trim_end_matches('/');
    if home.is_empty() || !home.starts_with('/') {
        return None;
    }
    Some(format!("{home}{rest}"))
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

pub(super) fn safe_listing_arguments(arguments: &[String]) -> bool {
    arguments.iter().all(|argument| {
        if argument == "-" || argument == "-R" || argument == "--recursive" {
            return false;
        }
        if argument.starts_with('-') {
            return !argument.contains('R');
        }
        safe_read_target(argument)
    })
}

pub(super) fn safe_plain_file_arguments(arguments: &[String]) -> bool {
    let mut saw_target = false;
    let mut after_options = false;
    for argument in arguments {
        if after_options {
            if argument == "-" || !safe_read_target(argument) || saw_target {
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
        if !safe_read_target(argument) {
            return false;
        }
        if saw_target {
            return false;
        }
        saw_target = true;
    }
    saw_target
}

pub(super) fn safe_head_tail_arguments(arguments: &[String], piped_input: bool) -> bool {
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
            if argument == "-" || !safe_read_target(argument) || saw_target {
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
        if !safe_read_target(argument) {
            return false;
        }
        if saw_target {
            return false;
        }
        saw_target = true;
    }
    (saw_target || piped_input) && !expect_count
}
