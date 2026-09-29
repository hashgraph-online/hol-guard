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
    const ROOTS: [&str; 6] = ["/etc", "/dev", "/proc", "/sys", "/var", "/private/etc"];
    if lowered.starts_with('/')
        || ROOTS
            .iter()
            .any(|prefix| lowered == *prefix || lowered.starts_with(&format!("{prefix}/")))
        || lowered.starts_with('~')
        || super::sensitive_command(argument)
        || super::sensitive_command(&normalized)
        || guard_secure_fs::sensitive_path_family(std::path::Path::new(
            normalized.trim_start_matches("./"),
        ))
        .is_some()
    {
        return false;
    }
    true
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

pub(super) fn safe_head_tail_arguments(arguments: &[String]) -> bool {
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
    saw_target && !expect_count
}
