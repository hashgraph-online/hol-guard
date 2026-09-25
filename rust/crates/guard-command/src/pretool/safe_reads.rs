pub(super) fn safe_date_arguments(arguments: &[String]) -> bool {
    let mut saw_format = false;
    for argument in arguments {
        if matches!(argument.as_str(), "-u" | "--utc" | "--universal") {
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
    true
}

pub(super) fn safe_read_target(argument: &str) -> bool {
    let lowered = argument.to_ascii_lowercase();
    ![
        "/etc/",
        "/dev/",
        "/proc/",
        "/sys/",
        "/var/",
        "/private/etc/",
        "~",
    ]
    .iter()
    .any(|prefix| lowered.starts_with(prefix))
        && !argument.split(['/', '\\']).any(|part| part == "..")
        && !lowered.contains("%2e")
        && !lowered.contains("%2f")
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
            if argument == "-" || !safe_read_target(argument) {
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
            if argument == "-" || !safe_read_target(argument) {
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
        saw_target = true;
    }
    saw_target && !expect_count
}
