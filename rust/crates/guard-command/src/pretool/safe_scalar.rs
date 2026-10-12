/// Longest literal delay, per command, that the classifier proves inert. Matches the
/// bound the shell secret-read walk already treats as a pure delay.
pub(super) const MAX_SAFE_SLEEP_SECONDS: f64 = 3600.0;

pub(super) fn safe_sleep_arguments(arguments: &[String]) -> bool {
    sleep_seconds(arguments).is_some()
}

/// Parse a bounded literal `sleep` duration in seconds.
pub(super) fn sleep_seconds(arguments: &[String]) -> Option<f64> {
    let [duration] = arguments else {
        return None;
    };
    if duration.is_empty()
        || duration.len() > 16
        || !duration
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || duration.bytes().filter(|byte| *byte == b'.').count() > 1
    {
        return None;
    }
    duration
        .parse::<f64>()
        .ok()
        .filter(|seconds| (0.0..=MAX_SAFE_SLEEP_SECONDS).contains(seconds))
}

/// Keep chained delays inert: the summed literal `sleep` time across segments
/// must stay within the per-command bound, with a small segment count.
pub(super) fn bounded_total_sleep(model: &crate::CanonicalCommandV1) -> bool {
    const MAX_SLEEP_SEGMENTS: usize = 8;

    let mut total = 0.0_f64;
    let mut count = 0_usize;
    for segment in &model.segments {
        if segment
            .executable
            .as_deref()
            .is_none_or(|executable| super::executable_basename(executable) != "sleep")
        {
            continue;
        }
        count += 1;
        let Some(seconds) = sleep_seconds(&segment.arguments) else {
            continue;
        };
        total += seconds;
    }
    count <= MAX_SLEEP_SEGMENTS && total <= MAX_SAFE_SLEEP_SECONDS
}

/// `pgrep` only lists matching process ids and names; admit read-only display
/// and matching flags plus exactly one literal pattern.
pub(super) fn safe_pgrep_arguments(arguments: &[String]) -> bool {
    let mut patterns = 0_usize;
    for argument in arguments {
        if let Some(flags) = argument.strip_prefix('-') {
            if flags.is_empty()
                || !flags
                    .bytes()
                    .all(|flag| matches!(flag, b'f' | b'i' | b'x' | b'n' | b'o' | b'c'))
            {
                return false;
            }
        } else {
            patterns += 1;
        }
    }
    patterns == 1
        && arguments
            .last()
            .is_some_and(|pattern| !pattern.starts_with('-') && pattern.len() <= 256)
}

/// A lone version flag prints the interpreter version and exits before any
/// script, module or startup file runs.
/// Python's `-v` is verbose startup, not a version flag, so only Node admits it.
pub(super) fn version_probe_arguments(basename: &str, arguments: &[String]) -> bool {
    let [flag] = arguments else {
        return false;
    };
    match basename {
        "node" | "nodejs" => matches!(flag.as_str(), "--version" | "-v"),
        "python" | "python3" => matches!(flag.as_str(), "--version" | "-V"),
        _ => false,
    }
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
