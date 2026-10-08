pub(super) use super::directory_targets::verified_cwd_target;
pub(super) use super::read_paths::{
    bounded_file_read_target, bounded_omp_directory_read_target, bounded_omp_file_read_target,
    bounded_omp_selector_requires_review, bounded_read_target, safe_read_target,
    verified_path_context,
};
pub(super) use super::safe_scalar::{safe_date_arguments, safe_sleep_arguments};
pub(super) use super::safe_writes::{
    bounded_native_file_write_target, safe_copy_arguments, safe_file_mutation_arguments,
};

pub(super) fn safe_file_predicate_arguments(
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    let [predicate, target] = arguments else {
        return false;
    };
    verified_path_context(context.home_dir, context.cwd)
        && matches!(predicate.as_str(), "-f" | "-d" | "-e" | "-r")
        && !target.starts_with('-')
        && bounded_read_target(
            target,
            context.home_dir,
            context.cwd,
            matches!(predicate.as_str(), "-d" | "-e"),
        )
}

pub(super) fn safe_find_listing_arguments(
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    let arguments = arguments
        .strip_prefix(&["-P".to_owned()])
        .unwrap_or(arguments);
    let (target, valid) = match arguments {
        [target, kind, file] => (target, kind == "-type" && file == "f"),
        [target, depth_option, depth, kind, file] => (
            target,
            depth_option == "-maxdepth"
                && depth.bytes().all(|byte| byte.is_ascii_digit())
                && depth.parse::<u8>().is_ok_and(|value| value <= 32)
                && kind == "-type"
                && file == "f",
        ),
        _ => return false,
    };
    valid
        && verified_path_context(context.home_dir, context.cwd)
        && !target.starts_with('-')
        && bounded_read_target(target, context.home_dir, context.cwd, true)
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
    if context.home_dir.is_some() || context.cwd.is_some() {
        bounded_read_target(value, context.home_dir, context.cwd, allow_directory)
    } else {
        safe_read_target(value)
    }
}

fn sed_program_and_targets(arguments: &[String]) -> Option<(bool, &str, &[String])> {
    let (quiet, rest) = if arguments.first().is_some_and(|arg| arg == "-n") {
        (true, &arguments[1..])
    } else {
        (false, arguments)
    };
    let rest = if rest.first().is_some_and(|arg| arg == "-e") {
        &rest[1..]
    } else {
        rest
    };
    let (program, targets) = rest.split_first()?;
    Some((quiet, program, targets))
}

pub(super) fn safe_sed_stdin_arguments(arguments: &[String]) -> bool {
    let Some((_, _, targets)) = sed_program_and_targets(arguments) else {
        return false;
    };
    (targets.is_empty() || matches!(targets, [target] if target == "-"))
        && safe_sed_arguments(arguments, true, super::PathContext::default())
}

pub(super) fn safe_sed_arguments(
    arguments: &[String],
    piped_input: bool,
    context: super::PathContext<'_>,
) -> bool {
    let Some((quiet, program, targets)) = sed_program_and_targets(arguments) else {
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
        && (matches!(targets, [target] if (target == "-" && piped_input) || (!target.starts_with('-') && command_read_target(target, context, false)))
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
    safe_head_tail_with_targets(
        arguments,
        true,
        crate::pretool::PathContext::default(),
        false,
    )
}

pub(super) fn safe_word_count_arguments(
    arguments: &[String],
    piped_input: bool,
    context: super::PathContext<'_>,
) -> bool {
    safe_word_count_with_targets(arguments, piped_input, context, true)
}

pub(super) fn safe_word_count_stdin_arguments(arguments: &[String]) -> bool {
    safe_word_count_with_targets(arguments, true, super::PathContext::default(), false)
}

pub(super) fn safe_byte_dump_arguments(
    arguments: &[String],
    piped_input: bool,
    context: super::PathContext<'_>,
) -> bool {
    safe_byte_dump_with_targets(arguments, piped_input, context, true)
}

pub(super) fn safe_byte_dump_stdin_arguments(arguments: &[String]) -> bool {
    safe_byte_dump_with_targets(arguments, true, super::PathContext::default(), false)
}

fn safe_byte_dump_with_targets(
    arguments: &[String],
    piped_input: bool,
    context: super::PathContext<'_>,
    allow_targets: bool,
) -> bool {
    let mut options = true;
    let mut target = false;
    for argument in arguments {
        if options && argument == "--" {
            options = false;
            continue;
        }
        if options
            && matches!(
                argument.as_str(),
                "-a" | "-b"
                    | "-c"
                    | "-d"
                    | "-f"
                    | "-o"
                    | "-s"
                    | "-v"
                    | "-x"
                    | "-An"
                    | "-Ad"
                    | "-Ao"
                    | "-Ax"
                    | "-tc"
                    | "-tx1"
            )
        {
            continue;
        }
        if target {
            return false;
        }
        if argument == "-" {
            if !piped_input {
                return false;
            }
        } else if argument.starts_with('-')
            || !allow_targets
            || !verified_path_context(context.home_dir, context.cwd)
            || !command_read_target(argument, context, false)
        {
            return false;
        }
        options = false;
        target = true;
    }
    target || piped_input
}

fn safe_word_count_with_targets(
    arguments: &[String],
    piped_input: bool,
    context: super::PathContext<'_>,
    allow_targets: bool,
) -> bool {
    let mut operands = false;
    let mut separator = false;
    let mut saw_target = false;
    for argument in arguments {
        if !operands && argument == "--" {
            operands = true;
            separator = true;
            continue;
        }
        if !operands && argument.starts_with('-') && argument != "-" {
            let counting_option = matches!(
                argument.as_str(),
                "--bytes" | "--chars" | "--lines" | "--words" | "--max-line-length"
            ) || argument.strip_prefix('-').is_some_and(|flags| {
                !flags.is_empty()
                    && flags
                        .bytes()
                        .all(|flag| matches!(flag, b'c' | b'm' | b'l' | b'w' | b'L'))
            });
            if !counting_option {
                return false;
            }
            continue;
        }
        operands = true;
        if argument == "-" {
            if !piped_input {
                return false;
            }
        } else if !allow_targets
            || (argument.starts_with('-') && !separator)
            || !command_read_target(argument, context, false)
        {
            return false;
        }
        saw_target = true;
    }
    saw_target || piped_input
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
