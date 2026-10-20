/// Longest literal delay, per command, that the classifier proves inert. Matches the
/// bound the shell secret-read walk already treats as a pure delay.
pub(super) const MAX_SAFE_SLEEP_SECONDS: f64 = 3600.0;

#[path = "process_probes.rs"]
mod process_probes;
#[cfg(all(test, unix))]
pub(super) use process_probes::steady_ancestry;
pub use process_probes::PsqlEnvironment;
pub(super) use process_probes::{
    local_postgres_host, plain_name as postgres_name, port as postgres_port, safe_lsof_arguments,
    safe_pg_isready_arguments, trusted_postgres_socket,
};
use process_probes::{PSQL_ROUTING_VARIABLES, PSQL_STARTUP_VARIABLES};

/// What a `psql` read inherits from the session. psql runs the system psqlrc
/// `PGSYSCONFDIR` may relocate, then the file `PSQLRC` names, else
/// `~/.psqlrc` from the shell's HOME (`%APPDATA%\postgresql\psqlrc.conf` on
/// Windows); libpq takes its server from the host, port and service
/// variables. A stamped name counts whatever its value. The stamp carries
/// HOME's value, which must name the `home_dir` that `psql_reads` checks, but
/// not APPDATA's, so a stamped APPDATA on Windows leaves its file unknown.
pub(super) fn psql_environment(
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    shell_home_matches: bool,
) -> PsqlEnvironment {
    let unset = |variables: &[&str]| match execution_environment {
        Some(environment) => {
            environment.has_valid_shape()
                && !environment.environment_names.iter().any(|name| {
                    variables
                        .iter()
                        .any(|variable| name.eq_ignore_ascii_case(variable))
                })
        }
        None => variables
            .iter()
            .all(|variable| std::env::var_os(variable).is_none()),
    };
    PsqlEnvironment {
        startup_files_absent: unset(&PSQL_STARTUP_VARIABLES)
            && execution_environment.is_none_or(|environment| {
                (environment.home.is_none() || shell_home_matches)
                    && (!cfg!(windows) || unset(&["APPDATA"]))
            }),
        routing_unset: unset(&PSQL_ROUTING_VARIABLES),
    }
}

/// `printenv` naming only location, identity or display variables prints
/// those values and nothing else. A bare `printenv`, an option, or any name
/// that could hold a credential stays reviewed.
pub(super) fn safe_printenv_arguments(arguments: &[String]) -> bool {
    !arguments.is_empty()
        && arguments
            .iter()
            .all(|name| crate::command_compatibility::plain_printed_name(name))
}

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
/// and matching flags plus exactly one literal pattern. `-l` and `-a` print
/// the matched process names or command lines, the same view `ps aux` gives.
pub(super) fn safe_pgrep_arguments(arguments: &[String]) -> bool {
    let mut patterns = 0_usize;
    for argument in arguments {
        if let Some(flags) = argument.strip_prefix('-') {
            if flags.is_empty()
                || !flags.bytes().all(|flag| {
                    matches!(flag, b'f' | b'i' | b'x' | b'n' | b'o' | b'c' | b'l' | b'a')
                })
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

/// `ps` lists processes and their arguments, the same view `pgrep -f`
/// already exposes. Environment display (BSD `e`, and `-e`/`-E` on macOS)
/// stays out because it prints other processes' variables.
pub(super) fn safe_ps_arguments(arguments: &[String]) -> bool {
    let mut expect_value: Option<char> = None;
    for argument in arguments {
        if let Some(option) = expect_value.take() {
            if !ps_option_value(option, argument) {
                return false;
            }
            continue;
        }
        let Some(flags) = argument.strip_prefix('-') else {
            if argument.is_empty()
                || !argument
                    .bytes()
                    .all(|flag| matches!(flag, b'a' | b'u' | b'x' | b'w' | b'j' | b'l' | b'c'))
            {
                return false;
            }
            continue;
        };
        if flags.is_empty() {
            return false;
        }
        for (index, flag) in flags.char_indices() {
            match flag {
                'A' | 'a' | 'f' | 'x' | 'w' | 'j' | 'l' | 'c' | 'm' | 'r' | 'h' => {}
                'e' if !cfg!(target_os = "macos") => {}
                'o' | 'O' | 'p' | 'q' | 'u' | 'U' | 'g' | 'G' | 't' => {
                    let rest = &flags[index + flag.len_utf8()..];
                    if rest.is_empty() {
                        expect_value = Some(flag);
                    } else if !ps_option_value(flag, rest) {
                        return false;
                    }
                    break;
                }
                _ => return false,
            }
        }
    }
    expect_value.is_none()
}

fn ps_option_value(option: char, value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| match option {
            'p' | 'q' => byte.is_ascii_digit() || byte == b',',
            'o' | 'O' => byte.is_ascii_alphanumeric() || matches!(byte, b',' | b'_' | b'%' | b'='),
            _ => byte.is_ascii_alphanumeric() || matches!(byte, b',' | b'_' | b'-' | b'.'),
        })
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

/// `node --check` parses a script and exits without running it; at most a
/// syntax error with the offending source line reaches the output. That line
/// is file content, so the file operand needs the same read proof as `cat`,
/// and the operand-free form only parses what a proven producer piped in.
/// Every other option is refused: `--require` and `--import` preloads still
/// run under `--check`, and an operand before the flag is a script to run.
pub(super) fn node_syntax_check_arguments(
    arguments: &[String],
    piped_input: bool,
    context: super::PathContext<'_>,
) -> bool {
    let check = |flag: &String| matches!(flag.as_str(), "--check" | "-c");
    // An inherited `NODE_OPTIONS=--require` or loader path also runs code.
    if !context.npm_config_inert {
        return false;
    }
    match arguments {
        [flag] => piped_input && check(flag),
        [flag, target] => {
            check(flag)
                && !target.starts_with('-')
                && super::safe_reads::command_read_target(target, context, false)
        }
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

#[cfg(test)]
mod psql_environment_tests {
    fn stamped(names: &[&str]) -> guard_contracts::GuardExecutionEnvironmentV1 {
        guard_contracts::GuardExecutionEnvironmentV1 {
            path: "/usr/bin".into(),
            environment_names: names.iter().map(|name| (*name).to_owned()).collect(),
            environment_digest: "0".repeat(64),
            home: None,
            git_pager_disabled: false,
            pager_disabled: false,
            xdg_config_home: None,
            git_config_no_system: true,
            library_search_paths: Default::default(),
        }
    }

    #[test]
    fn a_stamped_appdata_leaves_the_windows_startup_file_unknown() {
        let plain = super::psql_environment(Some(&stamped(&["PATH"])), false);
        assert!(plain.startup_files_absent && plain.routing_unset);
        let appdata = super::psql_environment(Some(&stamped(&["PATH", "APPDATA"])), false);
        assert_eq!(appdata.startup_files_absent, !cfg!(windows));
        assert!(appdata.routing_unset);
        for name in ["PSQLRC", "pgsysconfdir"] {
            let environment = super::psql_environment(Some(&stamped(&[name])), false);
            assert!(!environment.startup_files_absent, "{name}");
        }
    }
}
