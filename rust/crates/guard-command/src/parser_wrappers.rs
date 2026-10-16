//! Bounded executable extraction; unsupported execution modes remain uncertain.

use crate::{assignment_name, executable_basename, CommandSegmentV1, RawSegment};

/// Strips `sudo` wrappers and `timeout`/`command`/`time`/`env` prefixes.
///
/// `sudo` changes who runs the program, so it stays in the wrapper chain.
/// A bare `timeout 30 pytest -q` runs the program this text already names,
/// as this user and in this directory, and signals that one child when the
/// clock runs out: it bounds how long the work may take, not what it may do,
/// so it leaves no wrapper behind. `./timeout` and `bin/timeout` are not that
/// clock. They stay in the wrapper chain, and the duration is still skipped
/// so the program they name stays the executable. `command` and `time` run
/// the next word as the program.
/// `env` does that only when every assignment is inert; those names join
/// `environment_names`. A non-inert name leaves `env` as the executable.
/// Any option on a prefix leaves it as the executable, which keeps
/// `command -v`, `time -p` and `env -i` on their existing paths.
pub(super) fn unwrap_wrappers(
    tokens: &[String],
    mut index: usize,
    environment_names: &mut Vec<String>,
) -> Result<(usize, Vec<String>), &'static str> {
    let mut wrappers = Vec::new();
    let mut prefixes = 0usize;
    loop {
        if let Some((next, names)) = transparent_prefix(tokens, index) {
            if wrappers.len() + prefixes == 4 {
                return Err("command_wrapper_limit_exceeded");
            }
            prefixes += 1;
            environment_names.extend(names);
            index = next;
            continue;
        }
        if !tokens
            .get(index)
            .is_some_and(|token| matches!(executable_basename(token), "sudo" | "timeout"))
        {
            break;
        }
        if wrappers.len() + prefixes == 4 {
            return Err("command_wrapper_limit_exceeded");
        }
        let clock = trusted_timeout(&tokens[index]);
        let wrapper = executable_basename(&tokens[index]);
        index += 1;
        if wrapper == "timeout" {
            if clock {
                prefixes += 1;
            } else {
                wrappers.push(wrapper.to_owned());
            }
            if tokens.get(index).is_some_and(|value| value == "--") {
                index += 1;
            }
            if !tokens.get(index).is_some_and(|value| timeout(value)) {
                return Err("transparent_wrapper_not_yet_supported");
            }
            index += 1;
            let Some(command) = tokens.get(index) else {
                return Err("transparent_wrapper_not_yet_supported");
            };
            if command.is_empty() || command.starts_with('-') || assignment_name(command).is_some()
            {
                return Err("transparent_wrapper_not_yet_supported");
            }
            continue;
        }
        wrappers.push(wrapper.to_owned());
        while let Some(option) = tokens.get(index) {
            match option.as_str() {
                "--" => {
                    index += 1;
                    break;
                }
                "-n" | "--non-interactive" => index += 1,
                "-T" | "--command-timeout" => {
                    if !tokens.get(index + 1).is_some_and(|value| timeout(value)) {
                        return Err("transparent_wrapper_not_yet_supported");
                    }
                    index += 2;
                }
                value if value.starts_with("--command-timeout=") => {
                    if !timeout(&value["--command-timeout=".len()..]) {
                        return Err("transparent_wrapper_not_yet_supported");
                    }
                    index += 1;
                }
                value if value.starts_with('-') => {
                    return Err("transparent_wrapper_not_yet_supported");
                }
                _ => break,
            }
        }
        let Some(command) = tokens.get(index) else {
            return Err("transparent_wrapper_not_yet_supported");
        };
        if command.is_empty() || assignment_name(command).is_some() {
            return Err("transparent_wrapper_not_yet_supported");
        }
    }
    Ok((index, wrappers))
}

/// `command X`, `time X` and `env NAME=value... X` run `X` with no other
/// change. Bare `env X` is left alone: it only bypasses shell functions, and
/// extension floors key on that spelling. An `env` prefix is transparent only
/// when every assignment is inert. Any other name can retarget the program,
/// so the `env` executable stays in place and the command remains uncertain.
fn transparent_prefix(tokens: &[String], index: usize) -> Option<(usize, Vec<String>)> {
    let mut next = index + 1;
    let mut names = Vec::new();
    match tokens.get(index)?.as_str() {
        "command" | "time" => {}
        "env" | "/usr/bin/env" | "/bin/env" => {
            while let Some(name) = tokens.get(next).and_then(|value| assignment_name(value)) {
                if !crate::command_compatibility::inert_environment_name(name) {
                    return None;
                }
                names.push(name.to_owned());
                next += 1;
            }
            if names.is_empty() {
                return None;
            }
        }
        _ => return None,
    }
    let program = tokens.get(next)?;
    (!program.is_empty() && !program.starts_with('-') && assignment_name(program).is_none())
        .then_some((next, names))
}

/// Whether this word is the system clock rather than a file that happens to
/// be named for it. The shell resolves a bare `timeout` on `PATH`, and the
/// two system paths name the same program; `./timeout`, `bin/timeout` and
/// `/tmp/timeout` are whatever that file holds, so they stay wrappers and
/// keep the command under review.
fn trusted_timeout(token: &str) -> bool {
    matches!(token, "timeout" | "/usr/bin/timeout" | "/bin/timeout")
}

/// A duration `timeout` reads: a number of seconds, or one carrying an `s`,
/// `m`, `h` or `d` unit. `timeout 5m npm run build` bounds the same single
/// child that `timeout 300 npm run build` bounds, so the unit a person writes
/// cannot be what decides whether the command is read at all.
fn timeout(value: &str) -> bool {
    let number = value.strip_suffix(['s', 'm', 'h', 'd']).unwrap_or(value);
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    number.len() <= 10
        && !whole.is_empty()
        && whole.bytes().all(|byte| byte.is_ascii_digit())
        && fraction.bytes().all(|byte| byte.is_ascii_digit())
}

/// `command -v NAME` reports a path or a name and runs nothing, so the segment
/// stays a plain `command` segment. `command -V` prints a function body, so it
/// is not a lookup and stays unproven.
pub(super) fn is_command_lookup(executable: Option<&str>, arguments: &[String]) -> bool {
    let options = arguments
        .iter()
        .take_while(|argument| argument.starts_with('-') && argument.as_str() != "--")
        .collect::<Vec<_>>();
    executable.is_some_and(|value| executable_basename(value) == "command")
        && !options.is_empty()
        && options.iter().all(|option| {
            option.len() > 1
                && option[1..]
                    .chars()
                    .all(|letter| matches!(letter, 'p' | 'v'))
        })
        && options.iter().any(|option| option.contains('v'))
}

pub(super) fn is_file_shell_invocation(executable: Option<&str>, arguments: &[String]) -> bool {
    if !executable.is_some_and(|value| matches!(executable_basename(value), "sh" | "bash" | "zsh"))
    {
        return false;
    }
    let arguments = if arguments.first().is_some_and(|value| value == "--") {
        &arguments[1..]
    } else {
        arguments
    };
    // This represents the interpreter invocation, not the script's contents.
    // It keeps native execution review; shell options and inline code stay opaque.
    arguments.first().is_some_and(|script| {
        !script.starts_with('-') && script.ends_with(".sh") && script.len() > 3
    })
}

pub(super) fn is_encoded_stdin_shell(
    executable: Option<&str>,
    arguments: &[String],
    raw: &RawSegment,
    previous: Option<&CommandSegmentV1>,
) -> bool {
    // Do not normalize arbitrary interpreters, script files, shell flags or
    // unknown stdin. This exact producer/consumer shape is observed by the
    // native encoded-execution matcher, with the full raw pipeline preserved.
    let Some(previous) = previous else {
        return false;
    };
    executable.is_some_and(|value| matches!(executable_basename(value), "sh" | "bash" | "zsh"))
        && arguments.is_empty()
        && raw.pipeline_index > 0
        && previous.pipeline_index + 1 == raw.pipeline_index
        && previous.execution_context == format!("top:{}", raw.group_index)
        && previous
            .executable
            .as_deref()
            .is_some_and(|value| matches!(executable_basename(value), "base64" | "gpg" | "openssl"))
        && previous.arguments.iter().any(|argument| argument == "-d")
}

#[cfg(test)]
mod tests {
    use crate::{parse_command, CommandModelRequestV1};

    fn parse(command: &str) -> crate::CanonicalCommandV1 {
        parse_command(&CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        })
        .unwrap()
    }

    #[test]
    fn file_shell_invocation_is_not_a_transparent_wrapper() {
        for command in [
            "bash ./preflight.sh fixture",
            "sh -- './pre flight.sh'",
            "zsh ./fixtures/preflight.sh",
        ] {
            let model = parse(command);
            assert_eq!(model.confidence, "exact", "{command}");
            assert_eq!(model.segments.len(), 1);
            assert!(model.wrapper_chain.is_empty());
            assert!(matches!(
                model.segments[0].executable.as_deref(),
                Some("bash" | "sh" | "zsh")
            ));
        }
        for command in [
            "bash -c 'cat .env'",
            "bash -s",
            "bash -e ./preflight.sh",
            "sh --",
            "bash .sh",
        ] {
            assert_eq!(parse(command).confidence, "uncertain", "{command}");
        }
    }

    #[test]
    fn sudo_keeps_source_and_wrapper_evidence_for_destructive_arguments() {
        for command in [
            "sudo -n git push origin main --force",
            "sudo --command-timeout 10 git --config-env token=TOKEN push origin main --force",
            "sudo -T 10 -- git push origin main --force",
        ] {
            let model = parse(command);
            assert_eq!(model.confidence, "exact", "{command}");
            assert_eq!(model.wrapper_chain, ["sudo"]);
            assert_eq!(model.segments[0].wrapper_chain, ["sudo"]);
            assert_eq!(model.segments[0].text, command);
            assert_eq!(model.segments[0].tokens[0], "sudo");
            assert_eq!(model.segments[0].executable.as_deref(), Some("git"));
            assert_eq!(model.segments[0].arguments.last().unwrap(), "--force");
        }
    }

    #[test]
    fn unknown_wrapper_modes_cannot_hide_or_fabricate_executables() {
        for command in [
            "sudo -s git push --force",
            "sudo -i git status",
            "sudo -u user git status",
            "sudo --command-timeout git push --force",
            "sudo -n FOO=bar git status",
            "sudo sudo sudo sudo sudo git status",
            "sudo -n",
            "sudo -- sh -c 'rm -rf /tmp/x'",
        ] {
            let model = parse(command);
            assert_eq!(model.confidence, "uncertain", "{command}");
            assert!(model.segments.is_empty());
        }
    }

    #[test]
    fn only_observed_decoder_pipelines_accept_bare_shell_consumers() {
        let source = "echo 'cm0gLXJmIC4vYnVpbGQ=' | base64 -d | sh";
        let model = parse(source);
        assert_eq!(model.confidence, "exact");
        assert_eq!(model.segments.len(), 3);
        assert_eq!(model.segments[2].executable.as_deref(), Some("sh"));
        for source in [
            "echo arbitrary | sh",
            "base64 -d; sh",
            "base64 -d | sh -c payload",
            "sh",
        ] {
            assert_eq!(parse(source).confidence, "uncertain", "{source}");
        }
    }

    #[test]
    fn posix_embedded_braces_are_arguments_but_brace_groups_are_unsupported() {
        let model = parse("aws s3api put-object-tagging --tagging TagSet=[{Key=env,Value=prod}]");
        assert_eq!(model.confidence, "exact");
        assert_eq!(
            model.segments[0].arguments.last().unwrap(),
            "TagSet=[{Key=env,Value=prod}]"
        );
        for source in [
            "{ rm -rf /tmp/x; }",
            "true;{ rm -rf /tmp/x;}",
            "true&&{ rm -rf /tmp/x;}",
            "printf x|{ rm -rf /tmp/x;}",
            "printf %s ${COMMAND}",
            "${COMMAND} --force",
            "sudo -n git ${ACTION}",
        ] {
            let model = parse(source);
            assert_eq!(model.confidence, "uncertain", "{source}");
            assert!(model.segments.is_empty(), "{source}");
        }
        assert_eq!(parse("printf %s '${COMMAND}'").confidence, "exact");
    }

    #[test]
    fn command_time_and_env_assignment_prefixes_expose_the_program() {
        for (command, executable, names) in [
            ("command bun run build", "bun", &[][..]),
            ("time bun run build", "bun", &[]),
            ("command git push origin main", "git", &[]),
            (
                "CI=1 env NODE_ENV=production command bun run build",
                "bun",
                &["CI", "NODE_ENV"],
            ),
        ] {
            let model = parse(command);
            assert_eq!(model.confidence, "exact", "{command}");
            assert!(model.wrapper_chain.is_empty(), "{command}");
            assert!(!model.path_overridden, "{command}");
            let segment = &model.segments[0];
            assert_eq!(segment.executable.as_deref(), Some(executable), "{command}");
            assert_eq!(segment.environment_names, names, "{command}");
        }
        for command in ["env PATH=/tmp/x bun run build", "env NODE_PATH=x bun s.ts"] {
            let model = parse(command);
            assert_eq!(model.confidence, "uncertain", "{command}");
            assert!(!model.path_overridden, "{command}");
        }
        let model = parse("sudo env CI=1 rm -rf build");
        assert_eq!(model.confidence, "exact");
        assert_eq!(model.wrapper_chain, ["sudo"]);
        assert_eq!(model.segments[0].executable.as_deref(), Some("rm"));
        assert_eq!(model.segments[0].environment_names, ["CI"]);
    }

    #[test]
    fn prefixes_with_options_or_shells_stay_unmodeled() {
        for command in [
            "command -p bun run build",
            "time -p bun run build",
            "env bun run build",
            "env -i bun run build",
            "env -u HOME -i bun run build",
            "env -S 'bun run build'",
            "env CI=1 sh -c 'rm -rf x'",
            "command sh -c 'rm -rf x'",
            "command env",
            "env CI=1",
            "command command command command command bun run build",
        ] {
            let model = parse(command);
            assert!(
                model.confidence != "exact"
                    || model.segments[0].executable.as_deref() != Some("bun")
                        && model.segments[0].executable.as_deref() != Some("rm"),
                "{command}: {:?}",
                model.segments.first().map(|segment| &segment.executable)
            );
        }
    }
}
