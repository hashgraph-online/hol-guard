//! Bounded executable extraction; unsupported execution modes remain uncertain.

use crate::{assignment_name, executable_basename, CommandSegmentV1, RawSegment};

pub(super) fn unwrap_sudo(
    tokens: &[String],
    mut index: usize,
) -> Result<(usize, Vec<String>), &'static str> {
    let mut wrappers = Vec::new();
    while tokens
        .get(index)
        .is_some_and(|token| executable_basename(token) == "sudo")
    {
        if wrappers.len() == 4 {
            return Err("command_wrapper_limit_exceeded");
        }
        wrappers.push("sudo".to_owned());
        index += 1;
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

fn timeout(value: &str) -> bool {
    !value.is_empty() && value.len() <= 10 && value.bytes().all(|byte| byte.is_ascii_digit())
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
}
