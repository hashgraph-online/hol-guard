//! Source-faithful interpreter option and operand admission.
#[derive(Clone, Debug, serde::Serialize)]
pub struct InterpreterFlagPayload {
    pub script_text: String,
    pub tokens_consumed: usize,
}

static LETTERS: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();

fn letter_run(token: &str) -> bool {
    LETTERS
        .get_or_init(|| regex::Regex::new(r"^\p{L}+$").expect("literal regex"))
        .is_match(token)
}

/// Exact option/operand admission shared by the wrapper and public helper.
pub fn shell_interpreter_command_payload(
    parts: &[String],
    command_index: usize,
) -> Option<InterpreterFlagPayload> {
    parse_payload(parts, command_index, false)
}

pub(crate) fn legacy_shell_interpreter_command_payload(
    parts: &[String],
    command_index: usize,
) -> Option<InterpreterFlagPayload> {
    parse_payload(parts, command_index, true)
}

fn parse_payload(
    parts: &[String],
    command_index: usize,
    legacy: bool,
) -> Option<InterpreterFlagPayload> {
    use crate::command_option_parsing::python_is_whitespace;
    let trim = |text: &str| -> String {
        if legacy {
            text.trim()
        } else {
            text.trim_matches(python_is_whitespace)
        }
        .to_owned()
    };
    let mut index = command_index.checked_add(1)?;
    while index < parts.len() {
        let trimmed = trim(&parts[index]);
        let token = trimmed.trim_start_matches('(').trim_end_matches(')');
        if token.is_empty() {
            index += 1;
            continue;
        }
        if token == "-" || token == "--" {
            return None;
        }
        if !legacy && (token == "--command" || token.starts_with("--command=")) {
            let (script, consumed) = if let Some(script) = token.strip_prefix("--command=") {
                (script, index - command_index)
            } else {
                (parts.get(index + 1)?.as_str(), index + 1 - command_index)
            };
            let script_text = trim(script);
            if script_text.is_empty() {
                return None;
            }
            return Some(InterpreterFlagPayload {
                script_text,
                tokens_consumed: consumed,
            });
        }
        if token.starts_with("--") {
            let option = token.split('=').next().unwrap_or_default();
            index += if ["--init-file", "--rcfile"].contains(&option) && !token.contains('=') {
                2
            } else {
                1
            };
            continue;
        }
        if !token.starts_with('-') && !token.starts_with('+') {
            return None;
        }
        let flags: Vec<char> = token[1..].chars().collect();
        let mut has_command = false;
        let mut consumes_value = false;
        if if legacy {
            flags.iter().all(char::is_ascii_alphabetic)
        } else {
            letter_run(&token[1..])
        } {
            for (flag_index, flag) in flags.iter().enumerate() {
                if matches!(*flag, 'O' | 'o') {
                    consumes_value = legacy || flag_index == flags.len() - 1;
                    if !legacy {
                        break;
                    }
                }
                if (legacy || token.starts_with('-')) && *flag == 'c' {
                    has_command = true;
                }
            }
        }
        let script_index = index + 1 + usize::from(consumes_value);
        if has_command {
            let script_text = trim(parts.get(script_index)?);
            if script_text.is_empty() {
                return None;
            }
            return Some(InterpreterFlagPayload {
                script_text,
                tokens_consumed: script_index - command_index,
            });
        }
        index += 1 + usize::from(consumes_value);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_parser_preserves_both_interpreter_profiles() {
        let parts = |flags: &str| ["bash", flags, "pipefail", "echo hi"].map(str::to_owned);
        assert!(shell_interpreter_command_payload(&parts("-oc"), 0).is_none());
        assert_eq!(
            legacy_shell_interpreter_command_payload(&parts("-oc"), 0)
                .unwrap()
                .script_text,
            "echo hi"
        );
        let command = ["bash", "--command=echo hi"].map(str::to_owned);
        assert_eq!(
            shell_interpreter_command_payload(&command, 0)
                .unwrap()
                .script_text,
            "echo hi"
        );
        assert!(legacy_shell_interpreter_command_payload(&command, 0).is_none());
        for parser in [
            shell_interpreter_command_payload,
            legacy_shell_interpreter_command_payload,
        ] {
            assert_eq!(parser(&parts("-co"), 0).unwrap().tokens_consumed, 3);
        }
    }
}
