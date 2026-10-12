//! Source-faithful interpreter option and operand admission.
#[derive(serde::Serialize)]
pub struct InterpreterFlagPayload {
    pub script_text: String,
    pub tokens_consumed: usize,
}

/// Exact option/operand admission shared by the wrapper and public helper.
pub fn shell_interpreter_command_payload(
    parts: &[String],
    command_index: usize,
) -> Option<InterpreterFlagPayload> {
    use crate::command_option_parsing::python_is_whitespace;
    static LETTERS: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let mut index = command_index.checked_add(1)?;
    while index < parts.len() {
        let token = parts[index]
            .trim_matches(python_is_whitespace)
            .trim_start_matches('(')
            .trim_end_matches(')');
        if token.is_empty() {
            index += 1;
            continue;
        }
        if token == "-" || token == "--" {
            return None;
        }
        if token == "--command" || token.starts_with("--command=") {
            let (script, consumed) = if let Some(script) = token.strip_prefix("--command=") {
                (script, index - command_index)
            } else {
                (parts.get(index + 1)?.as_str(), index + 1 - command_index)
            };
            let script_text = script.trim_matches(python_is_whitespace);
            if script_text.is_empty() {
                return None;
            }
            return Some(InterpreterFlagPayload {
                script_text: script_text.to_owned(),
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
        if LETTERS
            .get_or_init(|| regex::Regex::new(r"^\p{L}+$").expect("literal regex"))
            .is_match(&token[1..])
        {
            for (flag_index, flag) in flags.iter().enumerate() {
                if matches!(*flag, 'O' | 'o') {
                    consumes_value = flag_index == flags.len() - 1;
                    break;
                }
                if token.starts_with('-') && *flag == 'c' {
                    has_command = true;
                }
            }
        }
        let script_index = index + 1 + usize::from(consumes_value);
        if has_command {
            let script_text = parts.get(script_index)?.trim_matches(python_is_whitespace);
            if script_text.is_empty() {
                return None;
            }
            return Some(InterpreterFlagPayload {
                script_text: script_text.to_owned(),
                tokens_consumed: script_index - command_index,
            });
        }
        index += 1 + usize::from(consumes_value);
    }
    None
}
