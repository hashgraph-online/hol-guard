//! `gh ... --jq` filter safety (`shell_static_safety.py`): programs may not
//! reach process environment or module data outside stdin.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::sync::LazyLock;

use fancy_regex::Regex;

use crate::hook_adapter_pytext::compile_fancy;

static JQ_EXTERNAL_INPUT: LazyLock<Regex> = LazyLock::new(|| {
    compile_fancy(r"\$ENV\b|(?<![A-Za-z0-9_$\.])(env|import|include)(?![A-Za-z0-9_])")
});

const BOOLEAN_OPTIONS: [&str; 19] = [
    "--ascii-output",
    "--compact-output",
    "--exit-status",
    "--join-output",
    "--monochrome-output",
    "--raw-input",
    "--raw-output",
    "--slurp",
    "--sort-keys",
    "-C",
    "-M",
    "-R",
    "-S",
    "-a",
    "-c",
    "-e",
    "-j",
    "-r",
    "-s",
];

/// `_github_jq_filter_args_are_safe`.
pub(crate) fn github_jq_filter_args_are_safe(args: &[String]) -> bool {
    let Some(normalized) = collapse_single_quoted_shell_argument(args) else {
        return false;
    };
    let mut index = 0;
    while index < normalized.len() {
        let token = normalized[index].as_str();
        if token == "2>&1" || token == "1>&2" || BOOLEAN_OPTIONS.contains(&token) {
            index += 1;
            continue;
        }
        if token.starts_with('-') {
            return false;
        }
        return index == normalized.len() - 1 && github_jq_program_is_safe(token);
    }
    false
}

/// `_github_jq_program_is_safe`.
pub(crate) fn github_jq_program_is_safe(program: &str) -> bool {
    let chars: Vec<char> = program.chars().collect();
    let normalized: String =
        if chars.len() >= 2 && chars[0] == '\'' && chars[chars.len() - 1] == '\'' {
            chars[1..chars.len() - 1].iter().collect()
        } else {
            program.to_owned()
        };
    let sanitized = strip_jq_strings_and_comments(&normalized);
    // Match offsets are byte offsets; neighbour lookups work on bytes of the
    // sanitized text, which only gains ASCII blanks.
    for found in JQ_EXTERNAL_INPUT.captures_iter(&sanitized).flatten() {
        let whole = found.get(0).expect("whole match");
        if whole.as_str().starts_with('$') {
            return false;
        }
        let previous = previous_nonspace(&sanitized, whole.start());
        let following = next_nonspace(&sanitized, whole.end());
        let keyword = found.get(1).map_or("", |group| group.as_str());
        let object_position =
            matches!(previous, Some('{' | ',')) && matches!(following, Some(',' | '}'));
        if previous == Some('.') || following == Some(':') || object_position {
            if keyword == "env" && matches!(following, Some(',' | '}')) {
                return false;
            }
            continue;
        }
        return false;
    }
    true
}

fn previous_nonspace(value: &str, end: usize) -> Option<char> {
    value[..end]
        .chars()
        .rev()
        .find(|character| !crate::codex_output_py::is_py_space(*character))
}

fn next_nonspace(value: &str, start: usize) -> Option<char> {
    value[start..]
        .chars()
        .find(|character| !crate::codex_output_py::is_py_space(*character))
}

/// `_strip_jq_strings_and_comments`. String text is blanked, but `\( ... )`
/// interpolation bodies are code that jq runs, so they stay visible to the
/// `env`/`$ENV` scan.
pub(crate) fn strip_jq_strings_and_comments(program: &str) -> String {
    let mut output = String::with_capacity(program.len());
    let mut in_string = false;
    let mut in_comment = false;
    let mut escaped = false;
    // Open-paren depth of each interpolation currently being read as code.
    let mut interpolations: Vec<usize> = Vec::new();
    for character in program.chars() {
        if in_comment {
            in_comment = character != '\n';
            output.push(if character == '\n' { '\n' } else { ' ' });
            continue;
        }
        if in_string {
            if escaped {
                escaped = false;
                if character == '(' {
                    in_string = false;
                    interpolations.push(1);
                    output.push('(');
                    continue;
                }
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            output.push(' ');
            continue;
        }
        match character {
            '"' => {
                in_string = true;
                output.push(' ');
            }
            '#' => {
                in_comment = true;
                output.push(' ');
            }
            _ => {
                if let Some(depth) = interpolations.last_mut() {
                    if character == '(' {
                        *depth += 1;
                    } else if character == ')' {
                        *depth -= 1;
                        if *depth == 0 {
                            interpolations.pop();
                            in_string = true;
                        }
                    }
                }
                output.push(character);
            }
        }
    }
    output
}

/// `_collapse_single_quoted_shell_argument`.
pub(crate) fn collapse_single_quoted_shell_argument(args: &[String]) -> Option<Vec<String>> {
    let mut normalized: Vec<String> = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        if !token.starts_with('\'') {
            normalized.push(token.clone());
            index += 1;
            continue;
        }
        if token.chars().count() > 1 && token.ends_with('\'') {
            let inner: String = token.chars().skip(1).collect();
            let inner = inner.strip_suffix('\'').unwrap_or(&inner);
            if inner.contains('\'') {
                return None;
            }
            normalized.push(token.clone());
            index += 1;
            continue;
        }
        let mut parts = vec![token.clone()];
        index += 1;
        while index < args.len() && !args[index].ends_with('\'') {
            if args[index].contains('\'') {
                return None;
            }
            parts.push(args[index].clone());
            index += 1;
        }
        if index >= args.len() {
            return None;
        }
        let closing = &args[index];
        let before_last =
            &closing[..closing.len() - closing.chars().last().map_or(0, char::len_utf8)];
        if before_last.contains('\'') {
            return None;
        }
        parts.push(closing.clone());
        normalized.push(parts.join(" "));
        index += 1;
    }
    Some(normalized)
}

#[cfg(test)]
mod tests {
    use super::github_jq_program_is_safe;

    #[test]
    fn interpolation_bodies_are_scanned_as_code() {
        for program in [
            r#""\(env.GH_TOKEN)""#,
            r#""\($ENV.X)""#,
            r#""a\("b" + env.HOME)c""#,
            r#""\((1) + env.HOME)""#,
        ] {
            assert!(!github_jq_program_is_safe(program), "{program}");
        }
        for program in [r#""\(.name) is env""#, r#""\(.a)-\(.b)""#, r#""env""#] {
            assert!(github_jq_program_is_safe(program), "{program}");
        }
    }
}
