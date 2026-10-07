pub(super) fn is_shell_token_whitespace(value: char) -> bool {
    matches!(value, ' ' | '\t' | '\r' | '\n')
}

pub(super) fn assignment_name(token: &str) -> Option<&str> {
    let (name, _value) = token.split_once('=')?;
    let mut chars = name.chars();
    let first = chars.next()?;
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return None;
    }
    if !chars.all(|value| value == '_' || value.is_ascii_alphanumeric()) {
        return None;
    }
    Some(name)
}
pub(super) fn executable_basename(executable: &str) -> &str {
    executable.rsplit(['/', '\\']).next().unwrap_or(executable)
}

pub(super) fn is_shell_control_keyword(executable: &str) -> bool {
    if executable.contains('/') {
        return false;
    }
    matches!(
        executable,
        "!" | "[["
            | "case"
            | "coproc"
            | "do"
            | "done"
            | "elif"
            | "else"
            | "esac"
            | "fi"
            | "for"
            | "function"
            | "if"
            | "in"
            | "select"
            | "then"
            | "until"
            | "while"
    )
}

pub(super) fn is_transparent_wrapper(executable: &str) -> bool {
    matches!(
        executable_basename(executable),
        "ash"
            | "bash"
            | "command"
            | "dash"
            | "doas"
            | "env"
            | "fish"
            | "lean-ctx"
            | "nice"
            | "nohup"
            | "setsid"
            | "sh"
            | "stdbuf"
            | "sudo"
            | "time"
            | "timeout"
            | "zsh"
    )
}

pub(super) fn is_nested_command_executor(executable: &str, arguments: &[String]) -> bool {
    let basename = executable_basename(executable);
    if matches!(
        basename,
        "." | "eval" | "exec" | "parallel" | "source" | "xargs"
    ) {
        return true;
    }
    if matches!(basename, "fd" | "fd.exe") {
        return fd_arguments_execute_command(arguments);
    }
    basename == "find"
        && !is_contained_compile_check_arguments(arguments)
        && arguments
            .iter()
            .any(|argument| matches!(argument.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir"))
}

pub(super) fn fd_arguments_execute_command(arguments: &[String]) -> bool {
    // fd substitutes filesystem search results into a subprocess invocation.
    // Its exec modes need their own bounded source and execution proof; an
    // exact shell tokenization must not silently treat them as a plain search.
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            return false;
        }
        if matches!(argument.as_str(), "--exec" | "--exec-batch")
            || argument.starts_with("--exec=")
            || argument.starts_with("--exec-batch=")
        {
            return true;
        }
        if argument.starts_with("--") {
            if matches!(
                argument.as_str(),
                "--base-directory"
                    | "--changed-after"
                    | "--changed-before"
                    | "--changed-within"
                    | "--color"
                    | "--exact-depth"
                    | "--exclude"
                    | "--extension"
                    | "--format"
                    | "--ignore-file"
                    | "--max-depth"
                    | "--max-results"
                    | "--min-depth"
                    | "--owner"
                    | "--path-separator"
                    | "--search-path"
                    | "--size"
                    | "--threads"
                    | "--type"
            ) {
                arguments.next();
            }
            continue;
        }
        let Some(cluster) = argument.strip_prefix('-') else {
            continue;
        };
        for (offset, flag) in cluster.char_indices() {
            if matches!(flag, 'x' | 'X') {
                return true;
            }
            if matches!(flag, 'c' | 'd' | 'E' | 'e' | 'j' | 'o' | 'S' | 't') {
                if offset + flag.len_utf8() == cluster.len() {
                    arguments.next();
                }
                break;
            }
        }
    }
    false
}

pub(super) fn is_contained_compile_check_arguments(arguments: &[String]) -> bool {
    const EXPECTED: [&str; 9] = [
        "src",
        "-name",
        "*.py",
        "-exec",
        "python",
        "-m",
        "py_compile",
        "{}",
        "+",
    ];
    arguments.len() == EXPECTED.len()
        && arguments
            .iter()
            .zip(EXPECTED)
            .all(|(actual, expected)| actual == expected)
}
