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

/// The program a Windows command names, without the image extension the
/// shell appends. `node.exe` is the program `node`, so a scan that reads the
/// raw name weighs the same command two different ways depending on how the
/// harness spelled it. Elsewhere a trailing `.exe` is an ordinary part of a
/// file name and stays.
pub(super) fn program_basename(executable: &str) -> &str {
    let name = executable_basename(executable);
    if !cfg!(windows) {
        return name;
    }
    match name.len().checked_sub(4) {
        Some(stem)
            if stem > 0
                && name.is_char_boundary(stem)
                && name[stem..].eq_ignore_ascii_case(".exe") =>
        {
            &name[..stem]
        }
        _ => name,
    }
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
        return fd_arguments_execute_command(arguments)
            && !crate::read_only_fanout::fd::fd_exec(arguments)
                .as_ref()
                .is_some_and(crate::read_only_fanout::fd::producer_shape_proven);
    }
    basename == "find"
        && !is_contained_compile_check_arguments(arguments)
        && crate::read_only_fanout::find_exec(arguments).is_none()
        && find_exec_sed(arguments).is_none()
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

/// `find SHAPE -type f -exec sed|gsed ARGS {} +` (or `... {} \;`): one `sed`
/// run over the regular files a name, type and depth walk found. Agents use it
/// to apply one rename across a test tree, the same edit `sed -i ... tests/*.py`
/// makes over a glob. Answers the `sed` words, program name first, so the
/// caller can run the `sed` script screen over them.
///
/// This only recognizes the shape, so the parser can model the command
/// exactly instead of treating `find` as running an unknown program. It admits
/// nothing: the walk must be the flat shape read-only fan-out accepts, limited
/// to regular files, with `{}` as the last word before the terminator and no
/// other `{}`, `;` or `+` inside the body that could end it early and start a
/// second action. Workspace containment still screens the `sed` script for
/// execution and every operand for reach before the edit runs in the sandbox.
pub(crate) fn find_exec_sed(arguments: &[String]) -> Option<&[String]> {
    let at = arguments.iter().position(|argument| argument == "-exec")?;
    let shape = crate::read_only_fanout::find_shape(&arguments[..at])?;
    if shape.print0 || !shape.regular_files_only {
        return None;
    }
    let (terminator, body) = arguments[at + 1..].split_last()?;
    let (marker, child) = body.split_last()?;
    let name = child.first()?;
    if !matches!(terminator.as_str(), "+" | ";")
        || marker != "{}"
        || !matches!(name.as_str(), "sed" | "gsed")
        || child
            .iter()
            .any(|argument| argument.contains("{}") || matches!(argument.as_str(), ";" | "+"))
        || !sed_exec_only_found_files(child)
    {
        return None;
    }
    Some(child)
}

/// `find -exec sed ... {} +` must not smuggle additional file operands into
/// the edit. The wipe screen checks the walk's paths, not any extra paths
/// named inside sed's argv. Keep the admitted spelling to options, one or
/// more literal scripts, and the substituted `{}` files only.
fn sed_exec_only_found_files(child: &[String]) -> bool {
    let mut index = 1; // the sed/gsed executable
    let mut named_script = false;
    let mut positional_script = false;
    while let Some(argument) = child.get(index) {
        match argument.as_str() {
            "-i" => {
                // BSD sed accepts an empty backup suffix after -i.
                if child.get(index + 1).is_some_and(String::is_empty) {
                    index += 1;
                }
            }
            "-e" | "--expression" => {
                // GNU sed may permute a later -e option ahead of an earlier
                // positional word, turning that earlier word into a file.
                if positional_script {
                    return false;
                }
                index += 1;
                if child.get(index).is_none() {
                    return false;
                }
                named_script = true;
            }
            "-n" | "-E" | "-r" | "-s" | "-u" | "-z" => {}
            "--" => {
                let trailing = &child[index + 1..];
                return if named_script || positional_script {
                    trailing.is_empty()
                } else {
                    trailing.len() == 1
                };
            }
            word if word.starts_with("--expression=") && word.len() > "--expression=".len() => {
                if positional_script {
                    return false;
                }
                named_script = true;
            }
            word if word.starts_with("-e") && word.len() > 2 => {
                if positional_script {
                    return false;
                }
                named_script = true;
            }
            word if word.starts_with("-i") && word.len() > 2 => {}
            word if word.starts_with('-') => return false,
            _ => {
                // Any second positional operand is a file beyond those find
                // supplies; never omit it from the broad-wipe screen.
                if named_script || positional_script {
                    return false;
                }
                positional_script = true;
            }
        }
        index += 1;
    }
    named_script || positional_script
}
