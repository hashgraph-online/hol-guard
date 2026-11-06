//! Bounded executable extraction; unsupported execution modes remain uncertain.

use crate::{assignment_name, executable_basename, CommandSegmentV1, RawSegment};

#[path = "parser_env_prefix.rs"]
mod env_prefix;
#[path = "parser_launchers.rs"]
mod launchers;

pub(crate) use launchers::launcher_program;

/// Strips `sudo` wrappers and `timeout`/`command`/`time`/`env` prefixes, and
/// the scheduling prefixes `launchers` reads.
///
/// `sudo` changes who runs the program, so it stays in the wrapper chain.
/// A bare `timeout 30 pytest -q` runs the program this text already names,
/// as this user and in this directory, and signals that one child when the
/// clock runs out: it bounds how long the work may take, not what it may do,
/// so it leaves no wrapper behind. `./timeout` and `bin/timeout` are not that
/// clock. They stay in the wrapper chain, and the duration is still skipped
/// so the program they name stays the executable. `command` and `time` run
/// the next word as the program.
/// `env` does that for the assignments it carries, whatever they name, and for
/// the names it removes; all of them join `environment_names`. An operand
/// `env` would take as an assignment of its own leaves `env` as the executable.
/// Any option on `command` or `time` leaves that prefix as the executable,
/// which keeps `command -v` and `time -p` on their existing paths.
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
        if let Some(next) = launchers::launcher_program(tokens, index) {
            if wrappers.len() + prefixes == 4 {
                return Err("command_wrapper_limit_exceeded");
            }
            prefixes += 1;
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

/// The spellings of `env` this parser reads as a prefix rather than as the
/// program itself. `./env` and `/opt/bin/env` are files of the user's own that
/// share the name and do whatever they were written to do, so neither is one.
pub(crate) fn env_spelling(token: &str) -> bool {
    matches!(token, "env" | "/usr/bin/env" | "/bin/env")
}

/// `command X`, `time X` and `env NAME=value... X` run `X` with no other
/// change. Bare `env X` is left alone: it only bypasses shell functions, and
/// extension floors key on that spelling.
///
/// An `env` prefix carries its names the way the shell's own prefix does.
/// `env FOO=1 npm test` and `FOO=1 npm test` run the same program with the
/// same environment, and the second models exactly, so the first reading as a
/// wrapper this parser does not model left ordinary work refused outright
/// with no approval to give it. Each name joins `environment_names`, where
/// `PATH` already marks the command as pointing the program elsewhere and the
/// compatibility layer reads the rest; an `env` that names no program at all,
/// or whose next operand `env` would take as an assignment of its own, is
/// still the environment dump, and keeps its own spelling.
///
/// `env_prefix` reads the controls that only decide which names the program
/// starts with; each name it collects joins `environment_names` as a written
/// one does, so `-u PATH` keeps the review a written `PATH=` keeps.
pub(crate) fn transparent_prefix(tokens: &[String], index: usize) -> Option<(usize, Vec<String>)> {
    let mut next = index + 1;
    let mut names = Vec::new();
    let mut is_env = false;
    match tokens.get(index)?.as_str() {
        "command" | "time" => {}
        token if env_spelling(token) => {
            is_env = true;
            let (position, decided) = env_prefix::env_names(tokens, next)?;
            next = position;
            names = decided;
        }
        _ => return None,
    }
    let program = tokens.get(next)?;
    // `env` consumes every operand holding an `=`, not only the ones that
    // spell a shell name, so `env FOO=1 A-B=1 rm -rf ~` sets `A-B` and runs
    // `rm`. The bare prefix `FOO=1 A-B=1 rm -rf ~` really does run a program
    // named `A-B=1`, so reading the two alike would model the wrong program.
    // A word the shell would not take as an assignment ends the prefix and
    // leaves `env` itself to be judged.
    let consumed_by_env = is_env && program.contains('=');
    (!program.is_empty()
        && !program.starts_with('-')
        && assignment_name(program).is_none()
        && !consumed_by_env)
        .then_some((next, names))
}

/// Whether this word is the system clock rather than a file that happens to
/// be named for it. The shell resolves a bare `timeout` on `PATH`, and the
/// two system paths name the same program; `./timeout`, `bin/timeout` and
/// `/tmp/timeout` are whatever that file holds, so they stay wrappers and
/// keep the command under review.
pub(crate) fn trusted_timeout(token: &str) -> bool {
    matches!(token, "timeout" | "/usr/bin/timeout" | "/bin/timeout")
}

/// The seconds in a duration `timeout` reads: a number of seconds, or one
/// carrying an `s`, `m`, `h` or `d` unit, and `None` for anything else.
///
/// `timeout 5m npm run build` bounds the same single child that `timeout 300
/// npm run build` bounds, so the unit a person writes cannot be what decides
/// whether the command is read at all. Seconds are whole here, so a fractional
/// duration rounds up: cutting `timeout 2.1` to two would end the run before
/// the clock it was given. An exact zero turns `timeout` off and is answered
/// as `0`, which bounds nothing.
pub(crate) fn clock_seconds(value: &str) -> Option<u64> {
    let number = value.strip_suffix(['s', 'm', 'h', 'd']).unwrap_or(value);
    let unit = match value.bytes().last() {
        Some(b'm') => 60u64,
        Some(b'h') => 3600,
        Some(b'd') => 86400,
        _ => 1,
    };
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    if number.len() > 10
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let duration = number.parse::<f64>().ok()? * unit as f64;
    Some(if duration == 0.0 {
        0
    } else {
        duration.ceil() as u64
    })
}

/// Whether this word is a duration `timeout` reads.
fn timeout(value: &str) -> bool {
    clock_seconds(value).is_some()
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
    arguments
        .first()
        .is_some_and(|script| names_a_script_file(script))
}

/// Whether a first operand names a file this interpreter opens and runs.
///
/// A shell runs the file the word names, whatever the name ends in, so the
/// suffix is not what makes a run readable: `sh ./gradlew test`,
/// `bash ./mvnw -q test` and `sh ./configure` are the same shape as
/// `sh ./build.sh`, and a wrapper an ecosystem ships without an extension is
/// the ordinary way those builds are driven. Requiring `.sh` left every one of
/// them unmodelled, which is a command no owner can approve rather than a
/// stricter reading of it.
///
/// A word carrying shell syntax is not a file name: what `sh $PLAN`,
/// `sh "$(pick)"` or `sh build-*` runs is settled by expansion the text does
/// not fix, so those keep the uncertainty they arrive with, and so does a home
/// path the shell expands. A directory is not a script either, and a leading
/// `-` is an option. A space is none of that: the word reaches here already
/// split, so `sh -- './pre flight.sh'` names one file the shell opens.
///
/// Braces and a leading `=` are expansions the word carries inside itself, so
/// they are refused with the rest of the syntax rather than read as part of a
/// name. `sh ./build{,}` runs `sh ./build ./build` and `sh =make` runs whatever
/// `make` resolves to on this `PATH`; reading either as one file would bind an
/// approval, and the credential scan behind it, to a path that is never opened.
fn names_a_script_file(script: &str) -> bool {
    !script.is_empty()
        && !script.starts_with('-')
        && !script.starts_with('~')
        && !script.starts_with('=')
        && !script.ends_with('/')
        && script != "."
        && script != ".."
        && !script.contains([
            '$', '*', '?', '[', ']', '{', '}', '`', '"', '\'', '\\', '\n', '\t', '\r', '\0',
        ])
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

/// Shells that take their whole script in one `-c` word and read no startup
/// file before running it.
///
/// `zsh` is not one of them: it reads `~/.zshenv` whatever option it is given,
/// so its script is never the whole command.
/// Words that run their first operand with other credentials.
///
/// `sudo`, and the four spellings that stand in for it, pick who runs the
/// program rather than which program runs, so the word after one is the
/// command. Only `sudo` is also read as an interpreter, which is why the
/// other four need naming here: every reader that walks past a wrapper to
/// the program behind it reads this one list.
pub(crate) const PRIVILEGE_WRAPPERS: &[&str] = &["doas", "gsudo", "pkexec", "run0", "sudo"];

const INLINE_SHELLS: &[&str] = &["sh", "bash", "dash", "ash"];

/// The script a shell carries in this same text, when the text is nothing but
/// that invocation.
///
/// `sh -c 'npm run build'` runs the programs those words name and nothing the
/// text does not say, so the script is the command to model. An expansion or a
/// substitution builds a word this text does not hold, so it is left alone, as
/// is any other spelling: an option the shell reads differently (a login
/// shell's `-lc` sources the profile files first), a `$0`, a script on stdin,
/// a prefix or assignment in front of the shell, and a pipeline or redirect
/// around it all keep their existing paths.
pub(super) fn inline_shell_script(raw: &str) -> Option<String> {
    if raw.len() > crate::MAX_COMMAND_BYTES
        || raw.contains(['$', '`', '\n', '\r'])
        || carries_unquoted_operator(raw)
    {
        return None;
    }
    let tokens = crate::shell_tokens(raw, false).ok()?;
    let (shell, rest) = tokens.split_first()?;
    if !INLINE_SHELLS.contains(&shell.as_str()) {
        return None;
    }
    let [script] = shell_options::carries_script(rest)? else {
        return None;
    };
    if script.trim().is_empty() {
        return None;
    }
    Some(script.clone())
}

/// Whether this text is only a shell carrying a script under options Guard
/// does not model, such as a login shell's `-lc`, a `--posix` or any `zsh`,
/// while the same script under plain `bash -c` is one Guard reads. Those
/// options run startup files or change how the script's words are read, so
/// the invocation stays blocked; this only says whether a plain `-c` is a
/// recovery that would be reviewed instead.
pub(crate) fn refused_inline_shell(raw: &str) -> bool {
    if raw.len() > crate::MAX_COMMAND_BYTES
        || raw.contains(['$', '`', '\n', '\r'])
        || carries_unquoted_operator(raw)
    {
        return false;
    }
    let Ok(tokens) = crate::shell_tokens(raw, false) else {
        return false;
    };
    let [shell, options @ .., flag, script] = tokens.as_slice() else {
        return false;
    };
    let readable_shell = INLINE_SHELLS.contains(&shell.as_str()) || shell == "zsh";
    let carries_flag =
        flag.len() > 1 && !flag.starts_with("--") && flag.starts_with('-') && flag.contains('c');
    if !readable_shell
        || !carries_flag
        || options
            .first()
            .is_some_and(|word| !word.starts_with(['-', '+']))
        || script.contains('\'')
        || inline_shell_script(raw).is_some()
    {
        return false;
    }
    inline_shell_script(&format!("bash -c '{script}'")).is_some()
}

/// Whether an operator stands outside the quoting, where the shell reads it as
/// its own word.
///
/// The tokenizer splits on whitespace alone, so `sh -c 'a; b'>out` comes back
/// as three words with the redirect stuck to the script. The shell instead
/// redirects the whole invocation, so the script is not the command this text
/// runs and the invocation keeps its existing path.
fn carries_unquoted_operator(raw: &str) -> bool {
    let mut quote: Option<char> = None;
    let mut characters = raw.chars();
    while let Some(character) = characters.next() {
        match (quote, character) {
            (None, '\\') | (Some('"'), '\\') => {
                characters.next();
            }
            (Some(open), closing) if closing == open => quote = None,
            (None, '\'' | '"') => quote = Some(character),
            (None, '<' | '>' | '|' | '&' | ';' | '(' | ')') => return true,
            _ => {}
        }
    }
    false
}

#[path = "parser_wrappers_shell_options.rs"]
mod shell_options;

#[cfg(test)]
#[path = "parser_wrappers_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "parser_wrappers_shell_options_tests.rs"]
mod shell_options_tests;
