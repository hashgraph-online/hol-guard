//! Launches and values inside compound text the parser leaves uncertain, each
//! read as the same words standing on their own: a launch behind a redirect
//! into a literal path, an inline program run from a list or a loop, a path
//! rooted at a quoted parameter, and a plain shell variable.
use super::prefix;
use super::redirections::without_redirections;
use super::{background_pipeline, literal_redirects_only, unquoted_literal};
use crate::pretool::PathContext;
use crate::CanonicalCommandV1;

/// Whether the only part of the command the parser could not read is a
/// redirect into a literal path, so the launch it carries is the one the same
/// text without that redirect runs.
///
/// `node server.js > /tmp/x.log 2>&1 &` runs what `node server.js &` runs and
/// sends its output to a file the text names. The redirect reason wins the
/// parser's scan, so the launch kept no segments, its script read as a file
/// nobody opened, and the dev server blocked outright with no approval left
/// to give it, while the same launch without the log file reached review. An
/// input redirect or a heredoc can feed the interpreter its program, and a
/// target the text does not spell could be anything, so both keep the
/// failure, as does a pipe a background job feeds.
///
/// A redirect that writes a file the rest of the text names is not a log:
/// `printf '...' > run.js && node run.js` writes the program it then runs, so
/// the launch runs text this scan never saw and keeps the failure.
pub(super) fn redirected_launch(command: &CanonicalCommandV1, context: PathContext<'_>) -> bool {
    let text = command.normalized_text.as_str();
    let bare = without_redirections(text);
    command.uncertainty_reason.as_deref() == Some("command_redirect_not_yet_supported")
        && command.wrapper_chain.is_empty()
        && !command.path_overridden
        && !unquoted_literal(text).contains('<')
        && literal_redirects_only(text)
        && !background_pipeline(&bare)
        && !writes_a_named_file(text, &bare)
        && crate::pretool::models_exactly(&bare, context)
}

/// Whether a redirect in `text` writes a file that `bare`, the same text
/// without its redirects, could name. Words compare by their last path
/// component with every quote and escape removed, so `./run.js`,
/// `/work/run.js`, `ru"n.js"` and `r\un.js` all name `run.js`. An
/// interpreter resolves a module without its exact file name, so the stem of
/// the target, any directory on its path and `.` or `..` name it too: `node
/// run` loads `run.js`, and `node ./lib` or `node .` load an `index.js`.
/// Plain output such as `/tmp/x.log` is matched by its exact name only. A
/// word that could expand to a name, through a glob, a brace or a parameter
/// outside single quotes, counts as naming it, as does a target the scan
/// cannot pick out.
fn writes_a_named_file(text: &str, bare: &str) -> bool {
    let Some(words) = split_unquoted(text, char::is_whitespace) else {
        return true;
    };
    let Some(spelled) = split_unquoted(bare, |character| {
        character.is_whitespace() || matches!(character, ';' | '&' | '|' | '(' | ')' | '=')
    }) else {
        return true;
    };
    let words: Vec<&str> = words.into_iter().filter(|word| !word.is_empty()).collect();
    let mut targets = Vec::new();
    for (index, rest) in words.iter().enumerate().flat_map(|(index, word)| {
        redirects_in(word)
            .into_iter()
            .map(move |rest| (index, rest))
    }) {
        let rest = rest.trim_start_matches('|');
        if rest.starts_with('&') {
            continue;
        }
        let target = match rest {
            "" => match words.get(index + 1) {
                Some(next) => *next,
                None => return true,
            },
            rest => rest,
        };
        // `>run.js&&node run.js` ends the target at the operator, and a
        // process substitution such as `> >(sh)` writes to a command.
        if target.starts_with(['>', '(']) {
            return true;
        }
        let target = target.split([';', '&', '|', ')']).next().unwrap_or(target);
        if target.is_empty() || target.contains('(') {
            return true;
        }
        if target != "/dev/null" {
            targets.push(target);
        }
    }
    if targets.is_empty() {
        return false;
    }
    let spelled: Vec<&str> = spelled
        .into_iter()
        .filter(|word| !word.is_empty())
        .collect();
    if targets
        .iter()
        .chain(&spelled)
        .any(|word| could_expand(word))
    {
        return true;
    }
    let names: Vec<String> = spelled.iter().map(|word| file_name(word)).collect();
    let dotted = names.iter().any(|name| matches!(name.as_str(), "." | ".."));
    targets.iter().any(|target| {
        let target = unquoted_word(target);
        let written = target.rsplit('/').next().unwrap_or(&target);
        if inert_output(written) {
            return names.iter().any(|name| name == written);
        }
        dotted
            || target
                .split('/')
                .filter(|part| !part.is_empty())
                .any(|part| {
                    names
                        .iter()
                        .filter(|name| !name.is_empty())
                        .any(|name| name == part || stem(name) == stem(part))
                })
    })
}

/// Whether the written file is plain output, such as a log, that no
/// interpreter resolves as a module when it is named without its extension.
fn inert_output(name: &str) -> bool {
    name.rsplit_once('.').is_some_and(|(stem, extension)| {
        !stem.is_empty()
            && matches!(
                extension,
                "log" | "txt" | "out" | "err" | "csv" | "tsv" | "md"
            )
    })
}

/// The word with its quotes and escapes removed.
fn unquoted_word(word: &str) -> String {
    word.chars()
        .filter(|character| !matches!(character, '\'' | '"' | '\\'))
        .collect()
}

/// A file name before its first `.`, or the whole name when that is empty.
fn stem(name: &str) -> &str {
    match name.split('.').next() {
        Some(stem) if !stem.is_empty() => stem,
        _ => name,
    }
}

/// The text after each redirect operator in one word, up to the next one: a
/// `>` that stands outside quotes and escapes, with `>>` read as one
/// operator. `'x'>run.js` writes `run.js`, while `'a>b'` and `a\>b` redirect
/// nothing, and `2>&1>log` yields `&1` and `log`.
fn redirects_in(word: &str) -> Vec<&str> {
    let mut operators = Vec::new();
    let (mut single, mut double, mut escaped) = (false, false, false);
    for (index, character) in word.char_indices() {
        if single {
            single = character != '\'';
        } else if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '\'' && !double {
            single = true;
        } else if character == '"' {
            double = !double;
        } else if character == '>' && !double {
            operators.push(index);
        }
    }
    operators
        .iter()
        .enumerate()
        .filter(|(position, at)| operators.get(position + 1) != Some(&(**at + 1)))
        .map(|(position, at)| {
            let end = operators.get(position + 1).copied().unwrap_or(word.len());
            &word[at + 1..end]
        })
        .collect()
}

/// The last non-empty path component of a word with its quotes and escapes
/// removed. `lib/` names `lib`, and a word with no component left, such as
/// `./` or `/`, names the directory itself as `.` does.
fn file_name(word: &str) -> String {
    let word = unquoted_word(word);
    let name = word.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    match name {
        "" => ".".to_owned(),
        name => name.to_owned(),
    }
}

/// Whether the shell could expand the word into a name it does not spell: a
/// glob or a brace outside quotes, or a parameter outside single quotes other
/// than `$!`, the last job's process ID.
fn could_expand(word: &str) -> bool {
    let chars: Vec<char> = word.chars().collect();
    let (mut single, mut double, mut escaped) = (false, false, false);
    for (index, &character) in chars.iter().enumerate() {
        if single {
            single = character != '\'';
        } else if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '\'' && !double {
            single = true;
        } else if character == '"' {
            double = !double;
        } else if (character == '$' && chars.get(index + 1) != Some(&'!'))
            || (!double && matches!(character, '*' | '?' | '[' | '{'))
        {
            return true;
        }
    }
    false
}

/// The inline program of every interpreter launch in a list or a loop, read
/// as each launch is read standing alone, or `None` when one of them is not
/// an inline program this scan reads.
///
/// `for f in a b; do [ -f "$f" ] && node -e '...' "$f"; done` runs the program
/// spelled between the quotes once per name. On its own, `node -e '...' "$f"`
/// is read and routed, but inside the loop the launch had no segments, so it
/// looked like an interpreter running a file nobody read and blocked outright.
/// A launch that names a script file, carries an environment of its own or
/// hands its program to a shell is still refused. So is any text that changes
/// directory or sources a file, since either moves where the program's
/// imports resolve from.
pub(super) fn listed_inline_sources(
    shell: &str,
    sources_files: bool,
    context: PathContext<'_>,
) -> Option<Vec<String>> {
    let commands: Vec<&str> = split_unquoted(shell, |character| {
        matches!(
            character,
            ';' | '&' | '|' | '(' | ')' | '{' | '}' | '\n' | '`'
        )
    })?
    .into_iter()
    .filter_map(past_reserved_words)
    .collect();
    if sources_files || commands.iter().any(|command| changes_directory(command)) {
        return None;
    }
    let mut sources = Vec::new();
    for launch in commands {
        if !prefix::interpreter_launch_reads_a_file(launch, false) {
            continue;
        }
        let request = serde_json::from_value(serde_json::json!({ "command": launch })).ok()?;
        let model = crate::parse_command(&request).ok()?;
        sources.extend(crate::pretool::sole_program_sources(&model, context)?);
    }
    (!sources.is_empty()).then_some(sources)
}

/// The text between the characters `split` picks out that stand outside
/// quotes, so an inline program such as `'console.log(a); b()'` stays whole.
/// `None` when a quote is left open.
fn split_unquoted(shell: &str, split: impl Fn(char) -> bool) -> Option<Vec<&str>> {
    let (mut pieces, mut start) = (Vec::new(), 0);
    let (mut single, mut double, mut escaped) = (false, false, false);
    for (index, character) in shell.char_indices() {
        if single {
            single = character != '\'';
        } else if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            double = !double;
        } else if !double && character == '\'' {
            single = true;
        } else if !double && split(character) {
            pieces.push(&shell[start..index]);
            start = index + character.len_utf8();
        }
    }
    pieces.push(&shell[start..]);
    (!single && !double && !escaped).then_some(pieces)
}

/// The command a list or loop piece runs, past the reserved words that only
/// say when it runs.
fn past_reserved_words(piece: &str) -> Option<&str> {
    let mut rest = piece.trim_start();
    loop {
        let (word, tail) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        if !matches!(
            word,
            "do" | "then" | "else" | "if" | "elif" | "while" | "until" | "!"
        ) {
            break;
        }
        rest = tail.trim_start();
    }
    let rest = rest.trim_end();
    (!rest.is_empty()).then_some(rest)
}

/// Whether the command, past the variables it sets and the shell prefixes
/// that run the word after them (`builtin cd`, `command cd`, `time cd`), is
/// one that moves the shell to another directory, a word that hands its
/// arguments back to the shell, or a word that could expand to either.
fn changes_directory(command: &str) -> bool {
    let Some(words) = split_unquoted(command, char::is_whitespace) else {
        return true;
    };
    let mut prefixed = false;
    words
        .into_iter()
        .filter(|word| !word.is_empty())
        .find(|word| {
            if sets_a_variable(word) {
                return false;
            }
            if matches!(*word, "builtin" | "command" | "time" | "nohup" | "exec") {
                prefixed = true;
                return false;
            }
            !(prefixed && word.starts_with('-'))
        })
        .is_some_and(|word| {
            matches!(
                word.trim_matches(['\'', '"']),
                "cd" | "pushd" | "popd" | "eval" | "source" | "."
            ) || word.contains(['$', '\\', '\'', '"'])
        })
}

fn sets_a_variable(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        name.chars()
            .next()
            .is_some_and(|first| !first.is_ascii_digit())
            && name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
    })
}

/// Whether every `$` in the text opens a parameter, inside double quotes,
/// that roots a path: `"$HOME/Downloads/x"` or `"${ROOT}/src"`.
///
/// `find "$HOME/Downloads/widgets" -type f -exec basename {} \;` searches a
/// directory under the home the shell already knows. The quotes keep the
/// value one word and the `/` after it keeps that word a path, so nothing the
/// value holds can become a find action, an operator or a program. Refusing
/// every `$` left that listing blocked outright, while the same search under
/// a relative root reached review.
pub(super) fn parameters_only_root_paths(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let (mut single, mut double, mut escaped) = (false, false, false);
    let mut index = 0;
    while let Some(&character) = chars.get(index) {
        index += 1;
        if single {
            single = character != '\'';
            continue;
        }
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '\'' if !double => single = true,
            '"' => double = !double,
            '$' => {
                let Some(after) = double
                    .then(|| rooted_parameter_end(&chars, index))
                    .flatten()
                else {
                    return false;
                };
                index = after;
            }
            _ => {}
        }
    }
    !single && !double
}

/// The index past `NAME` or `{NAME}` at `start`, when a `/` follows it.
fn rooted_parameter_end(chars: &[char], start: usize) -> Option<usize> {
    let braced = chars.get(start) == Some(&'{');
    let name = start + usize::from(braced);
    let length = chars[name.min(chars.len())..]
        .iter()
        .take_while(|character| character.is_ascii_alphanumeric() || **character == '_')
        .count();
    if length == 0 || chars[name].is_ascii_digit() {
        return None;
    }
    let mut end = name + length;
    if braced {
        (chars.get(end) == Some(&'}')).then_some(())?;
        end += 1;
    }
    (chars.get(end) == Some(&'/')).then_some(end)
}

/// `nodepath="$HOME/.nvm/..."`: a plain shell variable the text sets for its
/// own later words.
///
/// A lowercase name is not one the programs a command runs read from their
/// environment, and `ordinary_name` refuses the ones a shell ties to its own
/// state (zsh's `path`, `cdpath` and `fpath`) or that name a proxy, a package
/// manager setting or a credential. The value may expand a parameter only as
/// the quoted root of a path, so `x=$SECRET` still moves data, as does any
/// substitution. A command word built from the variable is refused wherever
/// it stands, so the text still names every program it runs.
pub(super) fn binds_a_shell_variable(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, value)| {
        name.chars().any(|character| character.is_ascii_lowercase())
            && crate::pretool::generic::chain_literals::ordinary_name(name)
            && (!value.contains('$') || parameters_only_root_paths(value))
    })
}

#[cfg(test)]
#[path = "native_command_unmodeled_compound_tests.rs"]
mod tests;
