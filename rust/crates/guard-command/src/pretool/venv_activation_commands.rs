//! What a generated activation script runs, beside the settings it writes.
//!
//! The settings scan reads assignments. A script can leave `PATH` and
//! `VIRTUAL_ENV` exactly as a generated one does and still decide which
//! program the shell runs next: a function named for the program the command
//! names, a `hash -p` entry pointing that name at another file, or a
//! `printf -v` writing a setting no assignment spells. The projection hands
//! its verdict to the word after the activation and rewrites that word to the
//! environment's own `bin`, so a script holding anything that could change
//! what the word reaches is not one this scan can read through.
//!
//! What is left is what the generated scripts are made of: tests, `export`,
//! `unset`, `hash -r`, a `command -v` lookup, `basename`, and a `deactivate`
//! the file defines and calls. A body nothing calls runs nothing, so the
//! `pydoc` wrapper every virtualenv ends with stays out of the scan the way
//! it stays out of the shell.

use std::collections::BTreeSet;

/// The longest activation script this scan reads. A generated one is a few
/// kilobytes.
const MAX_SCRIPT_CHARS: usize = 64 * 1024;

/// Words carrying no command of their own, which leave the word after them
/// in command position.
const GRAMMAR: &[&str] = &[
    "if", "then", "elif", "else", "fi", "while", "until", "do", "done", "!", "{", "}",
];

/// What a generated activation script runs. Each of these reads or reports;
/// none of them binds a name to a program. `alias` is among them because the
/// shell expands aliases while it parses a line, which it has finished doing
/// before `source` runs, so a name one binds cannot reach the word after the
/// `&&`. `cd`, `command` and `hash` are admitted under narrower rules below.
const SETTING_COMMANDS: &[&str] = &[
    "[", "[[", "test", ":", "true", "false", "echo", "export", "unset", "return", "exit", "shift",
    "alias", "unalias", "basename", "dirname", "pwd", "uname", "cygpath", "for", "case", "select",
];

/// Commands that look a name up rather than run it, so the name they are
/// handed is not a call to a function of that name.
const LOOKUPS: &[&str] = &["unset", "unalias", "alias", "type", "declare", "typeset"];

#[derive(Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    Separator,
    Open,
    Close,
}

#[derive(Debug)]
struct Command {
    word: String,
    arguments: Vec<String>,
    depth: usize,
}

/// Whether the script runs nothing beyond the settings it writes, and binds
/// no name the command runs next.
pub(super) fn runs_settings_only(text: &str, next: &[&str]) -> bool {
    if text.len() > MAX_SCRIPT_CHARS {
        return false;
    }
    let Some(tokens) = tokens(text) else {
        return false;
    };
    let Some(definitions) = definitions(&tokens) else {
        return false;
    };
    // A function of that name is what the shell finds when it looks any of
    // those words up, whatever the activated `PATH` holds. The word after a
    // later `&&` or `|` runs as a command too, so every one of them counts.
    if definitions
        .iter()
        .any(|(name, _, _)| next.contains(&name.as_str()))
    {
        return false;
    }
    let mut live: BTreeSet<String> = BTreeSet::new();
    let mut commands = Vec::new();
    // A body a live body calls is live too, so the set is grown until it
    // stops growing. It only ever grows, so this ends.
    for _ in 0..definitions.len() + 1 {
        let skipped: Vec<(usize, usize)> = definitions
            .iter()
            .filter(|(name, _, _)| !live.contains(name))
            .map(|(_, start, end)| (*start, *end))
            .collect();
        let Some(found) = simple_commands(&tokens, &skipped) else {
            return false;
        };
        let grown: BTreeSet<String> = definitions
            .iter()
            .filter(|(name, _, _)| called(&found, name))
            .map(|(name, _, _)| name.clone())
            .collect();
        commands = found;
        let before = live.len();
        live.extend(grown);
        if live.len() == before {
            break;
        }
    }
    let defined: BTreeSet<&str> = definitions
        .iter()
        .map(|(name, _, _)| name.as_str())
        .collect();
    commands.iter().all(|command| admits(command, &defined))
}

/// Whether anything outside the dead bodies could run `name`. A name handed
/// to a lookup is one of those builtins' arguments rather than a call, which
/// is how a generated script tidies up around its own wrapper.
fn called(commands: &[Command], name: &str) -> bool {
    commands.iter().any(|command| {
        if command.word == name {
            return true;
        }
        !LOOKUPS.contains(&command.word.as_str())
            && command
                .arguments
                .iter()
                .any(|argument| argument.contains(name))
    })
}

fn admits(command: &Command, defined: &BTreeSet<&str>) -> bool {
    let word = command.word.as_str();
    if defined.contains(word) {
        return true;
    }
    match word {
        // Inside a substitution `cd` reports a place; outside one it moves
        // the shell the command after the activation runs in.
        "cd" => command.depth > 0,
        // `hash -r` forgets what the shell looked up. `hash -p file name`
        // writes a lookup, which points a name at a file of the script's
        // choosing.
        "hash" => command.arguments.iter().all(|argument| argument == "-r"),
        // A lookup reports where a program is. Any other use runs one.
        "command" => matches!(
            command.arguments.first().map(String::as_str),
            Some("-v" | "-V")
        ),
        _ => SETTING_COMMANDS.contains(&word),
    }
}

/// The script's words, separators and substitution parens.
///
/// `None` where the text is not plain enough to take apart: an unclosed
/// quote, or a backtick substitution, whose contents this scan does not read.
fn tokens(text: &str) -> Option<Vec<Token>> {
    let mut scan = Scan::default();
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\'' | '"' => {
                scan.word.push(character);
                loop {
                    let inner = characters.next()?;
                    scan.word.push(inner);
                    if inner == character {
                        break;
                    }
                    if character == '"' && inner == '\\' {
                        scan.word.push(characters.next()?);
                    }
                }
            }
            '`' => return None,
            '\\' => match characters.next() {
                Some('\n') | None => {}
                Some(escaped) => scan.word.push(escaped),
            },
            '#' if scan.word.is_empty() => {
                for inner in characters.by_ref() {
                    if inner == '\n' {
                        break;
                    }
                }
                scan.separate();
            }
            ' ' | '\t' => scan.flush(),
            '\n' | ';' => scan.separate(),
            '|' => {
                characters.next_if_eq(&'|');
                scan.separate();
            }
            '&' => match characters.peek().copied() {
                Some('&') => {
                    characters.next();
                    scan.separate();
                }
                // `&>` is a redirection, and `2>&1` names a descriptor the
                // redirection already carries.
                Some('>') => {
                    characters.next();
                    scan.redirect();
                }
                _ if scan.redirecting => scan.word.push('&'),
                _ => scan.separate(),
            },
            '>' | '<' => {
                // A leading descriptor belongs to the redirection rather than
                // to a word of its own.
                if scan.word.chars().all(|digit| digit.is_ascii_digit()) {
                    scan.word.clear();
                }
                characters.next_if_eq(&character);
                scan.redirect();
            }
            '(' => {
                if scan.word.ends_with('$') {
                    scan.word.pop();
                }
                // `: >(helper)` and `: >$(helper)` run `helper` as a
                // redirection's target, where no word of it reaches `out`.
                if scan.redirecting {
                    return None;
                }
                scan.flush();
                scan.out.push(Token::Open);
            }
            ')' => {
                scan.flush();
                scan.out.push(Token::Close);
            }
            _ => scan.word.push(character),
        }
    }
    scan.separate();
    if scan.unreadable {
        return None;
    }
    Some(scan.out)
}

/// Whether a redirection's target names a descriptor the shell already holds.
fn descriptor(word: &str) -> bool {
    word.strip_prefix('&').is_some_and(|digits| {
        !digits.is_empty() && digits.chars().all(|digit| digit.is_ascii_digit())
    })
}

#[derive(Default)]
struct Scan {
    out: Vec<Token>,
    word: String,
    redirecting: bool,
    unreadable: bool,
}

impl Scan {
    /// Ends the word being read. A redirection's target is the file it writes
    /// rather than a word the shell runs.
    fn flush(&mut self) {
        if self.word.is_empty() {
            return;
        }
        let word = std::mem::take(&mut self.word);
        if self.redirecting {
            self.redirecting = false;
            // A generated script redirects to `/dev/null` or to a descriptor
            // it already holds. Reading past any other target would mean
            // reading the name of a file the script writes, and a write to
            // this environment's own `bin` changes the program the word the
            // projection rewrites then runs.
            if word != "/dev/null" && !descriptor(&word) {
                self.unreadable = true;
            }
            return;
        }
        self.out.push(Token::Word(word));
    }

    fn redirect(&mut self) {
        self.flush();
        self.redirecting = true;
    }

    fn separate(&mut self) {
        self.flush();
        self.redirecting = false;
        if !matches!(self.out.last(), None | Some(Token::Separator)) {
            self.out.push(Token::Separator);
        }
    }
}

/// Each function the script defines, as its name and the span of tokens the
/// definition covers.
///
/// `None` where a definition's body has no end this scan can place, or where
/// the name is not one it can read.
fn definitions(tokens: &[Token]) -> Option<Vec<(String, usize, usize)>> {
    let mut found = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        let Some((name, brace)) = opens(tokens, index)? else {
            index += 1;
            continue;
        };
        let end = body_end(tokens, brace)?;
        found.push((name, index, end));
        index = end + 1;
    }
    Some(found)
}

/// The name and body brace of a definition starting at `index`, for the two
/// shapes a script is written in: `name () {` and `function name {`.
fn opens(tokens: &[Token], index: usize) -> Option<Option<(String, usize)>> {
    let word = |at: usize| match tokens.get(at) {
        Some(Token::Word(word)) => Some(word.as_str()),
        _ => None,
    };
    let parens = matches!(tokens.get(index + 1), Some(Token::Open))
        && matches!(tokens.get(index + 2), Some(Token::Close));
    let opened = match word(index) {
        Some("function") => {
            let name = word(index + 1)?;
            match (word(index + 2), word(index + 3)) {
                (Some("{"), _) => Some((name, index + 2)),
                _ if matches!(tokens.get(index + 2), Some(Token::Open))
                    && matches!(tokens.get(index + 3), Some(Token::Close)) =>
                {
                    match word(index + 4) {
                        Some("{") => Some((name, index + 4)),
                        _ => return None,
                    }
                }
                _ => return None,
            }
        }
        Some(name) if parens => match word(index + 3) {
            Some("{") => Some((name, index + 3)),
            // A `(` the scan cannot read as a body is one it cannot place.
            _ => return None,
        },
        _ => None,
    };
    let Some((name, brace)) = opened else {
        return Some(None);
    };
    if name.is_empty()
        || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return None;
    }
    Some(Some((name.to_owned(), brace)))
}

/// The token closing the body opened at `brace`.
fn body_end(tokens: &[Token], brace: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut position = true;
    for (index, token) in tokens.iter().enumerate().skip(brace) {
        let word = match token {
            Token::Word(word) => word,
            // A separator and a substitution's opening both start a command;
            // its closing leaves one, where a brace is a word again.
            Token::Separator | Token::Open => {
                position = true;
                continue;
            }
            Token::Close => {
                position = false;
                continue;
            }
        };
        // The shell reads a brace as a brace only in command position. A body
        // holding `echo {` would otherwise swallow the lines after it, and a
        // program among them would never be read.
        let brace_word = word == "{" || word == "}";
        if brace_word && !position {
            return None;
        }
        if word == "{" {
            depth += 1;
        } else if word == "}" {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
        position = brace_word || GRAMMAR.contains(&word.as_str()) || assigns(word);
    }
    None
}

/// The commands the script runs, with the spans in `skipped` left out.
fn simple_commands(tokens: &[Token], skipped: &[(usize, usize)]) -> Option<Vec<Command>> {
    let mut out: Vec<Command> = Vec::new();
    let mut depth = 0usize;
    let mut position = true;
    let mut index = 0;
    while index < tokens.len() {
        if let Some((_, end)) = skipped.iter().find(|(start, _)| *start == index) {
            index = end + 1;
            position = true;
            continue;
        }
        match &tokens[index] {
            Token::Separator => position = true,
            Token::Open => {
                depth += 1;
                position = true;
            }
            Token::Close => {
                depth = depth.checked_sub(1)?;
                position = true;
            }
            Token::Word(word) => {
                if !position {
                    if let Some(command) = out.last_mut() {
                        command.arguments.push(word.clone());
                    }
                } else if !assigns(word) && !GRAMMAR.contains(&word.as_str()) {
                    out.push(Command {
                        word: word.clone(),
                        arguments: Vec::new(),
                        depth,
                    });
                    position = false;
                }
            }
        }
        index += 1;
    }
    Some(out)
}

/// Whether the word is an assignment, which leaves the word after it in
/// command position. The settings scan reads what these write.
fn assigns(word: &str) -> bool {
    let Some(name) = word.split('=').next().filter(|name| *name != word) else {
        return false;
    };
    let name = name.strip_suffix('+').unwrap_or(name);
    !name.is_empty()
        && !name.starts_with(|character: char| character.is_ascii_digit())
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
}

#[cfg(test)]
#[path = "venv_activation_commands_tests.rs"]
mod tests;
