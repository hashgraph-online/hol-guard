//! Agents often name a file once and reuse it through the rest of a chain:
//! `export OUT=build/report.json && rm -f $OUT && ./run.py > $OUT`. Every
//! `$OUT` hid the real operand, so the whole chain fell to review. When a
//! variable gets a plain literal from an assignment that always runs before
//! the use, the use expands to exactly that literal. Writing the literal in
//! place lets each step be judged on its real operands. The assignments stay
//! in the text, so their own treatment is unchanged, and anything this
//! recognizer does not fully understand returns `None`.

use crate::pretool::PathContext;
use guard_contracts::PreToolResultV1;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[path = "chain_literals_lex.rs"]
mod lex;
use lex::{identifier, items, names_variable, opaque, tokenize, Token};
#[path = "chain_literals_inert.rs"]
pub(crate) mod inert;
#[path = "chain_literals_launch.rs"]
mod launch;
use launch::{launches_as_judged, reviewed};
#[path = "chain_literals_home.rs"]
mod home;
#[path = "chain_literals_pwd.rs"]
mod pwd;

const MAX_COMMAND_CHARS: usize = 8192;
const MAX_VALUE_CHARS: usize = 256;
const MAX_BINDINGS: usize = 32;

// Word lists below are whitespace-separated and matched whole.

/// Builtins and zsh commands that can set a variable or run text as shell
/// code, as `zstyle -e` and zregexparse's actions do. A chain that calls one
/// has bindings this recognizer cannot track.
const STATE_COMMANDS: &str = ". alias autoload builtin declare emulate enable eval exec export \
    float function getopts integer let local mapfile private read readarray readonly select set \
    setopt shopt source trap typeset unalias unset unsetopt vared wait zmodload zparseopts \
    zregexparse zstyle";

/// Reserved words. A literal in their place would be parsed as syntax,
/// while the expansion it replaces is an ordinary word.
const KEYWORDS: &str = "! [[ ]] case coproc do done elif else esac fi for foreach function if \
    in repeat select then time until while";

/// Precommand modifiers whose operand is the command that actually runs.
const PRECOMMANDS: &str = "- command nocorrect noglob";

/// Names that steer the shell, program lookup, loading, configuration or
/// credentials, or whose value the shell itself rewrites, compared in upper
/// case so zsh's tied lowercase arrays (`path`, `fpath`, ...) match too.
/// They are never substituted.
const SPECIAL_NAMES: &str = "ALIASES ARGC ARGV AUTO_RESUME BAUD BROWSER BUFFER BUILTINS CDPATH \
    COLUMNS COMMANDS COPROC CPUTYPE CURSOR DIRSTACK EDITOR EGID ENV ERRNO EUID FIGNORE FPATH \
    FUNCTIONS GALIASES GID GLOBIGNORE GROUPS HOME HOST HOSTNAME HOSTTYPE IFS INPUTRC JOBDIRS \
    JOBSTATES JOBTEXTS KEYMAP KEYTIMEOUT LANG LBUFFER LESSCLOSE LESSOPEN LINENO LINES LISTMAX \
    LOGNAME MACHTYPE MAIL MAILCHECK MAILPATH MANPATH MAPFILE MATCH MBEGIN MEND MODULE_PATH \
    MODULES NAMEDDIRS NULLCMD NUMERIC OLDPWD OPTARG OPTERR OPTIND OPTIONS OSTYPE PAGER \
    PARAMETERS PATCHARS PATH PERIOD PIPESTATUS POSIXLY_CORRECT PPID PWD RANDOM RBUFFER \
    READNULLCMD REPLY RESWORDS SAVEHIST SECONDS SHELL SHELLOPTS SHLVL SIGNALS SRANDOM STATUS \
    SYSPARAMS TIMEFMT TIMEFORMAT TMOUT TMPDIR TMPPREFIX TTY TTYIDLE UID USER USERDIRS USERGROUPS \
    USERNAME VENDOR VISUAL WATCH WIDGET WORDCHARS ZDOTDIR";

const SPECIAL_PREFIXES: &str = "ANTHROPIC_ AWS_ AZURE_ BASH CARGO CLAUDE CLOUDSDK_ CODEX_ COMP \
    DIS_ DOCKER_ DYLD_ EPOCH FUNC GCLOUD_ GH_ GIT GO GOOGLE_ GUARD_ HIST HOL_ JAVA_ KUBE LC_ LD_ \
    NODE_ NPM_ OPENAI_ PERL PIP_ PROMPT PS PYTHON REPORT RPROMPT RPS RUBY RUST SPROMPT SSH_ SUDO_ \
    TERM XDG_ ZLE ZSH";

const CREDENTIAL_MARKERS: &str = "API_KEY AUTH CREDENTIAL PASSWD PASSWORD PRIVATE_KEY PROXY \
    SECRET TOKEN";

fn listed(list: &str, word: &str) -> bool {
    list.split_ascii_whitespace().any(|entry| entry == word)
}

struct Binding {
    value: String,
    /// Set by the first command of its `&&` list, so it also holds after a
    /// later `;`; an assignment behind `&&` holds only within its own list.
    unconditional: bool,
}

/// The extension controls cannot see through an expansion they do not model.
const EVALUATION_FAILED: &str = "native_command_extension_evaluation_failed";
/// A command the workspace sandbox runs because no rule proves it.
const CONTAINED: &str = "native_workspace_containment_required";

/// Replace a raw review with the verdict for the substituted command, which
/// runs the same words, or the same words with each value-producing command
/// substitution written as a stand-in no broader than its value. Another
/// sandbox verdict is kept only when its launcher, which re-derives the shape
/// from the raw text, would run it. A
/// raw block that only says the expansions could not be evaluated also takes
/// the substituted command's review, which every control did evaluate.
pub(super) fn rejudge(
    raw: PreToolResultV1,
    payload: &Value,
    context: PathContext<'_>,
    evaluate: impl Fn(&Value) -> PreToolResultV1,
) -> PreToolResultV1 {
    let unevaluated = raw.reason_code == EVALUATION_FAILED;
    if raw.minimum_action != "review" && !unevaluated {
        return raw;
    }
    let Some(command) = super::extract_generic_signals(payload)
        .ok()
        .and_then(|signals| signals.command)
    else {
        return raw;
    };
    // A value producer counts only when it would be allowed as a command of
    // its own, so lockdown, managed policy and extension controls on it hold.
    let allowed = |body: &str| {
        evaluate(&super::payload_with_command(payload, &command, body)).minimum_action == "allow"
    };
    let opened = inert::project(&command, allowed);
    // A fresh `mktemp -d` directory expanded later in its `&&` chain is
    // judged as `$TMPDIR`, which holds it; only a sandbox launch counts, and
    // only once `opened` found each substitution allowed on its own.
    if let Some(expanded) = opened
        .is_some()
        .then(|| inert::temp_cd::expanded(&command))
        .flatten()
    {
        let projected = evaluate(&super::payload_with_command(payload, &command, &expanded));
        if projected.minimum_action == "sandbox-required"
            && launches_as_judged(&projected, &command, context)
        {
            return projected;
        }
    }
    // `dirname` reads no file but no read rule names it, so on its own it
    // runs in the workspace sandbox. The contained run prints the same path,
    // so that verdict lets it name the parent too.
    let produces = |body: &str| {
        let verdict = evaluate(&super::payload_with_command(payload, &command, body));
        verdict.minimum_action == "allow"
            || (body.starts_with("dirname ")
                && verdict.minimum_action == "sandbox-required"
                && verdict.reason_code == CONTAINED)
    };
    let unopened = opened.as_deref().unwrap_or(&command);
    let directory = context
        .cwd
        .and_then(|cwd| pwd::project(unopened, cwd, produces));
    let base = directory.as_deref().unwrap_or(unopened);
    // `$HOME` names the declared home only while the shell's HOME does.
    let homed = context
        .home_dir
        .filter(|_| context.shell_home_matches)
        .and_then(|home| home::project(base, home));
    let base = homed.as_deref().unwrap_or(base);
    let Some(substituted) = substitute(base).or(homed).or(directory).or(opened) else {
        return raw;
    };
    let projected_payload = super::payload_with_command(payload, &command, &substituted);
    if projected_payload == *payload {
        return raw;
    }
    let projected = evaluate(&projected_payload);
    match projected.minimum_action.as_str() {
        "allow" | "warn" | "block" => projected,
        "sandbox-required" if launches_as_judged(&projected, &command, context) => projected,
        // A command the raw text could not evaluate keeps the review its
        // literal form earns, Git's reapproval floor included.
        "review" | "require-reapproval"
            if unevaluated && projected.reason_code != EVALUATION_FAILED =>
        {
            projected
        }
        // The sandbox would launch the raw text, which was never judged.
        "sandbox-required" if unevaluated => reviewed(projected),
        _ => raw,
    }
}

/// The command with each `$NAME` / `${NAME}` bound to a literal by an
/// earlier, unconditionally run assignment written as that literal; `None`
/// when nothing is substituted or the command has any shape outside a plain
/// `&&` / `;` list of simple commands and pipelines.
pub(crate) fn substitute(command: &str) -> Option<String> {
    // zsh reads a non-ASCII letter after `$NAME` as part of the name.
    if !command.is_ascii()
        || command.len() > MAX_COMMAND_CHARS
        || command.bytes().any(|b| b.is_ascii_control() && b != b'\t')
        // A changed `IFS` splits an unquoted use the literal would not.
        || names_variable(command, |name| name == "IFS")
    {
        return None;
    }
    let chars: Vec<char> = command.chars().collect();
    let tokens = tokenize(&chars)?;
    let list = items(&tokens)?;
    let assigned: HashSet<String> = list
        .iter()
        .flat_map(|(stages, _)| stages.iter().flatten())
        .filter_map(|&(start, end)| assignment(&chars[start..end]).map(|(name, _)| name))
        .collect();
    let mut bindings: HashMap<String, Binding> = HashMap::new();
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let mut first_in_list = true;
    for (stages, separator) in list {
        if stages
            .iter()
            .flatten()
            .any(|&(start, end)| modifies_in_place(&chars[start..end]))
        {
            return None;
        }
        let piped = stages.len() > 1;
        let words = &stages[0];
        let leading = words
            .iter()
            .take_while(|&&(start, end)| assignment(&chars[start..end]).is_some())
            .count();
        if !piped && leading == words.len() {
            // `A=1 B=2` sets shell variables in order.
            for &(start, end) in words {
                let (name, value) = assignment(&chars[start..end])?;
                bind(&mut bindings, name, value, first_in_list)?;
            }
        } else if !piped
            && leading == 0
            && word_text(&chars, words[0], &bindings).as_deref() == Some("export")
        {
            for &(start, end) in &words[1..] {
                let word = &chars[start..end];
                match assignment(word) {
                    Some((name, value)) => bind(&mut bindings, name, value, first_in_list)?,
                    None if identifier(&word.iter().collect::<String>()) => {}
                    None => return None,
                }
            }
        } else {
            let mut sealed = false;
            for stage in &stages {
                let leading = stage
                    .iter()
                    .take_while(|&&(start, end)| assignment(&chars[start..end]).is_some())
                    .count();
                if let Some(&word) = stage.get(leading) {
                    rebinding_free(&chars, word, &stage[leading + 1..], &bindings)?;
                }
                // Words expand before the prefix settings apply, so they see
                // the bindings that came before this command.
                for &(start, end) in &stage[leading..] {
                    let text = substitute_word(&chars[start..end], &bindings);
                    let word = text
                        .clone()
                        .unwrap_or_else(|| chars[start..end].iter().collect());
                    // Any builtin may take a variable to set by name; zsh's
                    // `zformat -f`, `zstyle -s` and module builtins do. A
                    // substituted word can spell `IFS` the raw text did not.
                    if names_variable(&word, |name| name == "IFS" || assigned.contains(name)) {
                        return None;
                    }
                    sealed |= opaque(&word);
                    if let Some(text) = text {
                        edits.push((start, end, text));
                    }
                }
            }
            if sealed {
                // Text this pass cannot see could name a variable to set, so
                // no later use is substituted.
                bindings.clear();
                break;
            }
            // A prefix setting may outlive its command (POSIX special
            // builtins, zsh's last pipeline stage); stop trusting the name.
            for stage in &stages {
                for &(start, end) in stage {
                    if let Some((name, _)) = assignment(&chars[start..end]) {
                        bindings.remove(&name);
                    }
                }
            }
        }
        if bindings.len() > MAX_BINDINGS {
            return None;
        }
        first_in_list = separator != Token::And;
        if separator == Token::Sequence {
            bindings.retain(|_, binding| binding.unconditional);
        }
    }
    if edits.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(command.len());
    let mut cursor = 0usize;
    for (start, end, text) in edits {
        out.extend(&chars[cursor..start]);
        out.push_str(&text);
        cursor = end;
    }
    out.extend(&chars[cursor..]);
    Some(out)
}

fn bind(
    bindings: &mut HashMap<String, Binding>,
    name: String,
    value: Option<String>,
    unconditional: bool,
) -> Option<()> {
    match value.filter(|_| ordinary_name(&name)) {
        Some(value) => {
            bindings.insert(
                name,
                Binding {
                    value,
                    unconditional,
                },
            );
        }
        None => {
            bindings.remove(&name);
        }
    }
    Some(())
}

/// `NAME+=...` or `NAME[...]=...`, which change a variable in place.
fn modifies_in_place(word: &[char]) -> bool {
    let Some(equals) = word.iter().position(|&c| c == '=') else {
        return false;
    };
    let target: String = word[..equals].iter().collect();
    let target = target.strip_suffix('+').unwrap_or(&target);
    let name = target.split_once('[').map_or(target, |(name, _)| name);
    name.len() < equals && identifier(name)
}

/// `NAME=VALUE` with an unquoted name: the name, and the value when it is a
/// plain literal (bare, or wholly single- or double-quoted). Appends,
/// subscripts and other near-assignments refuse the command.
fn assignment(word: &[char]) -> Option<(String, Option<String>)> {
    let equals = word.iter().position(|&c| c == '=')?;
    let name: String = word[..equals].iter().collect();
    if !identifier(&name) {
        return None;
    }
    let raw = &word[equals + 1..];
    let inner = match (raw.first(), raw.last()) {
        (Some(&open @ ('\'' | '"')), Some(&close)) if raw.len() >= 2 && open == close => {
            &raw[1..raw.len() - 1]
        }
        _ => raw,
    };
    let value: String = inner.iter().collect();
    let literal = !value.is_empty()
        && value.chars().count() <= MAX_VALUE_CHARS
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '_' | '.' | '/' | '@' | '%' | '+' | ':' | ',' | '-')
        })
        && !listed(KEYWORDS, &value);
    Some((name, literal.then_some(value)))
}

pub(crate) fn ordinary_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    name != "_"
        && name.len() <= 64
        && !listed(SPECIAL_NAMES, &upper)
        && !SPECIAL_PREFIXES
            .split_ascii_whitespace()
            .any(|prefix| upper.starts_with(prefix))
        && !CREDENTIAL_MARKERS
            .split_ascii_whitespace()
            .any(|marker| upper.contains(marker))
}

/// `Some` when the stage's command can neither set a variable nor run text
/// as shell code. A command word with a redirect, or with an expansion other
/// than a bound variable, could name such a builtin, so it refuses too.
fn rebinding_free(
    chars: &[char],
    word: (usize, usize),
    arguments: &[(usize, usize)],
    bindings: &HashMap<String, Binding>,
) -> Option<()> {
    if chars[word.0..word.1]
        .iter()
        .any(|&c| matches!(c, '<' | '>'))
    {
        return None;
    }
    let name = word_text(chars, word, bindings)?;
    let stateful = |name: &str| listed(STATE_COMMANDS, name) || listed(KEYWORDS, name);
    if stateful(&name) {
        return None;
    }
    let arguments = || {
        arguments
            .iter()
            .map(|&word| word_text(chars, word, bindings))
    };
    if listed(PRECOMMANDS, &name) {
        for argument in arguments() {
            if stateful(&argument?) {
                return None;
            }
        }
    }
    if matches!(name.as_str(), "print" | "printf") {
        for argument in arguments() {
            let argument = argument?;
            if argument.starts_with('-') && argument.contains('v') {
                return None;
            }
        }
    }
    Some(())
}

/// The word after substitution with quotes and escapes removed; `None` while
/// an unresolved expansion remains.
fn word_text(
    chars: &[char],
    (start, end): (usize, usize),
    bindings: &HashMap<String, Binding>,
) -> Option<String> {
    let text = match substitute_word(&chars[start..end], bindings) {
        Some(text) => text,
        None => chars[start..end].iter().collect(),
    };
    (!text.contains('$')).then(|| {
        text.chars()
            .filter(|&c| !matches!(c, '\'' | '"' | '\\'))
            .collect()
    })
}

/// The word with its bound `$NAME` / `${NAME}` uses replaced, outside single
/// quotes and escapes; `None` when nothing is replaced. An unbraced name
/// followed by `[` or `:` is a zsh subscript or modifier and stays as is. A
/// word with `~` or a leading `=` is left alone: bash expands those before the
/// variable, so the literal would expand where the variable did not.
fn substitute_word(word: &[char], bindings: &HashMap<String, Binding>) -> Option<String> {
    if word.contains(&'~') || word.first() == Some(&'=') {
        return None;
    }
    let mut out = String::with_capacity(word.len());
    let mut replaced = false;
    let mut single = false;
    let mut double = false;
    let mut index = 0usize;
    while index < word.len() {
        let c = word[index];
        if single {
            single = c != '\'';
            out.push(c);
            index += 1;
            continue;
        }
        match c {
            '\'' if !double => single = true,
            '"' => double = !double,
            '\\' => {
                out.extend(word.get(index..index + 2).unwrap_or(&word[index..]));
                index += 2;
                continue;
            }
            '$' => {
                let braced = word.get(index + 1) == Some(&'{');
                let from = index + 1 + usize::from(braced);
                let length = word[from..]
                    .iter()
                    .take_while(|&&c| c == '_' || c.is_ascii_alphanumeric())
                    .count();
                // `$$`, `$!` and the other special parameters expand on their
                // own; the next character must never start a new expansion.
                let special = word.get(index + 1).copied().filter(|next| {
                    length == 0
                        && !braced
                        && matches!(next, '$' | '!' | '?' | '#' | '-' | '@' | '*')
                });
                if let Some(next) = special {
                    out.push('$');
                    out.push(next);
                    index += 2;
                    continue;
                }
                let name: String = word[from..from + length].iter().collect();
                let after = word.get(from + length).copied();
                let usable = if braced {
                    after == Some('}')
                } else {
                    !matches!(after, Some('[' | ':'))
                };
                if let Some(binding) = bindings.get(&name).filter(|_| usable) {
                    out.push_str(&binding.value);
                    index = from + length + usize::from(braced);
                    replaced = true;
                    continue;
                }
            }
            _ => {}
        }
        out.push(c);
        index += 1;
    }
    replaced.then_some(out)
}

#[cfg(test)]
#[path = "chain_literals_tests.rs"]
mod tests;
