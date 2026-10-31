//! A conditional runs a subset of the command lists written inside it: the
//! branch whose test succeeds. Writing those lists out as one plain list
//! therefore runs at least as much as the construct ever can, so admitting
//! the flat list admits the construct, and the conditional grants no
//! authority of its own.
//!
//! A `case` statement is the same shape: one arm's list runs, so the lists
//! every arm holds stand for whichever arm the word selects. The word and the
//! patterns choose between those lists rather than running anything, so they
//! are not carried into the flat list, and each is taken only when it plainly
//! starts no command of its own.
//!
//! A loop is only the same shape when one flattened pass stands for every
//! iteration it could run. `while read NAME; do ...; done < FILE` is that
//! shape, for a plain relative `FILE`: the read ends at that file's end, and
//! a body that writes nothing leaves each iteration doing the work the single
//! pass already describes. A device or a path outside the workspace need
//! never end, so neither is taken.
//!
//! A wait is the other shape. `until pg_isready -h 127.0.0.1; do sleep 1;
//! done` asks one question over and over and waits between the asks, which is
//! how a developer holds a test suite until its fixture server answers. The
//! loop never ends on its own, but it reaches nothing a single pass does not:
//! the body only sleeps, so it reads no input and opens no output, and the
//! one command the test runs is the same command each time. Sleeping twice is
//! sleeping longer, so a flat `TEST; sleep N` holds everything the loop can
//! do however long it runs, and that command still faces the ordinary proofs.
//! The test is taken as one command with no redirection of its own, because a
//! list or a redirection would make the iterations differ from the pass; the
//! body is taken only as plain `sleep` calls with a literal duration, since
//! anything else could build up across them. Every other loop keeps its
//! review.
//!
//! The loop's redirection is the file its `read` consumes, so the flat list
//! opens with a read of that file and then the body's own commands. Carrying
//! the redirection onto each item instead would model the same access as a
//! shape no proof covers, which is a review for work that only reads.
//!
//! A conditional binds no name, so an expansion inside one reads the same
//! value in the flat list that it read in the construct, and it is written
//! back as it stood. A loop that binds a name carries no expansion at all.
//!
//! Each list item still faces the ordinary proofs, and anything this
//! recognizer does not fully understand returns `None`, which keeps the
//! existing review behavior.

use super::for_loop_unroll::body::{body_items, redirect_tail, substitute};
use super::for_loop_unroll::{ordinary_loop_name, valid_identifier};

/// Enough room for a conditional with a handful of `elif` arms.
const MAX_ITEMS: usize = 48;
pub(super) const MAX_FLATTENED_BYTES: usize = 8192;

/// The flattened command list for a top-level `if` construct or a bounded
/// `while read` loop, or `None` when the command is anything else.
pub(super) fn flatten(command: &str) -> Option<String> {
    if command
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return None;
    }
    let text = command.trim();
    if let Some(rest) = keyword(text, "if") {
        return flatten_conditional(rest);
    }
    if let Some(rest) = keyword(text, "while") {
        return flatten_loop(rest);
    }
    if let Some(rest) = keyword(text, "until") {
        return flatten_wait(rest);
    }
    if let Some(rest) = keyword(text, "case") {
        return flatten_case(rest);
    }
    None
}

/// `if LIST; then LIST; [elif LIST; then LIST;]... [else LIST;] fi`.
fn flatten_conditional(rest: &str) -> Option<String> {
    let (parts, after) = conditional_parts(rest)?;
    assemble(&parts, after)
}

/// Renders as `; ` and marks the last item of an `if` or `elif` test.
/// `then` reads that item's outcome, so a negated state change keeps its `!`.
pub(super) const TEST_OUTCOME: &str = ";\u{1} ";

/// Commands whose success changes what a later command in the same shell sees.
pub(super) const STATE_CHANGING: &[&str] = &[
    "cd",
    "pushd",
    "popd",
    "export",
    "unset",
    "set",
    "shopt",
    "setopt",
    "unsetopt",
    "source",
    ".",
    "alias",
    "unalias",
    "umask",
    "eval",
    "exec",
    "read",
    "mapfile",
    "readarray",
    "declare",
    "typeset",
    "local",
    "readonly",
    "trap",
    "hash",
    "builtin",
    "command",
    "enable",
    "ulimit",
    "getopts",
    "let",
    "shift",
    "chdir",
    "integer",
    "float",
    "private",
    "autoload",
    "unfunction",
    "unhash",
    "emulate",
    "zmodload",
    "vared",
    "disable",
    "noglob",
    "nocorrect",
    "-",
];

/// The command word of one pipeline stage, reading through one leading `!`.
pub(super) fn command_head(stage: &str) -> &str {
    let mut words = stage.split_whitespace();
    match words.next().unwrap_or_default() {
        "!" => words.next().unwrap_or_default(),
        word => word,
    }
}

pub(super) fn rendered_separator(separator: &str) -> &str {
    if separator == TEST_OUTCOME {
        "; "
    } else {
        separator
    }
}

/// The items of every list a conditional holds, in order, and the text after
/// its `fi`. `rest` starts after the `if` keyword.
pub(super) fn conditional_parts(rest: &str) -> Option<(Vec<(String, &'static str)>, &str)> {
    let mut parts: Vec<(String, &'static str)> = Vec::new();
    let mut rest = rest;
    loop {
        let (test, _, after_test) = body_items(rest, "", &["then"])?;
        let from = parts.len();
        collect(&mut parts, test)?;
        // `then` reads the last test item. Tag a plain `;` join so a negated
        // `cd` (or another state change) keeps the `!`: the branch runs when
        // that change failed, from the directory the shell was already in.
        if parts.len() > from {
            if let Some(last) = parts.last_mut() {
                if last.1 == "; " {
                    last.1 = TEST_OUTCOME;
                }
            }
        }
        let (branch, closer, after_branch) = body_items(after_test, "", &["elif", "else", "fi"])?;
        collect(&mut parts, branch)?;
        match closer {
            "elif" => rest = after_branch,
            "else" => {
                let (alternative, _, after_alternative) = body_items(after_branch, "", &["fi"])?;
                collect(&mut parts, alternative)?;
                return Some((parts, after_alternative));
            }
            _ => return Some((parts, after_branch)),
        }
    }
}

/// `case WORD in [(]PATTERN[|PATTERN]...) LIST ;; ... esac`.
///
/// One arm's list runs, so writing every arm's list out as one plain list
/// runs at least as much as the construct ever can, which is the same reason
/// a conditional's branches flatten.
///
/// The word and the patterns are not command lists and do not reach the flat
/// list. Dropping text that could start a program would hide work, so each is
/// taken only when it plainly starts none: no substitution in the word, and a
/// pattern written as bare glob text, which also leaves the `)` that closes it
/// the first one in the arm.
fn flatten_case(rest: &str) -> Option<String> {
    let (word, mut rest) = subject(rest)?;
    if starts_a_command(word) {
        return None;
    }
    let mut parts: Vec<(String, &'static str)> = Vec::new();
    loop {
        rest = rest.trim_start_matches([' ', '\t', '\n']);
        if let Some(after) = closing(rest) {
            return assemble(&parts, after);
        }
        let (pattern, body) = rest.split_once(')')?;
        if !plain_pattern(pattern) {
            return None;
        }
        let (list, after) = arm_list(body)?;
        collect(&mut parts, list)?;
        rest = after;
    }
}

/// The word a `case` chooses on, and the text after the `in` that closes it.
fn subject(rest: &str) -> Option<(&str, &str)> {
    let (word, after) = rest.split_once([' ', '\t', '\n'])?;
    let after = keyword(after.trim_start_matches([' ', '\t', '\n']), "in")?;
    (!word.is_empty()).then_some((word, after))
}

/// Whether dropping this text would drop a command with it. A parameter the
/// shell only expands carries none, and is kept out of the flat list the way
/// a conditional keeps the expansions it held.
///
/// A process substitution runs its own command list before the `case` chooses
/// anything, so `<(` and `>(` carry one as plainly as a backtick does.
///
/// Arithmetic carries one too. The shell evaluates a variable's value as an
/// expression, and an array subscript in that value runs a command
/// substitution the text in front of us never spells, so
/// `x='a[$(id)]'; case $[x] in *) ls;; esac` runs `id`. `$((` holds a `$(`
/// and is already read as carrying a command; the legacy `$[` spelling has to
/// be named.
fn starts_a_command(text: &str) -> bool {
    text.contains('`')
        || text.contains("$(")
        || text.contains("$[")
        || text.contains("<(")
        || text.contains(">(")
        || text
            .match_indices("${")
            .any(|(index, _)| !reads_a_value(&text[index + 2..]))
}

/// Whether this `${...}` only reads a value. `${NAME}` and `${#NAME}` do.
/// Every other form does more than read: `${NAME@P}` expands the value as a
/// prompt string, which runs a command substitution the value holds, and
/// `${NAME:=word}` writes the variable that the lookup after it reads. The
/// text of such a value is not in front of us, so the expansion is read as
/// carrying a command rather than as inert.
fn reads_a_value(rest: &str) -> bool {
    let rest = rest.strip_prefix('#').unwrap_or(rest);
    let Some(end) = rest.find('}') else {
        return false;
    };
    let name = &rest[..end];
    name.starts_with(|c: char| c.is_alphanumeric() || c == '_')
        && name.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// A pattern the flat list may drop: bare glob text, after the optional `(`
/// that may open it, holding nothing that runs and no `)` of its own.
fn plain_pattern(pattern: &str) -> bool {
    let pattern = pattern.trim();
    let pattern = pattern.strip_prefix('(').unwrap_or(pattern).trim();
    !pattern.is_empty()
        && !pattern.contains(['`', '$', '"', '\'', '(', ')', ';', '&', '<', '>', '\n'])
}

/// An arm's command list, and the text the next pattern starts in.
fn arm_list(body: &str) -> Option<(Vec<(String, &'static str)>, &str)> {
    let (end, after) = arm_end(body)?;
    let list = body[..end].trim().trim_end_matches([';', ' ', '\t', '\n']);
    let text = format!("{list}; esac");
    let (items, _, _) = body_items(&text, "", &["esac"])?;
    Some((items, &body[after..]))
}

/// Where an arm's list ends: the `;;` that closes it, and where the arm after
/// it starts. A `;&` or `;;&` arm runs the arm below it as well, which the
/// list this builds does not say, so neither is taken. Quotes are followed so
/// that a `;;` written inside one ends nothing.
fn arm_end(body: &str) -> Option<(usize, usize)> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (index, character) in body.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match quote {
            Some('\'') => {
                if character == '\'' {
                    quote = None;
                }
            }
            Some(_) => match character {
                '\\' => escaped = true,
                '"' => quote = None,
                _ => {}
            },
            None => match character {
                '\\' => escaped = true,
                '\'' | '"' => quote = Some(character),
                ';' => {
                    let rest = &body[index..];
                    if rest.starts_with(";;&") || rest.starts_with(";&") {
                        return None;
                    }
                    if rest.starts_with(";;") {
                        return Some((index, index + 2));
                    }
                }
                _ => {}
            },
        }
    }
    None
}

/// Consume the `esac` that closes the construct, for the text that follows
/// the last arm.
fn closing(text: &str) -> Option<&str> {
    let rest = text.strip_prefix("esac")?;
    (rest.is_empty() || rest.starts_with([' ', '\t', '\n', ';', '<', '>'])).then_some(rest)
}

/// The two `while` shapes one flattened pass describes: a read that empties a
/// redirected file, and a wait that asks one question until it succeeds.
fn flatten_loop(rest: &str) -> Option<String> {
    flatten_read_loop(rest).or_else(|| flatten_wait(rest))
}

/// `while read NAME...; do LIST; done < FILE`, the one loop shape a single
/// flattened pass describes. The read ends at the file's end, so the loop
/// stops on its own, and a body that opens no output keeps every iteration
/// doing the work that one pass already stands for. A loop whose test is
/// anything else may never end, and a body that writes would repeat its
/// effect for as long as it runs, so neither is flattened here.
///
/// The flat list reads the redirected file and then runs the body. `read`
/// itself only binds a name from that file, so the read of the file is the
/// whole of what the loop's test reaches.
fn flatten_read_loop(rest: &str) -> Option<String> {
    // The loop binds a name of its own, and the flat list does not, so an
    // expansion inside it would stand for different text than the one the
    // loop ran. No expansion at all is the rule that keeps the two the same
    // work. A conditional binds nothing, so it carries its expansions.
    if rest.contains(['$', '`']) {
        return None;
    }
    let (test, _, after_test) = body_items(rest, "", &["do"])?;
    let (body, _, tail) = body_items(after_test, "", &["done"])?;
    if !driven_by_a_read(&test) {
        return None;
    }
    let source = read_source(&redirect_tail(tail)?)?;
    if body
        .iter()
        .any(|(text, _)| text.contains('>') || text.contains('<'))
    {
        return None;
    }
    let mut parts: Vec<(String, &'static str)> = vec![(format!("cat {source}"), "; ")];
    collect(&mut parts, body)?;
    assemble(&parts, "")
}

/// `until TEST; do sleep N; done`, and the same shape written with `while`.
///
/// A developer holds the next step until a service answers, and writes the
/// wait as the loop that asks again after a pause. One flattened pass holds
/// everything that loop can reach: the test is one command, so every
/// iteration runs the command the flat list already carries, and the body
/// only sleeps, so no iteration leaves anything behind for the next one to
/// build on. The command still faces the ordinary proofs, which is what
/// decides the wait.
///
/// The test is taken as a single item with no redirection of its own. A list
/// would run its later commands only on the outcome of the ones before them,
/// which a flat pass does not say, and a redirection opens a file the second
/// iteration would reach again. Both keep their review.
fn flatten_wait(rest: &str) -> Option<String> {
    // The loop reads its test again on every pass, and an expansion could
    // name different text each time once the body or the test writes one.
    // No expansion at all keeps the flat list the work the loop ran, which
    // is the rule the read-driven loop above follows for the same reason.
    if rest.contains(['$', '`']) {
        return None;
    }
    let (test, _, after_test) = body_items(rest, "", &["do"])?;
    let (body, _, tail) = body_items(after_test, "", &["done"])?;
    let [(probe, _)] = test.as_slice() else {
        return None;
    };
    if probe.contains(['<', '>']) {
        return None;
    }
    if !body.iter().all(|(text, _)| only_waits(text)) {
        return None;
    }
    let mut parts: Vec<(String, &'static str)> = Vec::new();
    collect(&mut parts, test)?;
    collect(&mut parts, body)?;
    assemble(&parts, tail)
}

/// Whether this body item is a plain `sleep` that waits and does nothing else.
///
/// A second argument is another duration on GNU `sleep` and an error
/// elsewhere, and neither is the pause this shape stands for, so only the
/// single-argument spelling is taken.
fn only_waits(text: &str) -> bool {
    let mut words = text.split_whitespace();
    if words.next() != Some("sleep") {
        return false;
    }
    let Some(duration) = words.next() else {
        return false;
    };
    words.next().is_none() && plain_duration(duration)
}

/// A literal pause: a number, whole or fractional, under an optional unit.
///
/// `sleep 1`, `sleep 0.5`, `sleep 30s` and `sleep 5m` are the spellings a
/// developer writes for the same wait. An option, an expansion and any other
/// word are left out, because each names something this reading cannot call a
/// pause, and a pause is the whole of what the body may do.
fn plain_duration(value: &str) -> bool {
    let digits = match value.as_bytes() {
        [rest @ .., b's' | b'm' | b'h' | b'd'] => rest,
        rest => rest,
    };
    !digits.is_empty()
        && digits.iter().any(u8::is_ascii_digit)
        && digits
            .iter()
            .all(|byte| byte.is_ascii_digit() || *byte == b'.')
        && digits.iter().filter(|byte| **byte == b'.').count() <= 1
}

/// Whether a loop's test is the single `read` that empties the redirected
/// input, which is what makes the iteration count finite. A test that opens a
/// file of its own is some other loop.
///
/// The names the `read` binds matter as much as the word itself. `read` fills
/// them for every line of the input, so `while read PATH` rebinds `PATH` for
/// the body and changes which program each of its command words resolves to.
/// The flat list would then stand for commands the loop never ran. Only the
/// ordinary lowercase names `for` already admits as loop variables are taken,
/// and `-r`, which only stops backslash processing, is the one option allowed
/// before them.
fn driven_by_a_read(test: &[(String, &'static str)]) -> bool {
    let [(text, _)] = test else {
        return false;
    };
    if text.contains(['<', '>']) {
        return false;
    }
    let mut words = text.split_whitespace();
    let mut word = words.next();
    // `IFS=` empties the field separator for the `read` alone, which keeps
    // the whole line in the name instead of splitting it. It starts no
    // program and leaves the flat list the same, so the loop is still the
    // one a single pass describes. Any other assignment is some other loop.
    if word == Some("IFS=") {
        word = words.next();
    }
    if word != Some("read") {
        return false;
    }
    let mut names = words.peekable();
    if names.peek() == Some(&"-r") {
        names.next();
    }
    names.all(|name| valid_identifier(name) && ordinary_loop_name(name))
}

/// The file a loop's input redirection names, for the plain `< FILE` tail and
/// nothing else. A second redirection, a descriptor, or `<>` leaves a shape
/// this recognizer does not model.
///
/// Only a plain relative spelling counts. The loop stops because its `read`
/// reaches the input's end, and a character device such as `/dev/urandom` or
/// `/dev/stdin` has no end, so a loop reading one runs without bound and a
/// single flattened pass stands for nothing. An absolute path, a `~` home
/// path, a `-` and a `..` segment all leave the workspace the flat list is
/// read against, so they keep their review too.
fn read_source(tail: &str) -> Option<String> {
    let target = tail.strip_prefix('<')?.trim();
    let plain = !target.is_empty()
        && !target.starts_with(['/', '-', '~'])
        && !target.split('/').any(|segment| segment == "..")
        && !target.contains(['<', '>', '&', ' ', '\t']);
    plain.then(|| target.to_owned())
}

/// Add a list's items, rejecting an empty list and any item whose command
/// word is not a plain word. A nested construct leaves its keyword in command
/// position, so this is also what keeps nesting on the unmodeled path.
fn collect(
    parts: &mut Vec<(String, &'static str)>,
    items: Vec<(String, &'static str)>,
) -> Option<()> {
    if items.is_empty() || parts.len() + items.len() > MAX_ITEMS {
        return None;
    }
    for (text, separator) in items {
        parts.push((substitute(&text, "")?, separator));
    }
    Some(())
}

/// Join the collected items, giving each one the redirection that followed
/// the construct. The construct applied that redirection to every command it
/// ran, so each flattened item carries it too.
///
/// A `!` in front of an item inverts that pipeline's exit status and runs
/// nothing of its own, so the item stands for the same work without it. It is
/// dropped only where nothing reads the outcome it inverts, which the item's
/// own separator says: a `;` successor runs either way, while a `&&` or `||`
/// successor runs on the opposite outcome once the `!` is gone and keeps it.
fn assemble(parts: &[(String, &'static str)], tail: &str) -> Option<String> {
    let tail = redirect_tail(tail)?;
    if parts.is_empty() {
        return None;
    }
    let mut out = String::new();
    for (text, separator) in parts {
        out.push_str(&unnegated_part(text, separator));
        if !tail.is_empty() {
            out.push(' ');
            out.push_str(&tail);
        }
        out.push_str(rendered_separator(separator));
        if out.len() > MAX_FLATTENED_BYTES {
            return None;
        }
    }
    Some(out.trim_end_matches([' ', ';']).to_owned())
}

/// The item the flat list runs, with a leading `!` dropped where the
/// separator after it shows that nothing reads the outcome it inverts.
///
/// The last item of an `if` or `elif` test is the exception when that item
/// changes shell state. `then` runs because the change failed, so the branch
/// still sees the directory the shell was already in. Dropping the `!` would
/// describe the branch as running after the change.
pub(super) fn unnegated_part(text: &str, separator: &str) -> String {
    if separator == TEST_OUTCOME {
        if negated_state_change(text) {
            return text.to_owned();
        }
        return super::list_wrapper::unnegated_item(text).unwrap_or_else(|| text.to_owned());
    }
    if separator != "; " {
        return text.to_owned();
    }
    super::list_wrapper::unnegated_item(text).unwrap_or_else(|| text.to_owned())
}

/// A leading `!` in front of a command whose success changes later commands.
///
/// A head the shell rewrites before it runs (`\cd`, `'cd'`, `"cd"`, `$cd`)
/// is the same kind of change: the word here is not the word that runs, so
/// dropping the `!` would describe `then` as running after the change.
fn negated_state_change(text: &str) -> bool {
    let trimmed = text.trim();
    let Some(rest) = trimmed.strip_prefix('!') else {
        return false;
    };
    if !rest.starts_with([' ', '\t', '\n']) {
        return false;
    }
    command_word_changes_shell_state(rest.trim())
}

/// Whether this stage's command word changes what a later command sees, or is
/// written so the shell rewrites the word before its name is known.
pub(super) fn command_word_changes_shell_state(stage: &str) -> bool {
    let head = command_head(stage);
    STATE_CHANGING.contains(&head)
        || head.contains(['\'', '"', '\\', '$'])
        || (head == "printf" && stage.split_whitespace().any(|word| word.starts_with("-v")))
        || head.split_once('=').is_some_and(|(name, _)| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}

/// Consume `keyword` followed by whitespace.
pub(super) fn keyword<'a>(text: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = text.strip_prefix(keyword)?;
    rest.starts_with([' ', '\t', '\n'])
        .then(|| rest.trim_start_matches([' ', '\t', '\n']))
}

#[cfg(test)]
#[path = "control_flow_flatten_tests.rs"]
mod tests;
