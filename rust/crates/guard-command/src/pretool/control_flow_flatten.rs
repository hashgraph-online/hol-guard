//! A conditional runs a subset of the command lists written inside it: the
//! branch whose test succeeds. Writing those lists out as one plain list
//! therefore runs at least as much as the construct ever can, so admitting
//! the flat list admits the construct, and the conditional grants no
//! authority of its own.
//!
//! A loop is only the same shape when it is known to stop and its body cannot
//! build up across iterations, because one flattened pass stands for every
//! iteration. `while read NAME; do ...; done < FILE` is that shape, for a
//! plain relative `FILE`: the read ends at that file's end, and a body that
//! writes nothing leaves each iteration doing the work the single pass
//! already describes. A device or a path outside the workspace need never
//! end, so neither is taken. Every other loop keeps its review.
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
const MAX_FLATTENED_BYTES: usize = 8192;

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
    None
}

/// `if LIST; then LIST; [elif LIST; then LIST;]... [else LIST;] fi`.
fn flatten_conditional(rest: &str) -> Option<String> {
    let mut parts: Vec<(String, &'static str)> = Vec::new();
    let mut rest = rest;
    loop {
        let (test, _, after_test) = body_items(rest, "", &["then"])?;
        collect(&mut parts, test)?;
        let (branch, closer, after_branch) = body_items(after_test, "", &["elif", "else", "fi"])?;
        collect(&mut parts, branch)?;
        match closer {
            "elif" => rest = after_branch,
            "else" => {
                let (alternative, _, after_alternative) = body_items(after_branch, "", &["fi"])?;
                collect(&mut parts, alternative)?;
                return assemble(&parts, after_alternative);
            }
            _ => return assemble(&parts, after_branch),
        }
    }
}

/// `while read NAME...; do LIST; done < FILE`, the one loop shape a single
/// flattened pass describes. The read ends at the file's end, so the loop
/// stops on its own, and a body that opens no output keeps every iteration
/// doing the work that one pass already stands for. A loop whose test is
/// anything else may never end, and a body that writes would repeat its
/// effect for as long as it runs, so neither is flattened.
///
/// The flat list reads the redirected file and then runs the body. `read`
/// itself only binds a name from that file, so the read of the file is the
/// whole of what the loop's test reaches.
fn flatten_loop(rest: &str) -> Option<String> {
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
fn assemble(parts: &[(String, &'static str)], tail: &str) -> Option<String> {
    let tail = redirect_tail(tail)?;
    if parts.is_empty() {
        return None;
    }
    let mut out = String::new();
    for (text, separator) in parts {
        out.push_str(text);
        if !tail.is_empty() {
            out.push(' ');
            out.push_str(&tail);
        }
        out.push_str(separator);
        if out.len() > MAX_FLATTENED_BYTES {
            return None;
        }
    }
    Some(out.trim_end_matches([' ', ';']).to_owned())
}

/// Consume `keyword` followed by whitespace.
fn keyword<'a>(text: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = text.strip_prefix(keyword)?;
    rest.starts_with([' ', '\t', '\n'])
        .then(|| rest.trim_start_matches([' ', '\t', '\n']))
}

#[cfg(test)]
#[path = "control_flow_flatten_tests.rs"]
mod tests;
