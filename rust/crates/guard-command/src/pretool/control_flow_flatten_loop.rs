//! The `while` and `until` shapes one flattened pass describes.
//!
//! A loop is the same shape as a conditional only when one pass stands for
//! every iteration it could run. Two loops are: a `read` that empties a
//! redirected file, which ends at that file's end, and a wait that asks one
//! question until it succeeds, whose body only sleeps. Every other loop keeps
//! its review, and the reasons each shape is taken are written beside it.

use super::super::for_loop_unroll::body::{
    body_items, body_items_rewriting_references, redirect_tail,
};
use super::super::for_loop_unroll::{ordinary_loop_name, valid_identifier};
use super::{assemble, collect};

/// The two `while` shapes one flattened pass describes: a read that empties a
/// redirected file, and a wait that asks one question until it succeeds.
pub(super) fn flatten_loop(rest: &str) -> Option<String> {
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
///
/// The body keeps its references to the one name the `read` binds. Reading a
/// line of a file into a name leaves text no proof resolves, and so does the
/// value the surrounding shell holds under that name, so the flat list and
/// the loop are read the same way. `while read -r line; do echo "$line";
/// done < list.txt` is the shape a developer writes to walk a list, and it
/// reaches nothing `cat list.txt; echo "$line"` does not.
fn flatten_read_loop(rest: &str) -> Option<String> {
    let (test, _, after_test) = body_items(rest, "", &["do"])?;
    let name = read_bound_name(&test)?;
    // The body reads the name the `read` binds, and the flat list reads an
    // expansion of that same name. Neither is text a proof resolves -- a line
    // of the file is as unknown as whatever the shell already holds -- so the
    // two are read the same way and the flat list stands for the work the
    // loop did. The body grammar refuses any other expansion, because it
    // would name a value the loop never bound.
    let (body, _, tail) = body_items_rewriting_references(after_test, &name, &["done"])?;
    // A `read` that fills several names, or none, leaves no single name to
    // carry, so a body that expands anything at all keeps its review.
    if name.is_empty() && body.iter().any(|(text, _)| text.contains('$')) {
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
    let reference = if name.is_empty() {
        String::new()
    } else {
        format!("${name}")
    };
    collect(&mut parts, body, &reference)?;
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
pub(super) fn flatten_wait(rest: &str) -> Option<String> {
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
    if !opens_no_file(probe) {
        return None;
    }
    if !body.iter().all(|(text, _)| only_waits(text)) {
        return None;
    }
    // A redirection after `done` is opened once and used by every pass: a
    // file named there grows for as long as the wait runs, and an input
    // device feeds a probe that need never reach an end. One flat pass says
    // neither, so a wait written with a redirection keeps its review. A
    // command list written after the loop is not that shape: it runs once,
    // after the wait, and the flat list carries it.
    let after = trailing_list(tail)?;
    let mut parts: Vec<(String, &'static str)> = Vec::new();
    collect(&mut parts, test, "")?;
    collect(&mut parts, body, "")?;
    if !after.is_empty() {
        collect(&mut parts, after, "")?;
    }
    assemble(&parts, "")
}

/// Whether the loop's test opens nothing of its own.
///
/// A redirection in the test names something every pass reaches again: a
/// file that grows for as long as the wait runs, or an input the probe reads
/// a further piece of each time. One flat pass says neither, so a test that
/// carries one keeps its review.
///
/// An inert redirect to the null device is the exception. `kill -0 1234
/// 2>/dev/null` is how a wait asks whether a process is still running
/// without printing the answer while it is not, and the sink holds nothing:
/// every pass writes the same nothing, so the flat list stands for the loop
/// exactly as the unredirected spelling does. Only a sink that ends the test
/// is read, and only in front of text that spells no other redirection,
/// quote or escape, so what is taken off is the whole of what the probe
/// opens.
fn opens_no_file(probe: &str) -> bool {
    if !probe.contains(['<', '>']) {
        return true;
    }
    let asked = probe.trim_end();
    let chars: Vec<char> = asked.chars().collect();
    let Some(start) = (0..chars.len()).find(|start| {
        crate::parser_segments::null_sink_redirect_end(&chars, *start, false) == Some(chars.len())
    }) else {
        return false;
    };
    let command: String = chars[..start].iter().collect();
    !command.trim().is_empty() && !command.contains(['<', '>', '\\', '\'', '"'])
}

/// The command list written after `done`, empty when nothing follows it.
///
/// A developer holds the next step until a service answers and then takes
/// that step: `until ...; done; echo ready` is one command, and the list
/// after the loop runs once when the wait is over. Writing it into the flat
/// list keeps every command the shell runs in front of the ordinary proofs,
/// in the order it runs them.
///
/// Only a plain `;` or newline join is read. A `&&` or `||` reads the loop's
/// own outcome, a redirection belongs to the loop itself, and `&` puts the
/// wait in the background, so each keeps its review. The parse ends on a
/// terminator of this reading's own, which a list that spells `done` itself
/// would reach early, leaving text behind and keeping its review too.
fn trailing_list(tail: &str) -> Option<Vec<(String, &'static str)>> {
    let trimmed = tail.trim_start_matches([' ', '\t']);
    if trimmed.trim().is_empty() {
        return Some(Vec::new());
    }
    let list = trimmed
        .strip_prefix(';')
        .or_else(|| trimmed.strip_prefix('\n'))?;
    if list
        .trim_start_matches([' ', '\t', '\n'])
        .starts_with([';', '&', '|'])
    {
        return None;
    }
    let text = format!("{list}\ndone");
    let (items, _, after) = body_items(&text, "", &["done"])?;
    (after.is_empty() && !items.is_empty()).then_some(items)
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

/// The one name a loop's test binds, when that test is the single `read`
/// that empties the redirected input -- which is what makes the iteration
/// count finite. A test that opens a file of its own is some other loop, and
/// `None` keeps it on the unmodeled path.
///
/// The names the `read` binds matter as much as the word itself. `read` fills
/// them for every line of the input, so `while read PATH` rebinds `PATH` for
/// the body and changes which program each of its command words resolves to.
/// The flat list would then stand for commands the loop never ran. Only the
/// ordinary lowercase names `for` already admits as loop variables are taken,
/// and `-r`, which only stops backslash processing, is the one option allowed
/// before them.
///
/// An empty name is still a read-driven test. `read` with no name of its own
/// fills `REPLY`, and `read -r a b` splits each line across several names;
/// neither leaves one name for the body to carry, so the caller refuses a
/// body that expands anything.
fn read_bound_name(test: &[(String, &'static str)]) -> Option<String> {
    let [(text, _)] = test else {
        return None;
    };
    if text.contains(['<', '>']) {
        return None;
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
        return None;
    }
    let mut names = words.peekable();
    if names.peek() == Some(&"-r") {
        names.next();
    }
    let names: Vec<&str> = names.collect();
    if !names
        .iter()
        .all(|name| valid_identifier(name) && ordinary_loop_name(name))
    {
        return None;
    }
    Some(match names.as_slice() {
        [name] => (*name).to_owned(),
        _ => String::new(),
    })
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
