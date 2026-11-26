//! The body grammar of a `for` loop: the command list between `do` and
//! `done`, the references to the loop variable inside it, and the redirections
//! that may follow the loop.

use super::{CONTROL_WORDS, MAX_BODY_BYTES};

#[path = "for_loop_unroll_binding.rs"]
mod binding;

/// A parsed command list: its items with the separator that follows each, the
/// keyword that closed the list, and the text after that keyword.
pub(crate) type CommandList<'a> = (Vec<(String, &'static str)>, &'static str, &'a str);

/// Split a command list into items (with the separator that follows each),
/// stopping at whichever of `terminators` closes it, and return that keyword
/// with the text after it. Items keep a marker where `$NAME` appeared;
/// `substitute` expands it. An empty `name` binds nothing, and every
/// expansion is written back as it stood, because a list that binds no name
/// reads the same values the construct around it read. Any construct outside
/// the simple command list grammar returns `None`.
///
/// The caller here replaces the marker with a word of its own, so a reference
/// glued into a larger word is written out as that word glued the same way.
pub(crate) fn body_items<'a>(
    text: &'a str,
    name: &str,
    terminators: &[&'static str],
) -> Option<CommandList<'a>> {
    body_items_at(text, name, terminators, 0, false)
}

/// [`body_items`] for a caller that writes the marker back as a `$NAME`
/// expansion rather than replacing it with a word.
///
/// Braces come off in that spelling, so `${name}` glued to a word character
/// would be written out as `$name` glued to it -- an expansion of a name the
/// construct never bound. Such a reference keeps its review here.
pub(crate) fn body_items_rewriting_references<'a>(
    text: &'a str,
    name: &str,
    terminators: &[&'static str],
) -> Option<CommandList<'a>> {
    body_items_at(text, name, terminators, 0, true)
}

/// How deep a subshell group may nest inside a command list. A group holds a
/// command list of its own, so the list grammar reads it by reading that list;
/// the bound keeps that reading finite.
const MAX_GROUP_DEPTH: usize = 2;

/// [`body_items`], carrying how many subshell groups already enclose this
/// list. A `)` closes the list when `)` is one of its terminators, which is
/// how the group's own list ends.
fn body_items_at<'a>(
    text: &'a str,
    name: &str,
    terminators: &[&'static str],
    depth: usize,
    rewrites_references: bool,
) -> Option<CommandList<'a>> {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut items: Vec<(String, &'static str)> = Vec::new();
    let mut item = String::new();
    // Whether the next word to start is a command word, and whether the
    // previous operator was a redirection (so the next word is its target).
    let mut command_position = true;
    let mut redirect_target = false;
    let mut at_word_start = true;
    let mut i = 0;
    if chars.last().map_or(0, |(index, _)| *index) > MAX_BODY_BYTES {
        return None;
    }
    while i < chars.len() {
        let (byte, c) = chars[i];
        let rest = &text[byte..];
        match c {
            ' ' | '\t' => {
                item.push(c);
                at_word_start = true;
                i += 1;
            }
            '\n' | ';' | '&' | '|' => {
                let (separator, width): (&'static str, usize) =
                    if c == '|' && rest.starts_with("||") {
                        (" || ", 2)
                    } else if c == '&' && rest.starts_with("&&") {
                        (" && ", 2)
                    } else if c == '|' {
                        if rest.starts_with("|&") || item.trim().is_empty() {
                            return None;
                        }
                        item.push('|');
                        command_position = true;
                        redirect_target = false;
                        at_word_start = true;
                        i += 1;
                        continue;
                    } else if c == '&' {
                        // `>&2` and `&>file` are redirections; a lone `&` backgrounds.
                        if item.ends_with(['>', '<']) || rest.starts_with("&>") {
                            item.push('&');
                            redirect_target = true;
                            at_word_start = true;
                            i += 1;
                            continue;
                        }
                        return None;
                    } else if c == ';' && (rest.starts_with(";;") || rest.starts_with(";&")) {
                        return None;
                    } else {
                        ("; ", 1)
                    };
                let trimmed = item.trim().to_owned();
                if ends_in_an_open_escape(&trimmed) {
                    return None;
                }
                if trimmed.is_empty() {
                    // Blank separators (after `do`, doubled newlines) are fine;
                    // an empty slot around && or || is not.
                    if separator != "; " {
                        return None;
                    }
                    if let Some(last) = items.last() {
                        if last.1 != "; " {
                            return None;
                        }
                    }
                } else {
                    items.push((trimmed, separator));
                }
                item.clear();
                command_position = true;
                redirect_target = false;
                at_word_start = true;
                i += width;
                if separator == "; " {
                    let after = &text[chars.get(i).map_or(text.len(), |(b, _)| *b)..];
                    let lead = after.trim_start_matches([' ', '\t', '\n', ';']);
                    if let Some(&closer) = terminators
                        .iter()
                        .find(|keyword| starts_with_keyword(lead, keyword))
                    {
                        if items.last().is_none_or(|last| last.1 != "; ") {
                            return None;
                        }
                        return Some((items, closer, &lead[closer.len()..]));
                    }
                }
            }
            '>' | '<' => {
                if rest.starts_with("<<") || rest.starts_with("<(") || rest.starts_with(">(") {
                    return None;
                }
                item.push(c);
                command_position = false;
                redirect_target = true;
                at_word_start = true;
                i += 1;
            }
            // `{ list; }` in command position groups a list in the current
            // shell, as `[ -f "$f" ] && { printf …; sed -n … "$f"; }` reads a
            // file only when the test holds. Its list is read the way a
            // subshell's is and written back with the braces, so the proofs
            // below read the group, `cd` and all, as the shell runs it. A
            // brace anywhere else is a word or an expansion this grammar does
            // not model.
            '{' if command_position
                && depth < MAX_GROUP_DEPTH
                && rest[1..].starts_with([' ', '\t', '\n']) =>
            {
                let (inner, _, after) = body_items_at(
                    &text[byte + 1..],
                    name,
                    &["}"],
                    depth + 1,
                    rewrites_references,
                )?;
                if inner.is_empty()
                    || !inner
                        .iter()
                        .all(|(list_item, _)| stages_are_plain(list_item))
                {
                    return None;
                }
                item.push_str("{ ");
                for (inner_item, separator) in &inner {
                    item.push_str(inner_item);
                    item.push_str(separator);
                }
                item.push('}');
                at_word_start = false;
                command_position = false;
                redirect_target = false;
                let consumed = text.len() - after.len();
                i = chars.partition_point(|(index, _)| *index < consumed);
            }
            '`' | '{' | '}' => return None,
            // A `(` in command position opens a subshell, whose body is a
            // command list read the same way this one is. The group runs what
            // it holds in a shell of its own, so the written-out text keeps
            // the parentheses and the proofs below read the same work the
            // construct ran. Anywhere else a `(` belongs to a shape outside
            // this grammar (an array literal, a function body), which keeps
            // its review.
            // `((` opens an arithmetic command, not a subshell holding a
            // subshell, and arithmetic assigns without an `=` sign. It is not
            // a command list, so it keeps its review.
            '(' if command_position && depth < MAX_GROUP_DEPTH && !rest.starts_with("((") => {
                let (inner, _, after) = body_items_at(
                    &text[byte + 1..],
                    name,
                    &[")"],
                    depth + 1,
                    rewrites_references,
                )?;
                if inner.is_empty()
                    || !inner
                        .iter()
                        .all(|(list_item, _)| stages_are_plain(list_item))
                {
                    return None;
                }
                item.push('(');
                for (index, (inner_item, separator)) in inner.iter().enumerate() {
                    item.push_str(inner_item);
                    if index + 1 < inner.len() {
                        item.push_str(separator);
                    }
                }
                item.push(')');
                at_word_start = false;
                command_position = false;
                redirect_target = false;
                let consumed = text.len() - after.len();
                i = chars.partition_point(|(index, _)| *index < consumed);
            }
            ')' if terminators.contains(&")") => {
                let trimmed = item.trim().to_owned();
                if ends_in_an_open_escape(&trimmed) {
                    return None;
                }
                if trimmed.is_empty() {
                    // `(ls; )` closes after a finished item; `(ls &&)` and
                    // `()` leave an empty slot that runs nothing.
                    if items.last().is_none_or(|last| last.1 != "; ") {
                        return None;
                    }
                } else {
                    items.push((trimmed, "; "));
                }
                return Some((items, ")", &text[byte + 1..]));
            }
            '(' | ')' => return None,
            '#' if at_word_start => return None,
            '\\' => {
                let next = chars.get(i + 1)?.1;
                if next == '\n' {
                    return None;
                }
                item.push('\\');
                item.push(next);
                at_word_start = false;
                command_position = false;
                redirect_target = false;
                i += 2;
            }
            '\'' => {
                item.push('\'');
                i += 1;
                loop {
                    let q = chars.get(i)?.1;
                    item.push(q);
                    i += 1;
                    if q == '\'' {
                        break;
                    }
                }
                at_word_start = false;
                command_position = false;
                redirect_target = false;
            }
            '"' => {
                let argument = !command_position && !redirect_target;
                item.push('"');
                i += 1;
                loop {
                    let q = chars.get(i)?.1;
                    i += 1;
                    match q {
                        '"' => {
                            item.push('"');
                            break;
                        }
                        '`' => return None,
                        '\\' => {
                            let escaped = chars.get(i)?.1;
                            i += 1;
                            item.push('\\');
                            item.push(escaped);
                        }
                        '$' => item.push_str(&reference(
                            &chars,
                            &mut i,
                            name,
                            argument,
                            rewrites_references,
                        )?),
                        other => item.push(other),
                    }
                }
                at_word_start = false;
                command_position = false;
                redirect_target = false;
            }
            '$' => {
                let argument = !command_position && !redirect_target;
                i += 1;
                item.push_str(&reference(
                    &chars,
                    &mut i,
                    name,
                    argument,
                    rewrites_references,
                )?);
                at_word_start = false;
                command_position = false;
                redirect_target = false;
            }
            other => {
                item.push(other);
                at_word_start = false;
                command_position = false;
                redirect_target = false;
                i += 1;
            }
        }
    }
    None
}

/// Whether the item ends in a backslash with nothing left for it to escape.
/// `echo a\ ` ends in an escaped space, and trimming that space leaves the
/// backslash to escape the separator instead: the written list runs `echo a `
/// and then the next command, while the trimmed text would hand that command
/// to `echo` as arguments. No command list is described by both, so the
/// construct keeps its review.
fn ends_in_an_open_escape(item: &str) -> bool {
    (item.len() - item.trim_end_matches('\\').len()) % 2 == 1
}

/// Whether a body item can change the loop variable or `IFS`, so a later
/// `$NAME` would not expand to the word written in the header. References are
/// already placeholders here, so a remaining bare `NAME` or `IFS` is read as
/// the name `read`, `printf -v`, `declare`, `unset` or an assignment binds. A
/// `-NAME` flag such as `[ -f ... ]` is not a target; an attached `-vNAME` is.
pub(crate) fn rebinds(item: &str, name: &str) -> bool {
    // Quoting is how a rebinding hides: the shell builds one word out of
    // `o''pt=secret`, while the written text holds no run that spells the
    // name. Scanning both forms covers a name split across quotes and one
    // that quoting would instead join to its neighbour. A binding builtin is
    // read from the words the shell builds, so `select` inside a quoted jq
    // filter is text handed to jq, while `'re'ad n` is still `read`. Whether
    // the shell rewrites the text is read from it as written for both forms.
    let found = (
        binding::holds_a_binding_word(item),
        binding::rewritten(item),
    );
    may_rebind(item, name, found) || may_rebind(&unquoted(item), name, found)
}

/// A bare `NAME` only binds where something in the same item can bind a name:
/// the word is an assignment, a builtin that takes a name is there, or the
/// item opens an arithmetic command, which assigns without an `=` sign. A
/// name the item merely talks about, as in `echo "pkg: $pkg"`, binds nothing.
fn may_rebind(text: &str, name: &str, (binding_word, rewritten): (bool, bool)) -> bool {
    let assigns = || binding::assigns(text, name, rewritten);
    names_a_target(text, name) && (assigns() || binding_word || text.contains("(("))
}

/// The word the shell builds once it removes the quoting, which is the text
/// `rebinds` has to read as well as the text as written.
fn unquoted(item: &str) -> String {
    let mut built = String::new();
    let mut characters = item.chars();
    while let Some(character) = characters.next() {
        match character {
            '\'' => {
                for quoted in characters.by_ref() {
                    if quoted == '\'' {
                        break;
                    }
                    built.push(quoted);
                }
            }
            '"' => {
                let mut escaped = false;
                for quoted in characters.by_ref() {
                    if escaped {
                        // Inside double quotes a backslash escapes only these
                        // characters, and a backslash-newline pair is a line
                        // continuation that leaves nothing behind. Before any
                        // other character the shell keeps the backslash as an
                        // ordinary character of the word.
                        if quoted != '\n' {
                            if !matches!(quoted, '$' | '`' | '"' | '\\') {
                                built.push('\\');
                            }
                            built.push(quoted);
                        }
                        escaped = false;
                    } else if quoted == '"' {
                        break;
                    } else if quoted == '\\' {
                        escaped = true;
                    } else {
                        built.push(quoted);
                    }
                }
                if escaped {
                    built.push('\\');
                }
            }
            '\\' => built.extend(characters.next()),
            other => built.push(other),
        }
    }
    built
}

fn names_a_target(item: &str, name: &str) -> bool {
    let mut previous = ' ';
    let mut token = String::new();
    let mut flagged = false;
    for c in item.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_alphanumeric() || c == '_' {
            if token.is_empty() {
                flagged = previous == '-';
            }
            token.push(c);
        } else if !token.is_empty() {
            let target = |candidate: &str| {
                if flagged {
                    candidate.strip_prefix('v') == Some(name) || candidate == "vIFS"
                } else {
                    candidate == name || candidate == "IFS"
                }
            };
            if target(&token) {
                return true;
            }
            token.clear();
        }
        previous = c;
    }
    false
}

fn starts_with_keyword(text: &str, keyword: &str) -> bool {
    text.strip_prefix(keyword).is_some_and(|rest| {
        rest.is_empty() || rest.starts_with([' ', '\t', '\n', ';', '>', '<', '&'])
    })
}

/// Consume a `$NAME` or `${NAME}` reference (the `$` is already consumed) and
/// return a placeholder. A reference in command or redirect position, a
/// different variable, or any other expansion rejects the loop.
fn reference(
    chars: &[(usize, char)],
    i: &mut usize,
    name: &str,
    argument: bool,
    rewrites_references: bool,
) -> Option<String> {
    if !argument {
        return None;
    }
    let braced = chars.get(*i).is_some_and(|(_, c)| *c == '{');
    if braced {
        *i += 1;
    }
    let mut ident = String::new();
    while let Some(&(_, c)) = chars.get(*i) {
        if c.is_ascii_alphanumeric() || c == '_' {
            ident.push(c);
            *i += 1;
        } else {
            break;
        }
    }
    if ident.is_empty() {
        return None;
    }
    if braced {
        if chars.get(*i)?.1 != '}' {
            return None;
        }
        *i += 1;
    }
    if name.is_empty() {
        // Nothing binds a name here, so the expansion reads the same value in
        // the rewritten list as it did inside the construct. Writing it back
        // keeps the two the same work.
        return Some(if braced {
            format!("${{{ident}}}")
        } else {
            format!("${ident}")
        });
    }
    if ident != name {
        return None;
    }
    // Once the braces come off, `${name}` glued to a word character spells a
    // different name: a caller that writes the reference back as `$name`
    // would turn `${line}_suffix` into `$line_suffix`, an expansion of a name
    // the construct never bound. Only the braced spelling can reach here
    // glued -- an unbraced `$line_suffix` reads its whole identifier above
    // and fails the name comparison -- so only it is checked. A caller that
    // substitutes a word of its own keeps the gluing it was given, so the
    // check is its caller's to ask for.
    if rewrites_references
        && braced
        && chars
            .get(*i)
            .is_some_and(|(_, c)| c.is_ascii_alphanumeric() || *c == '_')
    {
        return None;
    }
    Some(MARKER.to_string())
}

/// Where the loop variable stood in the body, kept out of the shell's own
/// character set so no written word can collide with it.
const MARKER: char = '\u{1}';

/// Whether every reference to the loop variable is a whole unquoted word.
///
/// The shell splits an unquoted expansion into fields and expands what comes
/// out as a pattern, so each name a glob matches reaches the body as its own
/// argument. The proofs that expand a pattern own that rule, and they see it
/// only while the reference is the whole word: `cat $f` is written out as
/// `cat *.json`, so the glob proof reads exactly the names the loop reads,
/// and it refuses a directory holding a name that would split.
///
/// Glued into a larger word the written-out text spells a different pattern.
/// `cat bak-$f` becomes `cat bak-*.json`, whose matches are proven while the
/// loop's own `*.json` matches never are, so a name holding whitespace splits
/// in the body into words that pattern never matched. A reference inside a
/// larger word keeps its review. A reference the body quotes on its own is
/// read here as the whole word it is, because `unquote_whole_references` has
/// already taken the quotes off.
///
/// A reference followed by a plain relative path, as in `cat $d/package.json`,
/// stands alone as well. Written out it is `cat packages/*/package.json`: the
/// pattern then has a wildcard directory, and the glob proof that walks it
/// refuses every matched directory whose name holds whitespace or a glob
/// character, so no name the loop would split or expand again is admitted.
/// The loop reads `<match>/package.json` for every match, and those that
/// exist are exactly the words the written-out pattern expands to; the rest
/// read nothing.
pub(crate) fn references_stand_alone(item: &str) -> bool {
    let chars: Vec<char> = item.chars().collect();
    chars.iter().enumerate().all(|(index, &current)| {
        current != MARKER
            || (index.checked_sub(1).is_none_or(|before| {
                word_boundary(Some(chars[before])) && !escaped(&chars, before)
            }) && (word_boundary(chars.get(index + 1).copied())
                || plain_path_suffix(&chars, index + 1)
                    .is_some_and(|end| word_boundary(chars.get(end).copied()))))
    })
}

/// The end of a `/name/name` run that starts at `start`: one or more visible
/// or hidden components of plain filename characters, none of them `.` or
/// `..`, so the suffix only ever descends below the matched name.
fn plain_path_suffix(chars: &[char], start: usize) -> Option<usize> {
    if chars.get(start) != Some(&'/') {
        return None;
    }
    let end = chars[start..]
        .iter()
        .position(|character| {
            !(character.is_ascii_alphanumeric()
                || matches!(character, '/' | '.' | '_' | '-' | '+' | '@' | ','))
        })
        .map_or(chars.len(), |offset| start + offset);
    let suffix: String = chars[start + 1..end].iter().collect();
    suffix
        .split('/')
        .all(|component| !component.is_empty() && component != "." && component != "..")
        .then_some(end)
}

/// The commands of an item, cut at the `;`, `&&` and `||` that separate them
/// and at the braces of a `{ …; }` group, outside quotes. A group's list is
/// written back into one item, so a reference that ends one of its commands
/// stands beside `;` rather than a space; each command is held to the
/// reference rules on its own. Pipelines stay whole.
pub(crate) fn grouped_commands(item: &str) -> Vec<&str> {
    let bytes = item.as_bytes();
    let mut pieces = Vec::new();
    let (mut single, mut double) = (false, false);
    let (mut start, mut index) = (0, 0);
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\\' && !single {
            index += 2;
            continue;
        }
        match byte {
            b'\'' if !double => single = !single,
            b'"' if !single => double = !double,
            _ if single || double => {}
            b';' | b'{' | b'}' => {
                pieces.push(&item[start..index]);
                start = index + 1;
            }
            b'&' | b'|' if bytes.get(index + 1) == Some(&byte) => {
                pieces.push(&item[start..index]);
                start = index + 2;
                index += 2;
                continue;
            }
            _ => {}
        }
        index += 1;
    }
    pieces.push(&item[start.min(item.len())..]);
    pieces
        .into_iter()
        .map(str::trim)
        .filter(|piece| !piece.is_empty())
        .collect()
}

/// Whether `item` only prints, with every reference inside double quotes.
///
/// `echo "### $f"` labels each file a loop prints. Inside double quotes the
/// shell neither splits nor expands the matched name, so the item prints one
/// argument and reads nothing, whatever name the loop hands it. Written out
/// over the loop's pattern it prints the pattern instead, which is the same
/// work: text to standard output. That holds only for a lone `echo`, or a
/// `printf` whose format is a single-quoted literal the reference cannot
/// reach, with no redirection, pipe or group that could carry the name
/// anywhere else.
pub(crate) fn prints_quoted_references(item: &str) -> bool {
    let Some((command, rest)) = item.split_once(' ') else {
        return false;
    };
    let printer = match command {
        "echo" => true,
        "printf" => rest.trim_start().starts_with('\''),
        _ => false,
    };
    printer
        && !item.contains(['|', '<', '>', '(', ')', '{', '}', '&', ';', '`'])
        && references_are_quoted(item)
}

/// Whether every reference in `item` stands inside quotes of the body's own.
///
/// A header word that holds field separators is one field only while those
/// quotes stay on: written out bare it would split, and the shell's own split
/// of a quoted word never happened. An unquoted reference therefore keeps the
/// loop unmodeled rather than guessing which of the two the writer meant.
///
/// The quotes have to be open where the reference stands, not merely beside
/// it. A word such as `"a"$f"b"` closes one quoted run and opens another
/// around an expansion the shell still splits, so reading the two neighbours
/// alone would take that for a quoted reference.
pub(crate) fn references_are_quoted(item: &str) -> bool {
    let chars: Vec<char> = item.chars().collect();
    let mut single = false;
    let mut double = false;
    for (index, &current) in chars.iter().enumerate() {
        match current {
            MARKER if !single && !double => return false,
            '\'' if !double && (single || !escaped(&chars, index)) => single = !single,
            '"' if !single && !escaped(&chars, index) => double = !double,
            _ => {}
        }
    }
    true
}

/// Whether the character beside a reference ends the word, counting the ends
/// of the item itself.
fn word_boundary(character: Option<char>) -> bool {
    // An unquoted `;` ends a word as a space does. A `{ …; }` group is
    // written back into one item, so `"$f";` closes its last command there.
    character.is_none_or(|character| character.is_whitespace() || matches!(character, '|' | ';'))
}

/// Cutting a body item into the stages the shell reads.
#[path = "for_loop_unroll_pipeline.rs"]
mod pipeline;

pub(in crate::pretool) use pipeline::pipeline_stages;

/// Whether a backslash makes the character at `at` a literal. The shell reads
/// `\ ` as a space stuck to the word beside it, so `cat \ $f` is one glued
/// word rather than two, and the reference does not stand on its own after
/// all. An even run of backslashes spells backslashes and leaves the
/// character the boundary it looks like.
fn escaped(chars: &[char], at: usize) -> bool {
    chars[..at]
        .iter()
        .rev()
        .take_while(|character| **character == '\\')
        .count()
        % 2
        == 1
}

/// Take the quotes off a reference the body quotes as a whole word of its own.
///
/// Every word the loop header admits is one whitespace-free run of characters
/// the shell does nothing with, so `"$f"` and `$f` hand the body the same
/// single word. Writing the bare word out is what lets the glob proof read the
/// pattern the loop expands; left inside quotes it would stand for a name the
/// shell never matches.
///
/// Which `"` opens a string and which closes one decides that, so the scan
/// carries the quote state rather than reading the two characters beside the
/// reference. In `cat "x "$f" y"` the quote before the reference closes
/// `"x "` and the one after opens `" y"`: taking them off would spell the one
/// literal name `x *.md y` for a loop that reads `x a.md y` and `x b.md y`.
pub(crate) fn unquote_whole_references(item: &str) -> String {
    let chars: Vec<char> = item.chars().collect();
    let mut out = String::with_capacity(item.len());
    let mut index = 0usize;
    let mut in_double = false;
    while let Some(&current) = chars.get(index) {
        if !in_double && current == '\'' {
            out.push(current);
            index += 1;
            while let Some(&inner) = chars.get(index) {
                out.push(inner);
                index += 1;
                if inner == '\'' {
                    break;
                }
            }
            continue;
        }
        if !in_double
            && current == '"'
            && chars.get(index + 1) == Some(&MARKER)
            && word_boundary(index.checked_sub(1).map(|before| chars[before]))
        {
            // `"$d"` or `"$d/package.json"`: the quoted run holds only the
            // reference and a plain path below it, which no split or glob
            // expansion would change.
            let close = plain_path_suffix(&chars, index + 2).unwrap_or(index + 2);
            if chars.get(close) == Some(&'"') && word_boundary(chars.get(close + 1).copied()) {
                out.push(MARKER);
                out.extend(&chars[index + 2..close]);
                index = close + 1;
                continue;
            }
        }
        if current == '\\' && index + 1 < chars.len() {
            out.push(current);
            out.push(chars[index + 1]);
            index += 2;
            continue;
        }
        if current == '"' {
            in_double = !in_double;
        }
        out.push(current);
        index += 1;
    }
    out
}

/// Whether a body item reads the loop variable anywhere in its text.
pub(crate) fn reads_the_variable(item: &str) -> bool {
    item.contains(MARKER)
}

pub(crate) fn substitute(item: &str, word: &str) -> Option<String> {
    if !stages_are_plain(item) {
        return None;
    }
    Some(item.replace(MARKER, word))
}

/// Whether every pipeline stage of a body item starts with a plain command
/// word. A subshell group's own items were read as a command list and checked
/// here when the group was parsed.
fn stages_are_plain(item: &str) -> bool {
    // Every pipeline stage must start with a plain word: no marker, no
    // assignment, no shell keyword. A leading redirection such as
    // `2>/dev/null $f` would hide the real command word from this check, so a
    // stage that starts with one is rejected. A glob in the command word
    // (`/usr/bin/doc?er`) could name any program, so it keeps the loop on
    // the unmodeled path.
    //
    // A stage that opens with `[[` and closes with `]]` is the one keyword
    // that is read here, because the parse surface reads that closed pair as
    // the `[` test it asks, of less: inside `[[ ]]` the shell splits no word
    // and expands no glob. An unclosed `[[` is some other shape and keeps the
    // construct on the unmodeled path with every other keyword.
    //
    // `||` writes two `|` characters in a row, so splitting on the single
    // character leaves an empty run between them where the shell has a list
    // separator rather than a pipeline stage. That gap carries no command
    // word of its own, and the two commands it separates are each checked as
    // the stage before and after it, so a single empty run between two
    // non-empty runs is stepped over. Anything else is some other shape --
    // a pipeline that starts or ends on `|`, or a run of three or more `|`
    // the shell reads as a syntax error -- and keeps the construct on the
    // unmodeled path.
    let Some(stages) = pipeline_stages(item) else {
        return false;
    };
    for (index, stage) in stages.iter().copied().enumerate() {
        if stage.is_empty() {
            if index > 0
                && index + 1 < stages.len()
                && !stages[index - 1].is_empty()
                && !stages[index + 1].is_empty()
            {
                continue;
            }
            return false;
        }
        // A `!` in front of a pipeline inverts the exit status it reports and
        // runs nothing of its own, so the command word this check reads is
        // the word written after it. The shell accepts that `!` only where
        // the pipeline starts, so no later stage carries one.
        let stage = if index == 0 {
            negation_tail(stage)
        } else {
            stage
        };
        let Some(first) = stage.split_whitespace().next() else {
            return false;
        };
        let bare = first.trim_start_matches(|c: char| c.is_ascii_digit());
        let bracket_test = first == "[[" && stage.trim_end().ends_with("]]");
        if first.contains(MARKER)
            || first.contains('=')
            || bare.starts_with(['>', '<', '&'])
            || (first != "[" && !bracket_test && first.contains(['*', '?', '[']))
            || (CONTROL_WORDS.contains(&first) && !bracket_test)
        {
            return false;
        }
    }
    true
}

/// The pipeline without the `!` that inverts its exit status, where one is
/// written as a word of its own. A `!` joined to what follows it is an
/// ordinary word, and a bare `!` starts no pipeline, so neither is read as a
/// negation.
fn negation_tail(stage: &str) -> &str {
    stage
        .trim_start()
        .strip_prefix('!')
        .filter(|rest| rest.starts_with([' ', '\t']))
        .unwrap_or(stage)
}

/// The redirect text after `done`, restricted to plain redirections.
pub(crate) fn redirect_tail(tail: &str) -> Option<String> {
    // Newlines after done start new commands and must not be trimmed away.
    let tail = tail.trim_start_matches([' ', '\t']).trim_end();
    if tail.is_empty() {
        return Some(String::new());
    }
    if !(tail.starts_with(['>', '<', '&']) || tail.starts_with(|c: char| c.is_ascii_digit())) {
        return None;
    }
    let bytes: Vec<char> = tail.chars().collect();
    for (index, &c) in bytes.iter().enumerate() {
        match c {
            ';' | '|' | '$' | '`' | '(' | ')' | '\n' | '{' | '}' | '#' | '\'' | '"' | '\\'
            | '*' | '?' | '[' | '~' => return None,
            '&' => {
                let prev = index.checked_sub(1).map(|i| bytes[i]);
                if !(prev == Some('>') || bytes.get(index + 1) == Some(&'>')) {
                    return None;
                }
            }
            '<' if bytes.get(index + 1) == Some(&'<') => return None,
            _ => {}
        }
    }
    Some(tail.to_owned())
}
