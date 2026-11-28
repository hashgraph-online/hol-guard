//! Which lines of a code file open a definition, and the name each gives.
//!
//! CIGAR splits a file into the definitions it holds and places a prompt's
//! code by their names. A language that opens a definition with a keyword
//! (`def`, `fn`, `func`, `class`, `fun`) is read by that keyword after its
//! modifiers. A method in Java, C#, C++ or a TypeScript or JavaScript class
//! has no keyword: it is a name and its parameters, then the body's brace,
//! so a line shaped that way opens one too. Without it a file in those
//! languages had no sections at all, and a note could not place its code.

/// Words that open a definition line, after any modifiers.
const DEFINERS: [&str; 13] = [
    "def ",
    "class ",
    "fn ",
    "function ",
    "func ",
    "struct ",
    "enum ",
    "trait ",
    "impl ",
    "interface ",
    "type ",
    "mod ",
    "module ",
];
/// Words that open a definition only when a name follows: in other
/// languages they are ordinary names, as `object = ...` in Python.
const NAMED_DEFINERS: [&str; 7] = [
    "fun ",
    "object ",
    "record ",
    "protocol ",
    "extension ",
    "namespace ",
    "union ",
];
/// Words that bind a value: a definition only at a file's top level, since
/// inside a function they name a local.
const BINDERS: [&str; 3] = ["const ", "let ", "var "];
/// Modifiers that may come before a definer or a method's type.
const MODIFIERS: [&str; 26] = [
    "export ",
    "default ",
    "pub ",
    "pub(crate) ",
    "pub(super) ",
    "async ",
    "static ",
    "public ",
    "private ",
    "protected ",
    "abstract ",
    "unsafe ",
    "final ",
    "override ",
    "open ",
    "data ",
    "sealed ",
    "internal ",
    "inline ",
    "suspend ",
    "readonly ",
    "virtual ",
    "partial ",
    "synchronized ",
    "native ",
    "declare ",
];
/// Words a line that calls or tests something starts with, or that name a
/// statement rather than a method: `if (x) {`, `return run(x)`.
const STATEMENTS: [&str; 34] = [
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "return",
    "new",
    "throw",
    "else",
    "do",
    "try",
    "with",
    "lock",
    "using",
    "foreach",
    "elif",
    "sizeof",
    "typeof",
    "await",
    "yield",
    "match",
    "when",
    "case",
    "assert",
    "delete",
    "defer",
    "go",
    "select",
    "unless",
    "until",
    "print",
    "echo",
    "fixed",
    "synchronized",
];
/// Words that mark a member of a class even when its brace is on the next
/// line, as C# and some Java code write it.
const ACCESS: [&str; 4] = ["public", "private", "protected", "internal"];
/// Kotlin and Swift functions that take a trailing block: `repeat(3) {` is
/// a call, though it is shaped like a method.
const BLOCK_CALLS: [&str; 16] = [
    "launch",
    "withContext",
    "runBlocking",
    "repeat",
    "withAnimation",
    "coroutineScope",
    "supervisorScope",
    "withTimeout",
    "withTimeoutOrNull",
    "measureTimeMillis",
    "assertFailsWith",
    "assertThrows",
    "takeIf",
    "onAppear",
    "onChange",
    "onDisappear",
];
/// Keywords that, in C and C++, may begin a function's return type:
/// `struct node *new_node(int v) {`, `const char *label(void) {`.
const RETURN_TYPE_WORDS: [&str; 4] = ["struct", "enum", "union", "const"];

/// The text after one leading modifier other than `const`, if there is one.
fn after_modifier(rest: &str) -> Option<&str> {
    if let Some(after) = MODIFIERS.iter().find_map(|m| rest.strip_prefix(m)) {
        return Some(after);
    }
    if let Some(after) = rest.strip_prefix("pub(") {
        return after.split_once(") ").map(|(_, after)| after);
    }
    let after = rest.strip_prefix("extern ")?;
    Some(
        after
            .strip_prefix('"')
            .and_then(|abi| abi.split_once("\" "))
            .map_or(after, |(_, after)| after),
    )
}

/// The line with its modifiers taken off: `pub(in crate::x)`, `extern "C"`
/// and `const` before `fn` included. One pass over the line, so a line of
/// many `const` words costs no more than its length.
fn unmodified(line: &str) -> &str {
    let mut rest = line.trim_start();
    loop {
        if let Some(after) = after_modifier(rest) {
            rest = after;
            continue;
        }
        if !rest.starts_with("const ") {
            return rest;
        }
        // `const fn` in Rust; `const x = 1` stays a binding.
        let mut ahead = rest;
        while let Some(after) = ahead
            .strip_prefix("const ")
            .or_else(|| after_modifier(ahead))
        {
            ahead = after;
        }
        if !ahead.starts_with("fn ") {
            return rest;
        }
        rest = ahead;
    }
}

/// Words that may follow a declared name: `extension Array where ...`,
/// `object Foo extends Bar`.
const DECLARATION_WORDS: [&str; 4] = ["where", "extends", "implements", "with"];

/// The definer followed by a name, then what a declaration has next: the
/// end of the line, a brace, parameters, a type, or a declaration word.
/// `object and refresh()` in Python is an expression, not a declaration.
fn named(rest: &str, definer: &str) -> bool {
    let Some(name) = rest.strip_prefix(definer) else {
        return false;
    };
    if !name.starts_with(|c: char| c.is_alphabetic() || c == '_') {
        return false;
    }
    let after = name.trim_start_matches(|c: char| c.is_alphanumeric() || c == '_');
    let next = after.trim_start();
    next.is_empty()
        || next.starts_with(['{', '(', ':', '<', '[', '.', '='])
        || DECLARATION_WORDS
            .iter()
            .any(|word| next.split_whitespace().next() == Some(word))
}

/// A line that opens a definition by its keyword.
fn keyword_definition(line: &str) -> bool {
    let top_level = !line.starts_with(char::is_whitespace);
    let rest = unmodified(line);
    DEFINERS.iter().any(|definer| rest.starts_with(definer))
        || NAMED_DEFINERS.iter().any(|definer| named(rest, definer))
        || (top_level && BINDERS.iter().any(|binder| rest.starts_with(binder)))
}

/// Words that open a clause, `else: x = 1`, never a binding's name.
const CLAUSES: [&str; 5] = ["finally", "except", "lambda", "default", "label"];

/// The name a top-level value binding without a keyword gives: a constant
/// written in capitals, `MAX_NESTING = 400`, or a value with a declared
/// type, `_spec: Tuple[str, ...] = (` and Rust's `static NAME: T = x;`.
/// Python and Ruby keep a module's settings this way, and a fix that only
/// changes a limit edits nothing else. An ordinary lowercase assignment,
/// `object = make()`, stays a statement.
fn constant(line: &str) -> Option<&str> {
    if line.starts_with(char::is_whitespace) {
        return None;
    }
    let rest = unmodified(line);
    let end = rest
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    let (name, after) = rest.split_at(end);
    if !identifier(name) || STATEMENTS.contains(&name) || CLAUSES.contains(&name) {
        return None;
    }
    let after = after.trim_start();
    let capitals = name.chars().any(char::is_uppercase) && !name.chars().any(char::is_lowercase);
    let assigned = |text: &str| text.starts_with('=') && !text.starts_with("==");
    let typed = after
        .strip_prefix(':')
        .filter(|kind| !kind.starts_with([':', '=']))
        .is_some_and(|kind| kind.contains(" = "));
    (typed || (capitals && assigned(after))).then_some(name)
}

/// A line that opens a function, method, type or top-level value definition.
pub(crate) fn definition(line: &str) -> bool {
    keyword_definition(line) || method(line).is_some() || constant(line).is_some()
}

fn identifier(word: &str) -> bool {
    let mut chars = word.chars();
    chars
        .next()
        .is_some_and(|c| c.is_alphabetic() || c == '_' || c == '$')
        && chars.all(|c| c.is_alphanumeric() || c == '_' || c == '$')
}

/// Where the parenthesis opened at the start of `text` closes, outside
/// quoted text.
fn closing(text: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (at, c) in text.char_indices() {
        match quote {
            Some(_) if escaped => escaped = false,
            Some(_) if c == '\\' => escaped = true,
            Some(mark) if c == mark => quote = None,
            Some(_) => {}
            None => match c {
                '"' | '\'' | '`' => quote = Some(c),
                '(' => depth += 1,
                ')' => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(at);
                    }
                }
                _ => {}
            },
        }
    }
    None
}

/// What may follow a method's parameters before its body: a return type,
/// `throws`, `const`, `noexcept`, `override` or `-> T`.
fn signature_tail(text: &str) -> bool {
    text.chars()
        .all(|c| c.is_alphanumeric() || c.is_whitespace() || "_:<>[],.?*&|()-$".contains(c))
}

/// The text before a method's parameters with its trailing type
/// parameters, `<T, K extends keyof T>`, taken off.
fn generic_free(head: &str) -> &str {
    if !head.ends_with('>') {
        return head;
    }
    let mut depth = 0usize;
    for (at, c) in head.char_indices().rev() {
        match c {
            '>' => depth += 1,
            '<' => {
                depth -= 1;
                if depth == 0 {
                    return &head[..at];
                }
            }
            _ => {}
        }
    }
    head
}

/// The name a method line defines, when the line is a name and its
/// parameters followed by the body's brace: `parse(url: string): Url {`,
/// `public static int count(List<T> items) throws IOException {`,
/// `std::string Box::name() const {`. A C# or Java member with an access
/// modifier may leave the brace for the next line. A call is not one: its
/// name follows a `.`, a statement word comes first, an argument opens a
/// block (`it("adds", () => {`), or a capitalised name stands alone, as
/// `Button(action: save) {` does in SwiftUI.
pub(crate) fn method(line: &str) -> Option<&str> {
    let text = line.trim();
    if text.starts_with(|c: char| !(c.is_alphabetic() || c == '_' || c == '$' || c == '~')) {
        return None;
    }
    let open = text.find('(')?;
    // Type parameters may hold spaces: `pick<T, K extends keyof T>(`.
    let head = generic_free(&text[..open]);
    if !head
        .chars()
        .all(|c| c.is_alphanumeric() || c.is_whitespace() || "_<>[],.?*&:$~".contains(c))
    {
        return None;
    }
    let words: Vec<&str> = head.split_whitespace().collect();
    let last = *words.last()?;
    let name = last
        .rsplit("::")
        .next()?
        .trim_start_matches(['*', '&', '~']);
    // A generic method, `parse<T>(`, is named before its type parameters.
    let name = name.split_once('<').map_or(name, |(name, _)| name);
    if last.contains('.') || !identifier(name) {
        return None;
    }
    // `synchronized void flush() {` is a Java method; `synchronized (x) {`
    // is a statement, caught by its name.
    let leading_statement = STATEMENTS.contains(&words[0]) && words[0] != "synchronized";
    if STATEMENTS.contains(&name) || leading_statement {
        return None;
    }
    if ACCESS.contains(&name) || (words.len() == 1 && BLOCK_CALLS.contains(&name)) {
        return None;
    }
    let close = open + closing(&text[open..])?;
    let after = text[close + 1..].trim();
    let after = after
        .split_once("//")
        .map_or(after, |(code, _)| code)
        .trim_end();
    // A body may open and close on the line: `int size() const { return n; }`.
    let braced = after.strip_suffix('{').map(str::trim_end).or_else(|| {
        after
            .ends_with('}')
            .then(|| after.split_once('{'))
            .flatten()
            .map(|(tail, _)| tail.trim_end())
    });
    let member = words.iter().any(|word| ACCESS.contains(word));
    let shaped = match braced {
        Some(tail) => signature_tail(tail),
        None => member && signature_tail(after),
    };
    let lone_type =
        words.len() == 1 && !last.contains("::") && name.starts_with(char::is_uppercase);
    (shaped && !lone_type).then_some(name)
}

/// The name a definition line gives, as the code writes it.
pub(crate) fn written_name(line: &str) -> Option<String> {
    if !keyword_definition(line) && method(line).is_none() {
        if let Some(name) = constant(line) {
            return Some(name.to_owned());
        }
    }
    let rest = unmodified(line);
    let mut words = rest.split_whitespace();
    let definer = words.next().unwrap_or_default();
    // A C function whose return type starts with a keyword is named by its
    // parameters, not by the word after the keyword. Its modifiers are read
    // off first: `pub(crate) struct Id {` is no call to `pub`.
    let method_name = if !keyword_definition(line) {
        method(line).map(str::to_owned)
    } else if RETURN_TYPE_WORDS.contains(&definer) {
        // The body's brace may be on the next line: `struct node *f(int v)`.
        let header = rest.trim_end();
        method(rest).map(str::to_owned).or_else(|| {
            let opened = format!("{header} {{");
            header
                .ends_with(')')
                .then(|| method(&opened).map(str::to_owned))
                .flatten()
        })
    } else {
        None
    };
    if let Some(name) = method_name {
        return Some(name);
    }
    if definer.is_empty() {
        return None;
    }
    let mut word = words.next()?;
    // A Go method's name follows its receiver: `func (r *Route) Name()`.
    if definer == "func" && word.starts_with('(') {
        while !word.contains(')') {
            word = words.next()?;
        }
        word = word
            .split_once(')')
            .map(|(_, after)| after)
            .unwrap_or_default();
        if word.is_empty() {
            word = words.next()?;
        }
    }
    let name: String = word
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
#[path = "context_assistance_engine_definitions_tests.rs"]
mod tests;
