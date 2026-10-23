//! A forgiving reader of one line of source, for `code_expression`.
//!
//! It walks identifiers, calls, indexes, templates and short literals without
//! building a syntax tree, and fails closed on anything it does not know: a
//! long or encoded-looking literal, a stray symbol, an unbalanced bracket.

/// The longest expression read. A longer one is never treated as code, because
/// the cursor would stop before it had seen every literal.
pub(crate) const MAX_EXPRESSION_BYTES: usize = 600;
const MAX_DEPTH: usize = 8;

/// Which quoted literals a scan accepts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Literals {
    /// Short words, slugs, hosts and paths.
    Ordinary,
    /// One short word: the default of a getter, which may hold a real value.
    Word,
    /// Only the empty string: the default of an environment read.
    Empty,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scan {
    Fail,
    Done,
    /// The line ended before the expression closed, as in `await sign({`.
    Incomplete,
}

#[derive(Clone, Copy)]
pub(crate) struct Operand {
    pub(crate) structural: bool,
    pub(crate) dotted: bool,
}

pub(crate) struct Cursor<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) at: usize,
    pub(crate) literals: Literals,
}

pub(crate) fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte == b'$'
}

pub(crate) fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
}

/// An identifier or number long enough to be encoded material.
pub(crate) fn encoded_looking(word: &[u8]) -> bool {
    word.len() >= 16 && word.iter().any(u8::is_ascii_digit)
}

/// Path segments that name the process environment.
const ENVIRONMENT_PATH: [&[u8]; 4] = [b"env", b"environ", b"ENV", b"Env"];
/// Reads of one environment variable, whose first argument is its name.
const ENVIRONMENT_READS: [&[u8]; 4] = [b"get", b"fetch", b"var", b"var_os"];
/// Calls that supply the value used when the environment has none.
const ENVIRONMENT_DEFAULTS: [&[u8]; 4] =
    [b"unwrap_or", b"unwrap_or_else", b"or_else", b"getOrDefault"];
/// Getters on any receiver whose later arguments are default values.
const DEFAULT_GETTERS: [&[u8]; 4] = [b"get", b"fetch", b"getOrDefault", b"setdefault"];
/// Calls on any receiver whose arguments are all default values.
const DEFAULT_FALLBACKS: [&[u8]; 4] = [b"unwrap_or", b"unwrap_or_else", b"or_else", b"orElse"];
/// Encoding and curve names that mix letters and digits without being encoded.
const KNOWN_ENCODINGS: [&[u8]; 2] = [b"base64url", b"secp256k1"];

/// The first argument position of a call whose literals are hardcoded defaults
/// rather than names, and the literals those defaults may hold. A default on an
/// environment read can only be empty: `os.getenv("TOKEN", "x")` spells the name
/// first and the default second, and `.unwrap_or("x")` is all default. A default
/// on any other getter may be one short word, never a longer phrase or slug.
pub(crate) fn environment_call(path_env: bool, name: &[u8]) -> Option<(usize, Literals)> {
    if name == b"getenv" || (path_env && ENVIRONMENT_READS.contains(&name)) {
        return Some((1, Literals::Empty));
    }
    if path_env && ENVIRONMENT_DEFAULTS.contains(&name) {
        return Some((0, Literals::Empty));
    }
    if DEFAULT_GETTERS.contains(&name) {
        return Some((1, Literals::Word));
    }
    DEFAULT_FALLBACKS
        .contains(&name)
        .then_some((0, Literals::Word))
}

/// A quoted argument that cannot be a credential: one short word, or a literal
/// that reads as a slug, a host or a path of at most three words.
pub(crate) fn literal_ok(literal: &[u8]) -> bool {
    short_literal(literal) || word_like(literal)
}

/// At most one short word, with any blanks or punctuation around it, as in
/// `'hex'`, `'Bearer '`, `' '` or `', '`. Several words stay a possible
/// passphrase.
pub(crate) fn short_literal(literal: &[u8]) -> bool {
    literal.len() < 12
        && literal
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|word| word.iter().any(u8::is_ascii_alphanumeric))
            .count()
            <= 1
        && !literal
            .split(|byte| !byte.is_ascii_alphanumeric())
            .any(mixed_run)
}

/// A run of letters and digits long enough to be encoded and holding both.
fn mixed_run(run: &[u8]) -> bool {
    run.len() >= 8
        && run.iter().any(u8::is_ascii_digit)
        && run.iter().any(u8::is_ascii_alphabetic)
        && !KNOWN_ENCODINGS
            .iter()
            .any(|known| known.eq_ignore_ascii_case(run))
}

pub(crate) fn word_like(literal: &[u8]) -> bool {
    literal.len() <= 80
        && literal
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || b"._~:/?&=%#@-".contains(&byte))
        && literal.iter().filter(|&&byte| byte == b'-').count() <= 2
        && literal
            .split(|byte| !byte.is_ascii_alphanumeric())
            .all(|run| run.len() < 16 && !mixed_run(run))
}

/// Literal text of a template: no run that looks like an encoded secret and no
/// spelled-out phrase.
pub(crate) fn text_ok(text: &[u8]) -> bool {
    text.split(|&byte| !(byte.is_ascii_alphanumeric() || byte == b'_'))
        .all(|run| run.len() < 20 && !encoded_looking(run))
        && !spelled_phrase(text)
}

/// Four or more words joined by hyphens, or four lower-case words in a row, as
/// in the passphrase `correct-horse-battery-staple`.
fn spelled_phrase(text: &[u8]) -> bool {
    text.split(|&byte| !(byte.is_ascii_alphanumeric() || byte == b'-' || byte == b' '))
        .any(|segment| {
            let hyphenated = segment.split(|&byte| byte == b' ').any(|part| {
                part.split(|&byte| byte == b'-')
                    .filter(|word| !word.is_empty())
                    .count()
                    >= 4
            });
            let mut spoken = 0usize;
            let mut phrase = false;
            for word in segment.split(|&byte| byte == b' ') {
                if word.len() >= 2 && word.iter().all(u8::is_ascii_lowercase) {
                    spoken += 1;
                    phrase = phrase || spoken >= 4;
                } else {
                    spoken = 0;
                }
            }
            hyphenated || phrase
        })
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(text: &'a str) -> Self {
        let bytes = text.as_bytes();
        Self::over(&bytes[..bytes.len().min(MAX_EXPRESSION_BYTES)])
    }

    pub(crate) fn over(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            at: 0,
            literals: Literals::Ordinary,
        }
    }

    /// Whether one quoted literal is acceptable under the current mode.
    fn literal_allowed(&self, literal: &[u8]) -> bool {
        match self.literals {
            Literals::Ordinary => literal_ok(literal),
            Literals::Word => short_literal(literal),
            Literals::Empty => literal.is_empty(),
        }
    }

    /// Whether the text of a template literal is acceptable under the current
    /// mode. A template is quoted material like any other literal, so a mode
    /// that bounds quoted literals bounds its text too: a backtick cannot be
    /// used to hand a call the passphrase that the same quotes would refuse.
    fn template_text_ok(&self, text: &[u8]) -> bool {
        text_ok(text)
            && match self.literals {
                Literals::Ordinary => true,
                Literals::Word => short_literal(text),
                Literals::Empty => text.is_empty(),
            }
    }

    pub(crate) fn done(&self) -> bool {
        self.at >= self.bytes.len()
    }

    pub(crate) fn peek(&self, ahead: usize) -> u8 {
        self.bytes.get(self.at + ahead).copied().unwrap_or(0)
    }

    pub(crate) fn starts_with(&self, token: &[u8]) -> bool {
        self.bytes
            .get(self.at..)
            .is_some_and(|rest| rest.starts_with(token))
    }

    pub(crate) fn skip_blanks(&mut self) {
        while !self.done() && matches!(self.bytes[self.at], b' ' | b'\t') {
            self.at += 1;
        }
    }

    pub(crate) fn identifier(&mut self) -> Option<&'a [u8]> {
        let bytes: &'a [u8] = self.bytes;
        let start = self.at;
        if self.done() || !is_identifier_start(bytes[start]) {
            return None;
        }
        while !self.done() && is_identifier_byte(bytes[self.at]) {
            self.at += 1;
        }
        Some(&bytes[start..self.at])
    }

    /// A keyword followed by a blank, consumed with the blanks after it.
    pub(crate) fn keyword(&mut self, word: &[u8]) -> bool {
        if self.starts_with(word) && matches!(self.peek(word.len()), b' ' | b'\t') {
            self.at += word.len();
            self.skip_blanks();
            return true;
        }
        false
    }

    /// The body of a quoted literal, with the cursor after its closing quote.
    pub(crate) fn quoted(&mut self) -> Option<&'a [u8]> {
        let bytes: &'a [u8] = self.bytes;
        let quote = bytes[self.at];
        self.at += 1;
        let start = self.at;
        while !self.done() {
            let byte = bytes[self.at];
            if byte == b'\\' {
                self.at = (self.at + 2).min(bytes.len());
                continue;
            }
            if byte == quote {
                let body = &bytes[start..self.at];
                self.at += 1;
                return Some(body);
            }
            self.at += 1;
        }
        None
    }

    /// A template literal from its opening backtick, with the number of
    /// interpolations it holds.
    pub(crate) fn template(&mut self) -> (Scan, usize) {
        self.at += 1;
        let mut interpolations = 0;
        let mut text: Vec<u8> = Vec::new();
        loop {
            if self.done() {
                let scan = if self.template_text_ok(&text) {
                    Scan::Incomplete
                } else {
                    Scan::Fail
                };
                return (scan, interpolations);
            }
            let byte = self.bytes[self.at];
            if byte == b'\\' {
                let end = (self.at + 2).min(self.bytes.len());
                text.extend_from_slice(&self.bytes[self.at..end]);
                self.at = end;
                continue;
            }
            if byte == b'`' {
                self.at += 1;
                let scan = if self.template_text_ok(&text) {
                    Scan::Done
                } else {
                    Scan::Fail
                };
                return (scan, interpolations);
            }
            if byte == b'$' && self.peek(1) == b'{' {
                if !self.template_text_ok(&text) {
                    return (Scan::Fail, interpolations);
                }
                text.clear();
                self.at += 2;
                interpolations += 1;
                let scan = self.scan(Some(b'}'), 1);
                if scan != Scan::Done {
                    return (scan, interpolations);
                }
                continue;
            }
            text.push(byte);
            self.at += 1;
        }
    }

    /// Loose scan of code up to `closer`, or up to a terminator when there is
    /// none: identifiers, numbers, operators, short literals and nested groups.
    pub(crate) fn scan(&mut self, closer: Option<u8>, depth: usize) -> Scan {
        if depth > MAX_DEPTH {
            return Scan::Fail;
        }
        loop {
            if self.done() {
                return if closer.is_some() {
                    Scan::Incomplete
                } else {
                    Scan::Done
                };
            }
            let byte = self.bytes[self.at];
            if closer == Some(byte) {
                self.at += 1;
                return Scan::Done;
            }
            if closer.is_none() && b",;)}]".contains(&byte) {
                return Scan::Done;
            }
            match byte {
                b' ' | b'\t' | b',' | b':' | b'?' | b'.' | b'=' | b'<' | b'>' | b'+' | b'-'
                | b'*' | b'!' | b'&' | b'|' | b'%' | b'~' | b'^' => self.at += 1,
                b'/' => {
                    if matches!(self.peek(1), b'/' | b'*') {
                        return if closer.is_some() {
                            Scan::Incomplete
                        } else {
                            Scan::Done
                        };
                    }
                    self.at += 1;
                }
                b';' if closer == Some(b'}') => self.at += 1,
                b'0'..=b'9' => {
                    let start = self.at;
                    while !self.done()
                        && (is_identifier_byte(self.bytes[self.at]) || self.bytes[self.at] == b'.')
                    {
                        self.at += 1;
                    }
                    if self.at - start >= 16 {
                        return Scan::Fail;
                    }
                }
                b'"' | b'\'' => match self.quoted() {
                    Some(literal) if self.literal_allowed(literal) => {}
                    _ => return Scan::Fail,
                },
                b'`' => {
                    let (scan, _) = self.template();
                    if scan != Scan::Done {
                        return scan;
                    }
                }
                b'(' | b'[' | b'{' => {
                    let close = match byte {
                        b'(' => b')',
                        b'[' => b']',
                        _ => b'}',
                    };
                    self.at += 1;
                    let scan = self.scan(Some(close), depth + 1);
                    if scan != Scan::Done {
                        return scan;
                    }
                }
                _ if is_identifier_start(byte) => {
                    let Some(name) = self.identifier() else {
                        return Scan::Fail;
                    };
                    if encoded_looking(name) {
                        return Scan::Fail;
                    }
                }
                _ => return Scan::Fail,
            }
        }
    }

    /// The argument list of a call with default values. From `defaults_from`
    /// onward each argument is read for `defaults` only, so a hardcoded default
    /// that can hold a real credential does not make the expression inert code.
    /// Nested calls and closures in a default are read the same way.
    pub(crate) fn environment_arguments(
        &mut self,
        defaults_from: usize,
        defaults: Literals,
    ) -> Scan {
        let mut argument = 0usize;
        loop {
            self.skip_blanks();
            if self.done() {
                return Scan::Incomplete;
            }
            let byte = self.bytes[self.at];
            if byte == b')' {
                self.at += 1;
                return Scan::Done;
            }
            if byte == b',' {
                self.at += 1;
                argument += 1;
                continue;
            }
            // A getter's later argument is a default only when it is a plain
            // value, as `config.get(KEY, "fallback")` spells it. An object
            // literal there is a request's options, as in `fetch(url, {...})`
            // or `axios.get(url, {params: {...}})`, and its ordinary literals,
            // a media type or a grant type, stay ordinary. An environment read
            // and an all-default call hold no options.
            let options = defaults == Literals::Word && defaults_from > 0 && byte == b'{';
            let outer = self.literals;
            if argument >= defaults_from && !options {
                self.literals = defaults;
            }
            let scan = self.scan(None, 1);
            self.literals = outer;
            if scan == Scan::Fail {
                return Scan::Fail;
            }
            if self.done() {
                return Scan::Incomplete;
            }
            if !matches!(self.bytes[self.at], b',' | b')') {
                return Scan::Fail;
            }
        }
    }

    /// A `<...>` type argument list directly before a call, as in `parse<T>(`.
    pub(crate) fn generic_before_call(&mut self) -> bool {
        let mut at = self.at + 1;
        let mut depth = 1usize;
        while at < self.bytes.len() && depth > 0 {
            match self.bytes[at] {
                b'<' => depth += 1,
                b'>' => depth -= 1,
                byte if is_identifier_byte(byte) || b" \t,[]|&.".contains(&byte) => {}
                _ => return false,
            }
            at += 1;
        }
        if depth == 0 && self.bytes.get(at) == Some(&b'(') {
            self.at = at;
            return true;
        }
        false
    }

    /// An identifier path with calls, indexes, casts and non-null marks.
    pub(crate) fn operand(&mut self, numbers: bool) -> Option<Operand> {
        let mut structural = false;
        self.skip_blanks();
        loop {
            if self.keyword(b"await") || self.keyword(b"new") {
                structural = true;
            } else if self.keyword(b"typeof") || self.keyword(b"void") {
                continue;
            } else if self.peek(0) == b'!' && self.peek(1) != b'=' {
                self.at += 1;
            } else {
                break;
            }
        }
        if self.done() {
            return None;
        }
        let first = self.bytes[self.at];
        if first.is_ascii_digit() {
            if !numbers {
                return None;
            }
            let start = self.at;
            while !self.done()
                && (is_identifier_byte(self.bytes[self.at]) || self.bytes[self.at] == b'.')
            {
                self.at += 1;
            }
            return (self.at - start < 16).then_some(Operand {
                structural,
                dotted: false,
            });
        }
        if first == b'(' {
            self.at += 1;
            return (self.scan(Some(b')'), 1) != Scan::Fail).then_some(Operand {
                structural,
                dotted: false,
            });
        }
        if !is_identifier_start(first) || first == b'$' {
            return None;
        }
        let mut name = self.identifier()?;
        if encoded_looking(name) {
            return None;
        }
        let mut path_env = ENVIRONMENT_PATH.contains(&name);
        let mut dotted = false;
        while !self.done() {
            let byte = self.bytes[self.at];
            if byte == b'.' && is_identifier_start(self.peek(1)) {
                self.at += 1;
                dotted = true;
                name = self.identifier()?;
                if encoded_looking(name) {
                    return None;
                }
                path_env = path_env || ENVIRONMENT_PATH.contains(&name);
            } else if byte == b'?' && self.peek(1) == b'.' {
                self.at += 2;
                if !self.done() && is_identifier_start(self.bytes[self.at]) {
                    dotted = true;
                    name = self.identifier()?;
                    if encoded_looking(name) {
                        return None;
                    }
                    path_env = path_env || ENVIRONMENT_PATH.contains(&name);
                }
            } else if byte == b'?'
                && (self.at + 1 >= self.bytes.len() || b";),".contains(&self.peek(1)))
            {
                self.at += 1;
                structural = true;
            } else if byte == b':' && self.peek(1) == b':' && is_identifier_start(self.peek(2)) {
                self.at += 2;
                name = self.identifier()?;
                path_env = path_env || ENVIRONMENT_PATH.contains(&name);
            } else if byte == b'(' || byte == b'[' {
                self.at += 1;
                let close = if byte == b'(' { b')' } else { b']' };
                let scan = match (byte, environment_call(path_env, name)) {
                    (b'(', Some((defaults_from, defaults))) => {
                        self.environment_arguments(defaults_from, defaults)
                    }
                    _ => self.scan(Some(close), 1),
                };
                name = b"";
                if scan == Scan::Fail {
                    return None;
                }
                structural = true;
                if scan == Scan::Incomplete {
                    self.at = self.bytes.len();
                    break;
                }
            } else if byte == b'!' && self.peek(1) != b'=' {
                self.at += 1;
                structural = true;
            } else if byte == b'<' && self.generic_before_call() {
                continue;
            } else {
                break;
            }
        }
        Some(Operand { structural, dotted })
    }
}
