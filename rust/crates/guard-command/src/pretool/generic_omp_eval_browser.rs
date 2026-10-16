//! Oh My Pi `eval` programs that drive the isolated browser on a loopback page.
//!
//! OMP's JavaScript eval exposes a session-scoped `browser` facade. Checking a
//! local dev server is a common step: open `http://localhost:PORT`, click,
//! press keys, read the title, take a screenshot and display what the page
//! reports. This module accepts only that shape:
//!
//! - `const|let NAME = await browser.open({...})` with a literal options
//!   object whose `url` is an `http(s)` loopback URL and whose other keys are
//!   presentation options. Options that attach another browser (`app`), load
//!   scripts or files, keep a profile, or relax TLS are not accepted.
//! - `const|let NAME = browser.tab('name')`, a tab already in the session.
//!   Guard reviews every other `open`, so such a tab is a loopback page or
//!   one the user approved for the agent to drive.
//! - `await TAB.method(...)` for page reads and interactions with literal
//!   arguments, `goto` only to a loopback URL, and `evaluate` with an inline
//!   arrow function. OMP serializes that function with `String(fn)` and runs
//!   it inside the page, never in the agent process. Its body may read and
//!   compute over the DOM but not name a network, navigation, markup or code
//!   sink, a global object, a URL, or a computed property.
//! - `display(...)`, `log(...)` and `console.log(...)` of literals, declared
//!   names and awaited tab calls.
//!
//! Anything else (comments, `/`, template interpolation, `tab.run`, file,
//! cookie and download helpers, other identifiers) keeps the program reviewed.

use std::collections::HashSet;

const MAX_CODE_BYTES: usize = 16 * 1024;
const MAX_DEPTH: usize = 12;

#[path = "generic_omp_eval_browser_lex.rs"]
mod lex;
use lex::{
    loopback_url, page_token, tokenize, Token, NO_ARGUMENT_METHODS, OPEN_KEYS, OPTION_KEYS,
    RESERVED,
};

#[derive(Default)]
struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    tabs: HashSet<String>,
    values: HashSet<String>,
    depth: usize,
    browser_calls: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        token
    }

    fn punct(&mut self, c: char) -> Option<()> {
        (self.next()? == Token::Punct(c)).then_some(())
    }

    fn eat_punct(&mut self, c: char) -> bool {
        let found = self.peek() == Some(&Token::Punct(c));
        if found {
            self.pos += 1;
        }
        found
    }

    fn ident(&mut self) -> Option<String> {
        match self.next()? {
            Token::Ident(name) => Some(name),
            _ => None,
        }
    }

    fn keyword(&mut self, word: &str) -> Option<()> {
        (self.ident()? == word).then_some(())
    }

    fn peek_ident(&self, word: &str) -> bool {
        matches!(self.peek(), Some(Token::Ident(name)) if name == word)
    }

    fn string(&mut self) -> Option<String> {
        match self.next()? {
            Token::Str(text) => Some(text),
            _ => None,
        }
    }

    fn enter(&mut self) -> Option<()> {
        self.depth += 1;
        (self.depth <= MAX_DEPTH).then_some(())
    }

    fn program(&mut self) -> Option<()> {
        while self.peek().is_some() {
            if self.eat_punct(';') {
                continue;
            }
            self.statement()?;
            // A statement ends at `;`, the end, or the next statement's
            // keyword; anything else would chain onto it.
            match self.peek() {
                None | Some(Token::Punct(';')) | Some(Token::Ident(_)) => {}
                _ => return None,
            }
        }
        (self.browser_calls > 0).then_some(())
    }

    fn statement(&mut self) -> Option<()> {
        match self.ident()?.as_str() {
            "const" | "let" => {
                let name = self.ident()?;
                if RESERVED.contains(&name.as_str())
                    || self.tabs.contains(&name)
                    || self.values.contains(&name)
                {
                    return None;
                }
                self.punct('=')?;
                if self.peek_ident("browser") {
                    self.browser_tab()?;
                    self.tabs.insert(name);
                } else if self.peek_ident("await") {
                    self.pos += 1;
                    if self.peek_ident("browser") {
                        self.browser_open()?;
                        self.tabs.insert(name);
                    } else {
                        self.tab_call()?;
                        self.values.insert(name);
                    }
                } else {
                    self.value()?;
                    self.values.insert(name);
                }
                Some(())
            }
            "await" if self.peek_ident("browser") => self.browser_open(),
            "await" => self.tab_call(),
            "display" | "log" => self.output_args(),
            "console" => {
                self.punct('.')?;
                if !matches!(self.ident()?.as_str(), "log" | "info" | "warn" | "error") {
                    return None;
                }
                self.output_args()
            }
            _ => None,
        }
    }

    fn output_args(&mut self) -> Option<()> {
        self.punct('(')?;
        if self.eat_punct(')') {
            return Some(());
        }
        loop {
            self.value()?;
            if self.eat_punct(')') {
                return Some(());
            }
            self.punct(',')?;
        }
    }

    /// `browser.tab('name')`, a handle to a tab already in the session.
    fn browser_tab(&mut self) -> Option<()> {
        self.keyword("browser")?;
        self.punct('.')?;
        self.keyword("tab")?;
        self.punct('(')?;
        if !self.eat_punct(')') {
            if self.string()?.is_empty() {
                return None;
            }
            self.punct(')')?;
        }
        self.browser_calls += 1;
        Some(())
    }

    /// `browser.open({...})` with a loopback `url` and presentation options.
    fn browser_open(&mut self) -> Option<()> {
        self.keyword("browser")?;
        self.punct('.')?;
        self.keyword("open")?;
        self.punct('(')?;
        self.punct('{')?;
        let mut seen = HashSet::new();
        let mut loopback = false;
        while !self.eat_punct('}') {
            let key = self.key()?;
            if !OPEN_KEYS.contains(&key.as_str()) || !seen.insert(key.clone()) {
                return None;
            }
            self.punct(':')?;
            match key.as_str() {
                "url" => loopback = loopback_url(&self.string()?),
                "viewport" => self.viewport()?,
                _ => self.scalar()?,
            }
            if !self.eat_punct(',') {
                self.punct('}')?;
                break;
            }
        }
        self.punct(')')?;
        self.browser_calls += 1;
        loopback.then_some(())
    }

    fn viewport(&mut self) -> Option<()> {
        self.punct('{')?;
        while !self.eat_punct('}') {
            if !matches!(
                self.key()?.as_str(),
                "width" | "height" | "deviceScaleFactor" | "isMobile" | "hasTouch"
            ) {
                return None;
            }
            self.punct(':')?;
            self.scalar()?;
            if !self.eat_punct(',') {
                return self.punct('}');
            }
        }
        Some(())
    }

    fn key(&mut self) -> Option<String> {
        match self.next()? {
            Token::Ident(name) | Token::Str(name) => Some(name),
            _ => None,
        }
    }

    /// A string, number, boolean or `null` literal.
    fn scalar(&mut self) -> Option<()> {
        self.eat_punct('-');
        match self.next()? {
            Token::Str(_) | Token::Num => Some(()),
            Token::Ident(word) if matches!(word.as_str(), "true" | "false" | "null") => Some(()),
            _ => None,
        }
    }

    /// An optional trailing options object of modeled scalar keys.
    fn options(&mut self) -> Option<()> {
        if self.peek() != Some(&Token::Punct('{')) {
            return Some(());
        }
        self.pos += 1;
        while !self.eat_punct('}') {
            if !OPTION_KEYS.contains(&self.key()?.as_str()) {
                return None;
            }
            self.punct(':')?;
            self.scalar()?;
            if !self.eat_punct(',') {
                return self.punct('}');
            }
        }
        Some(())
    }

    /// `TAB.method(args)` on a declared tab, after any `await`.
    fn tab_call(&mut self) -> Option<()> {
        let tab = self.ident()?;
        if !self.tabs.contains(&tab) {
            return None;
        }
        self.punct('.')?;
        let method = self.ident()?;
        self.punct('(')?;
        if self.eat_punct(')') {
            return NO_ARGUMENT_METHODS.contains(&method.as_str()).then_some(());
        }
        match method.as_str() {
            "title" | "url" | "close" => return None,
            "reload" | "observe" | "screenshot" | "errors" | "console" => {
                self.options()?;
            }
            "click" | "hover" | "text" => {
                self.string()?;
            }
            "press" | "waitForSelector" | "waitForText" => {
                self.string()?;
                if self.eat_punct(',') {
                    self.options()?;
                }
            }
            "waitFor" => {
                if matches!(self.peek(), Some(Token::Num)) {
                    self.pos += 1;
                } else {
                    self.string()?;
                    if self.eat_punct(',') {
                        self.options()?;
                    }
                }
            }
            "fill" | "type" => {
                self.string()?;
                self.punct(',')?;
                self.string()?;
            }
            "select" => {
                self.string()?;
                while self.eat_punct(',') {
                    self.string()?;
                }
            }
            "scroll" => {
                self.scalar()?;
                self.punct(',')?;
                self.scalar()?;
                if self.eat_punct(',') {
                    self.options()?;
                }
            }
            "goto" => {
                if !loopback_url(&self.string()?) {
                    return None;
                }
                if self.eat_punct(',') {
                    self.options()?;
                }
            }
            "evaluate" => {
                self.page_function()?;
                while self.eat_punct(',') {
                    self.literal()?;
                }
            }
            _ => return None,
        }
        self.punct(')')
    }

    /// The arrow function `evaluate` serializes into the page, with plain
    /// identifier parameters and a body that passes `page_token`. It must
    /// end at the argument, so it is passed rather than called in place.
    fn page_function(&mut self) -> Option<()> {
        if self.peek_ident("async") {
            self.pos += 1;
        }
        if self.eat_punct('(') {
            if !self.eat_punct(')') {
                loop {
                    let param = self.ident()?;
                    if RESERVED.contains(&param.as_str()) {
                        return None;
                    }
                    if self.eat_punct(')') {
                        break;
                    }
                    self.punct(',')?;
                }
            }
        } else if RESERVED.contains(&self.ident()?.as_str()) {
            return None;
        }
        self.punct('=')?;
        self.punct('>')?;
        let block = self.peek() == Some(&Token::Punct('{'));
        let mut stack: Vec<char> = Vec::new();
        loop {
            if self.pos >= self.tokens.len() || !page_token(&self.tokens, self.pos) {
                return None;
            }
            match self.peek()?.clone() {
                Token::Punct(',' | ')') if stack.is_empty() => break,
                Token::Punct(c @ ('(' | '[' | '{')) => {
                    stack.push(match c {
                        '(' => ')',
                        '[' => ']',
                        _ => '}',
                    });
                    if stack.len() > MAX_DEPTH * 4 {
                        return None;
                    }
                }
                Token::Punct(c @ (')' | ']' | '}')) => {
                    if stack.pop() != Some(c) {
                        return None;
                    }
                    self.pos += 1;
                    if block && stack.is_empty() {
                        // A block body ends at its brace; only the next
                        // argument or the call's close may follow.
                        return matches!(self.peek(), Some(Token::Punct(',' | ')'))).then_some(());
                    }
                    continue;
                }
                _ => {}
            }
            self.pos += 1;
        }
        Some(())
    }

    /// A literal argument handed to the page function.
    fn literal(&mut self) -> Option<()> {
        self.enter()?;
        match self.peek()? {
            Token::Punct('{') => {
                self.pos += 1;
                while !self.eat_punct('}') {
                    self.key()?;
                    self.punct(':')?;
                    self.literal()?;
                    if !self.eat_punct(',') {
                        self.punct('}')?;
                        break;
                    }
                }
            }
            Token::Punct('[') => {
                self.pos += 1;
                while !self.eat_punct(']') {
                    self.literal()?;
                    if !self.eat_punct(',') {
                        self.punct(']')?;
                        break;
                    }
                }
            }
            _ => self.scalar()?,
        }
        self.depth -= 1;
        Some(())
    }

    /// A displayed value: a literal, a declared name, an awaited tab call,
    /// or an object or array of those.
    fn value(&mut self) -> Option<()> {
        self.enter()?;
        match self.peek()?.clone() {
            Token::Punct('{') => {
                self.pos += 1;
                while !self.eat_punct('}') {
                    self.key()?;
                    self.punct(':')?;
                    self.value()?;
                    if !self.eat_punct(',') {
                        self.punct('}')?;
                        break;
                    }
                }
            }
            Token::Punct('[') => {
                self.pos += 1;
                while !self.eat_punct(']') {
                    self.value()?;
                    if !self.eat_punct(',') {
                        self.punct(']')?;
                        break;
                    }
                }
            }
            Token::Ident(word) if word == "await" => {
                self.pos += 1;
                self.tab_call()?;
            }
            Token::Ident(word) if self.values.contains(&word) => {
                self.pos += 1;
            }
            _ => self.scalar()?,
        }
        self.depth -= 1;
        Some(())
    }
}

/// Whether `code` is a JavaScript program that only drives the isolated
/// browser against loopback pages and displays what it reads.
pub(super) fn loopback_browser_program(code: &str) -> bool {
    if code.len() > MAX_CODE_BYTES {
        return false;
    }
    let Some(tokens) = tokenize(code) else {
        return false;
    };
    Parser {
        tokens,
        ..Parser::default()
    }
    .program()
    .is_some()
}

#[cfg(test)]
#[path = "generic_omp_eval_browser_tests.rs"]
mod tests;
