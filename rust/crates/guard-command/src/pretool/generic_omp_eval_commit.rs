//! Oh My Pi's `commit` eval prelude.
//!
//! Oh My Pi 18.22 commits through `commit.draft()` inside `eval`: the draft
//! reads the repository's changes, `take`/`drop`/`only` narrow the
//! selection, and `commit` writes it. The prelude call raises no tool hook of
//! its own, so the eval is the only call Guard sees. This module accepts only
//! programs made of those helpers with literal arguments, plus `read` of the
//! prelude's own `xd://eval/<name>` documentation, and maps each draft onto
//! the git command it performs: `git status --short` for drafting and
//! narrowing, `git add -A && git commit` for the commit, in the draft's
//! repository. Each mapped command is then judged like a direct `bash` call.
//! `git add -A` covers every selection a draft can make, so the judged
//! command never stages less than the helper could.

use super::parser::{Call, Lit};
use super::tokens::{tokenize_lines, Token};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};

const MAX_CODE_BYTES: usize = 16 * 1024;
const MAX_CALLS: usize = 24;
const MAX_DEPTH: usize = 6;

struct Parser {
    tokens: Vec<Token>,
    breaks: Vec<bool>,
    pos: usize,
    /// Draft bindings declared in this program, with their repository.
    drafts: HashMap<String, Option<String>>,
    /// Names bound by a `for (const p of [...])` over literal strings.
    loop_names: HashSet<String>,
    calls: Vec<Call>,
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

    fn at(&self, punct: char) -> bool {
        self.peek() == Some(&Token::Punct(punct))
    }

    fn at_ident(&self, name: &str) -> bool {
        matches!(self.peek(), Some(Token::Ident(word)) if word == name)
    }

    fn eat(&mut self, punct: char) -> Option<()> {
        (self.next()? == Token::Punct(punct)).then_some(())
    }

    fn eat_ident(&mut self, name: &str) -> Option<()> {
        matches!(self.next()?, Token::Ident(ref word) if word == name).then_some(())
    }

    fn ident(&mut self) -> Option<String> {
        match self.next()? {
            Token::Ident(word) => Some(word),
            _ => None,
        }
    }

    fn skip_semicolons(&mut self) {
        while self.at(';') {
            self.pos += 1;
        }
    }

    fn program(&mut self) -> Option<()> {
        loop {
            self.skip_semicolons();
            if self.peek().is_none() {
                return Some(());
            }
            self.statement()?;
            match self.peek() {
                None | Some(Token::Punct(';')) | Some(Token::Ident(_)) => {}
                Some(_) => return None,
            }
        }
    }

    fn statement(&mut self) -> Option<()> {
        match self.peek()? {
            Token::Ident(word) if word == "const" || word == "let" => {
                self.pos += 1;
                let name = self.ident()?;
                if super::parser::is_reserved(&name)
                    || self.drafts.contains_key(&name)
                    || self.loop_names.contains(&name)
                {
                    return None;
                }
                self.eat('=')?;
                if self.at_ident("await") {
                    self.pos += 1;
                }
                self.eat_ident("commit")?;
                let repo = self.draft_call()?;
                self.drafts.insert(name, repo);
                Some(())
            }
            Token::Ident(word) if word == "return" => {
                self.pos += 1;
                if self.breaks.get(self.pos).copied().unwrap_or(true) {
                    return None;
                }
                self.expression(0)?;
                self.tokens[self.pos..]
                    .iter()
                    .all(|token| matches!(token, Token::Punct(';')))
                    .then_some(())
            }
            Token::Ident(word) if word == "for" => self.for_loop(),
            _ => self.expression(0),
        }
    }

    /// `for (const p of ["a", "b"]) await d.take(p);` over literal strings.
    fn for_loop(&mut self) -> Option<()> {
        self.pos += 1;
        self.eat('(')?;
        if !(self.at_ident("const") || self.at_ident("let")) {
            return None;
        }
        self.pos += 1;
        let name = self.ident()?;
        if super::parser::is_reserved(&name) || self.drafts.contains_key(&name) {
            return None;
        }
        self.eat_ident("of")?;
        match self.literal(0)? {
            Value::Array(items) if items.iter().all(Value::is_string) => {}
            _ => return None,
        }
        self.eat(')')?;
        let fresh = self.loop_names.insert(name.clone());
        let body = if self.at('{') {
            self.pos += 1;
            loop {
                self.skip_semicolons();
                if self.at('}') {
                    break Some(());
                }
                if self.expression(0).is_none() {
                    break None;
                }
            }
            .and_then(|()| self.eat('}'))
        } else {
            self.expression(0)
        };
        if fresh {
            self.loop_names.remove(&name);
        }
        body
    }

    /// Output calls, awaits, parentheses, draft methods and the prelude's own
    /// documentation read.
    fn expression(&mut self, depth: usize) -> Option<()> {
        if depth > MAX_DEPTH {
            return None;
        }
        match self.next()? {
            Token::Ident(word) => match word.as_str() {
                "await" => self.expression(depth + 1),
                "print" | "display" | "log" => self.output(depth),
                "console" => {
                    self.eat('.')?;
                    self.eat_ident("log")?;
                    self.output(depth)
                }
                "commit" => self.draft_call().map(|_| ()),
                "read" => self.documentation_read(),
                name => {
                    let repo = self.drafts.get(name)?.clone();
                    if self.at('.') {
                        self.draft_method(repo)
                    } else {
                        Some(())
                    }
                }
            },
            Token::Punct('(') => {
                self.expression(depth + 1)?;
                self.eat(')')
            }
            _ => None,
        }
    }

    fn output(&mut self, depth: usize) -> Option<()> {
        self.eat('(')?;
        self.expression(depth + 1)?;
        self.eat(')')
    }

    /// `read("xd://eval/<name>")`: the prelude's own documentation page.
    fn documentation_read(&mut self) -> Option<()> {
        self.eat('(')?;
        let Token::Str(url) = self.next()? else {
            return None;
        };
        let name = url.strip_prefix("xd://eval/")?;
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c == '-')
        {
            return None;
        }
        self.eat(')')
    }

    /// `.draft({ agents, repo })` after `commit`: the draft's repository.
    fn draft_call(&mut self) -> Option<Option<String>> {
        self.eat('.')?;
        self.eat_ident("draft")?;
        let args = self.arguments()?;
        let repo = match args.as_slice() {
            [] => None,
            [Value::Object(options)] => {
                if !options
                    .keys()
                    .all(|key| matches!(key.as_str(), "agents" | "repo" | "silent"))
                {
                    return None;
                }
                if !options.get("agents").is_none_or(agents_literal) {
                    return None;
                }
                match options.get("repo") {
                    None => None,
                    Some(Value::String(repo)) if repository_literal(repo) => Some(repo.clone()),
                    Some(_) => return None,
                }
            }
            _ => return None,
        };
        self.push(repo.as_deref(), "git status --short")?;
        Some(repo)
    }

    fn draft_method(&mut self, repo: Option<String>) -> Option<()> {
        self.eat('.')?;
        let method = self.ident()?;
        let args = self.arguments()?;
        let options_ok = |value: Option<&Value>, allowed: &[&str]| match value {
            None => true,
            Some(Value::Object(options)) => {
                options.keys().all(|key| allowed.contains(&key.as_str()))
            }
            Some(_) => false,
        };
        match method.as_str() {
            "take" | "drop" => {
                let path_ok = args.first().is_none_or(paths_literal);
                (args.len() <= 2
                    && path_ok
                    && options_ok(args.get(1), &["units", "grep", "silent"]))
                .then_some(())?;
                self.push(repo.as_deref(), "git status --short")
            }
            "only" => {
                (args.len() <= 2
                    && args.first().is_some_and(paths_literal)
                    && options_ok(args.get(1), &["silent"]))
                .then_some(())?;
                self.push(repo.as_deref(), "git status --short")
            }
            "show" | "diff" => {
                let path_ok = method == "show" && args.first().is_some_and(Value::is_string);
                let rest = if path_ok { &args[1..] } else { &args[..] };
                (rest.len() <= 1 && options_ok(rest.first(), &["silent"])).then_some(())?;
                self.push(repo.as_deref(), "git status --short")
            }
            "commit" => {
                let subject = args.first()?.as_str()?;
                if subject.trim().is_empty() || args.len() > 2 {
                    return None;
                }
                let mut command = String::from("git add -A && git commit -q -m commit");
                match args.get(1) {
                    None | Some(Value::Array(_)) => {}
                    Some(Value::Object(options)) => {
                        for (key, value) in options {
                            match (key.as_str(), value) {
                                ("body" | "fixes" | "silent", _) => {}
                                ("amend", Value::Bool(true)) => command.push_str(" --amend"),
                                ("noVerify", Value::Bool(true)) => command.push_str(" --no-verify"),
                                ("amend" | "noVerify", Value::Bool(false) | Value::Null) => {}
                                _ => return None,
                            }
                        }
                    }
                    Some(_) => return None,
                }
                self.push(repo.as_deref(), &command)
            }
            _ => None,
        }
    }

    /// A parenthesized list of literal arguments.
    fn arguments(&mut self) -> Option<Vec<Value>> {
        self.eat('(')?;
        let mut values = Vec::new();
        while !self.at(')') {
            values.push(self.literal(0)?);
            if self.at(',') {
                self.pos += 1;
            } else {
                break;
            }
        }
        self.eat(')')?;
        Some(values)
    }

    /// Strings, numbers, booleans, `null`, arrays and objects of those, and a
    /// loop name over literal strings, which reads as a string.
    fn literal(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_DEPTH {
            return None;
        }
        match self.next()? {
            Token::Str(text) => Some(Value::String(text)),
            Token::Num(number) => Some(number),
            Token::Ident(word) => match word.as_str() {
                "true" => Some(json!(true)),
                "false" => Some(json!(false)),
                "null" => Some(Value::Null),
                name if self.loop_names.contains(name) => Some(Value::String(String::new())),
                _ => None,
            },
            Token::Punct('[') => {
                let mut items = Vec::new();
                while !self.at(']') {
                    items.push(self.literal(depth + 1)?);
                    if self.at(',') {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                self.eat(']')?;
                Some(Value::Array(items))
            }
            Token::Punct('{') => {
                let mut object = Map::new();
                while !self.at('}') {
                    let key = match self.next()? {
                        Token::Ident(key) | Token::Str(key) => key,
                        _ => return None,
                    };
                    self.eat(':')?;
                    let value = self.literal(depth + 1)?;
                    if object.insert(key, value).is_some() {
                        return None;
                    }
                    if self.at(',') {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                self.eat('}')?;
                Some(Value::Object(object))
            }
            _ => None,
        }
    }

    fn push(&mut self, repo: Option<&str>, command: &str) -> Option<()> {
        if self.calls.len() >= MAX_CALLS {
            return None;
        }
        let mut args = vec![("command".to_owned(), Lit::Str(command.to_owned()))];
        if let Some(repo) = repo {
            args.push(("cwd".to_owned(), Lit::Str(repo.to_owned())));
        }
        self.calls.push(Call {
            tool: "bash".to_owned(),
            args,
            sdk_read_helper: false,
            // The prelude runs git itself; no `bash` hook fires for it.
            shell_helper: true,
        });
        Some(())
    }
}

fn agents_literal(value: &Value) -> bool {
    match value {
        Value::String(_) => true,
        Value::Array(items) => items.iter().all(Value::is_string),
        _ => false,
    }
}

fn paths_literal(value: &Value) -> bool {
    match value {
        Value::String(_) => true,
        Value::Array(items) => items.iter().all(Value::is_string),
        _ => false,
    }
}

/// A repository the prelude resolves against the session directory the way
/// the `bash` tool resolves its `cwd`. Spellings that tool would read
/// differently are rejected.
fn repository_literal(repo: &str) -> bool {
    !repo.is_empty()
        && !repo.starts_with('~')
        && !repo.contains("://")
        && !repo.contains(['\\', '$'])
        && repo.trim() == repo
        && !repo.chars().any(char::is_control)
}

/// Parse a program built only from the `commit` prelude and its
/// documentation read into the git commands it runs, or `None` when any
/// token falls outside that grammar.
pub(super) fn parse_commit_program(code: &str) -> Option<Vec<Call>> {
    if code.len() > MAX_CODE_BYTES {
        return None;
    }
    let lexed = tokenize_lines(code)?;
    let mut parser = Parser {
        tokens: lexed.tokens,
        breaks: lexed.breaks,
        pos: 0,
        drafts: HashMap::new(),
        loop_names: HashSet::new(),
        calls: Vec::new(),
    };
    parser.program()?;
    Some(parser.calls)
}

#[cfg(test)]
#[path = "generic_omp_eval_commit_tests.rs"]
mod tests;
