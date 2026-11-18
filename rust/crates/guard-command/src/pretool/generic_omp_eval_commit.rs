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
        // The body runs once per item, so each run counts toward the call
        // budget. An empty list runs nothing this grammar needs to answer for.
        let runs = match self.literal(0)? {
            Value::Array(items) if !items.is_empty() && items.iter().all(Value::is_string) => {
                items.len()
            }
            _ => return None,
        };
        self.eat(')')?;
        let fresh = self.loop_names.insert(name.clone());
        let before = self.calls.len();
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
        let per_run = self.calls.len() - before;
        if before + per_run.checked_mul(runs)? > MAX_CALLS {
            return None;
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
                if !options.get("agents").is_none_or(strings_literal) {
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
                let path_ok = args.first().is_none_or(strings_literal);
                (args.len() <= 2
                    && path_ok
                    && options_ok(args.get(1), &["units", "grep", "silent"]))
                .then_some(())?;
                self.push(repo.as_deref(), "git status --short")
            }
            "only" => {
                (args.len() <= 2
                    && args.first().is_some_and(strings_literal)
                    && options_ok(args.get(1), &["silent"]))
                .then_some(())?;
                self.push(repo.as_deref(), "git status --short")
            }
            // Both print file content, so they are judged as the diff they
            // read: a configured textconv or external diff program and the
            // content screens apply exactly as they do to a direct `git diff`.
            "show" | "diff" => {
                let path = match (method.as_str(), args.first()) {
                    ("show", Some(Value::String(path))) if plain_path(path) => Some(path.clone()),
                    ("show", _) => return None,
                    _ => None,
                };
                let rest = if path.is_some() {
                    &args[1..]
                } else {
                    &args[..]
                };
                (rest.len() <= 1 && options_ok(rest.first(), &["silent"])).then_some(())?;
                let command = match path {
                    Some(path) => format!("git diff HEAD -- {path}"),
                    None => "git diff HEAD".to_owned(),
                };
                self.push(repo.as_deref(), &command)
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

/// A string or a list of strings, the shape `agents`, `take`, `drop` and
/// `only` accept.
fn strings_literal(value: &Value) -> bool {
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
        && !climbs_after_descending(repo)
}

/// `scratch/../project`: the prelude normalizes the text before it opens the
/// repository, while the filesystem walks through `scratch`, so the two can
/// name different directories. Leading `..` climbs read the same both ways.
fn climbs_after_descending(path: &str) -> bool {
    let mut descended = false;
    path.split('/').any(|part| match part {
        "" | "." => false,
        ".." => descended,
        _ => {
            descended = true;
            false
        }
    })
}

/// A relative path made of plain name characters, safe to write unquoted.
fn plain_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with(['-', '/'])
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
        && !path.split('/').any(|part| part == "..")
}

/// Parse a program built only from the `commit` prelude and its
/// documentation read into the git commands it runs, or `None` when any
/// token falls outside that grammar.
pub(super) fn parse_commit_program(code: &str) -> Option<Vec<Call>> {
    if code.len() > MAX_CODE_BYTES {
        return None;
    }
    // The subject and body never reach the projected `git commit`, so text
    // holding a literal secret keeps the unknown-program review.
    if crate::pretool::literal_secrets::holds_literal_secret(code) {
        return None;
    }
    let lexed = tokenize_lines(code)?;
    // An empty program runs nothing the tool grammar would have answered for.
    if lexed.tokens.is_empty() {
        return None;
    }
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
