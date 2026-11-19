//! Oh My Pi's `commit` eval prelude: `await commit.draft(options)` and the
//! draft's `take`, `drop`, `only`, `show`, `diff` and `commit` methods.
//!
//! The prelude runs Git from the host process to attribute, select and commit
//! changed lines in one repository: the session's, or the checkout `repo`
//! names. It builds the commit from a private index and never touches the
//! worktree, but Git may still start configured programs (filters, an
//! fsmonitor, hooks, signing) the way `git add` and `git commit` do. Each
//! draft is recorded as one `commit` call, which the eval judges as that local
//! Git write in that repository.
//!
//! Every argument must be a literal. Options outside the documented ones,
//! including `amend`, keep the whole program reviewed, as does a draft method
//! on anything but a name bound to an awaited draft.

use super::super::tokens::{tokenize_lines, Token};
use super::{Call, Lit, Parser, MAX_CALLS, MAX_DEPTH};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

const DRAFT_METHODS: &[&str] = &["take", "drop", "only", "show", "diff", "commit"];

/// Whether the program would parse if the names it calls draft methods on
/// without binding them held drafts: a cell that reuses a draft an earlier
/// cell made. Guard reads each cell alone and cannot prove such a name still
/// holds that draft, so the cell stays reviewed; this only lets the review
/// name the one-cell form Guard can check.
pub(in super::super) fn uses_earlier_cell_draft(code: &str) -> bool {
    if code.len() > super::MAX_CODE_BYTES {
        return false;
    }
    let Some(lexed) = tokenize_lines(code) else {
        return false;
    };
    let tokens = &lexed.tokens;
    let ident = |index: usize| match tokens.get(index) {
        Some(Token::Ident(word)) => Some(word.as_str()),
        _ => None,
    };
    let bound: HashSet<&str> = (1..tokens.len())
        .filter(|&index| {
            matches!(
                ident(index - 1),
                Some("const" | "let" | "var" | "function" | "class")
            )
        })
        .filter_map(ident)
        .collect();
    let carried: HashSet<String> = (0..tokens.len())
        .filter(|&index| {
            (index == 0 || tokens[index - 1] != Token::Punct('.'))
                && tokens.get(index + 1) == Some(&Token::Punct('.'))
                && ident(index + 2).is_some_and(|method| DRAFT_METHODS.contains(&method))
        })
        .filter_map(ident)
        .filter(|name| !bound.contains(name) && *name != "commit")
        .map(str::to_owned)
        .collect();
    if carried.is_empty() {
        return false;
    }
    let mut parser = Parser {
        tokens: lexed.tokens,
        breaks: lexed.breaks,
        raw_templates: lexed.raw_templates,
        pos: 0,
        declared: carried.clone(),
        drafts: carried,
        calls: Vec::new(),
    };
    parser.program().is_some()
}

impl Parser {
    /// Whether `await commit.draft` starts at the cursor.
    pub(super) fn draft_ahead(&self) -> bool {
        let word = |offset: usize, name: &str| matches!(self.tokens.get(self.pos + offset), Some(Token::Ident(ident)) if ident == name);
        word(0, "await")
            && word(1, "commit")
            && self.tokens.get(self.pos + 2) == Some(&Token::Punct('.'))
            && word(3, "draft")
    }

    /// `.draft(options?)` after `commit`, recorded as one `commit` call.
    pub(super) fn commit_draft(&mut self) -> Option<()> {
        self.eat('.')?;
        self.eat_ident("draft")?;
        let args = self.literal_args()?;
        let mut call_args = Vec::new();
        match args.as_slice() {
            [] => {}
            [Value::Object(options)] => {
                for (key, value) in options {
                    match (key.as_str(), value) {
                        ("agents", value) if strings(value) => {}
                        ("silent", Value::Bool(_)) => {}
                        ("repo", Value::String(repo)) if !repo.is_empty() => {
                            call_args.push(("cwd".to_owned(), Lit::Str(repo.clone())));
                        }
                        _ => return None,
                    }
                }
            }
            _ => return None,
        }
        if self.calls.len() >= MAX_CALLS {
            return None;
        }
        self.calls.push(Call {
            tool: "commit".to_owned(),
            args: call_args,
            sdk_read_helper: false,
            shell_helper: false,
        });
        Some(())
    }

    /// A name bound to a draft: shown as is, one of its fields, one of its
    /// methods called with literal arguments, or a method itself, uncalled or
    /// shown with `toString()`. The draft's repository is already recorded.
    pub(super) fn draft_use(&mut self) -> Option<()> {
        if !self.at('.') {
            return Some(());
        }
        self.pos += 1;
        let method = self.ident()?;
        if !self.at('(') {
            return self.draft_member(&method);
        }
        let args = self.literal_args()?;
        let silent = |value: &Value| object_keys(value, &["silent"]);
        let selection = |value: &Value| object_keys(value, &["units", "grep", "silent"]);
        let valid = match (method.as_str(), args.as_slice()) {
            ("take" | "drop", []) => true,
            ("take" | "drop", [path]) => strings(path),
            ("take" | "drop", [path, options]) => {
                (strings(path) || path.is_null()) && selection(options)
            }
            ("only", [globs]) => strings(globs),
            ("only", [globs, options]) => strings(globs) && silent(options),
            ("show", []) => true,
            ("show", [path]) => plain_paths(path),
            ("show", [path, options]) => (plain_paths(path) || path.is_null()) && silent(options),
            ("diff", []) => true,
            ("diff", [options]) => silent(options),
            ("commit", [Value::String(subject)]) => !subject.trim().is_empty(),
            ("commit", [Value::String(subject), options]) => {
                !subject.trim().is_empty() && commit_options(options)
            }
            ("commit", [Value::Object(options)]) => subject_in_options(options),
            _ => false,
        };
        valid.then_some(())
    }

    /// `draft.id`, `draft.details` and `draft.text` are plain fields the
    /// prelude sets. A method named without a call is taken only as its
    /// source text through `toString()`, never as a value: placed under
    /// `then` or `toJSON`, the host would call it with arguments no literal
    /// check saw. `typeof draft.method` is read before this.
    fn draft_member(&mut self, name: &str) -> Option<()> {
        match name {
            "id" | "details" | "text" => Some(()),
            name if DRAFT_METHODS.contains(&name) => {
                self.eat('.')?;
                self.eat_ident("toString")?;
                self.eat('(')?;
                self.eat(')')
            }
            _ => None,
        }
    }

    /// `typeof draft.method`, which names the method without reading it as
    /// a value anything could call.
    pub(super) fn typeof_draft_method(&mut self) -> bool {
        let ident = |offset: usize| match self.tokens.get(self.pos + offset) {
            Some(Token::Ident(ident)) => Some(ident.as_str()),
            _ => None,
        };
        let found = ident(0).is_some_and(|name| self.drafts.contains(name))
            && self.tokens.get(self.pos + 1) == Some(&Token::Punct('.'))
            && ident(2).is_some_and(|name| DRAFT_METHODS.contains(&name))
            && !matches!(
                self.tokens.get(self.pos + 3),
                Some(Token::Punct('(' | '.' | '['))
            );
        if found {
            self.pos += 3;
        }
        found
    }

    /// `(literal, ...)`: strings, numbers, booleans, `null`, and arrays and
    /// objects of them. Identifiers, calls and computed keys are rejected.
    fn literal_args(&mut self) -> Option<Vec<Value>> {
        self.eat('(')?;
        let mut args = Vec::new();
        while !self.at(')') {
            args.push(self.literal(0)?);
            if self.at(',') {
                self.pos += 1;
            } else {
                break;
            }
        }
        self.eat(')')?;
        Some(args)
    }

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
                let mut fields = Map::new();
                while !self.at('}') {
                    let key = match self.next()? {
                        Token::Ident(key) | Token::Str(key) => key,
                        _ => return None,
                    };
                    self.eat(':')?;
                    let value = self.literal(depth + 1)?;
                    if fields.insert(key, value).is_some() {
                        return None;
                    }
                    if self.at(',') {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                self.eat('}')?;
                Some(Value::Object(fields))
            }
            _ => None,
        }
    }
}

/// A `show` path, or an array of them, that names no file Guard keeps out of
/// a plain read. `show(path)` prints the draft's hunks for exactly that path,
/// the read `git diff HEAD -- <path>` performs, and Guard reviews that command
/// when the path names a secret. The prelude's own route follows it, so the
/// same spelling cannot answer through `eval` what it is refused through
/// `bash`. `take`, `drop` and `only` select what the commit carries rather
/// than printing a file, and `show()` with no path is the draft's own summary,
/// so neither is read through this check.
fn plain_paths(value: &Value) -> bool {
    strings(value) && !names_sensitive(value)
}

/// Whether `value` names a sensitive read target, directly or in an array.
fn names_sensitive(value: &Value) -> bool {
    match value {
        Value::String(path) => crate::pretool::sensitive_read_path_argument(path),
        Value::Array(items) => items.iter().any(names_sensitive),
        _ => false,
    }
}

/// A string, or an array of strings.
fn strings(value: &Value) -> bool {
    match value {
        Value::String(_) => true,
        Value::Array(items) => items.iter().all(Value::is_string),
        _ => false,
    }
}

/// An options object whose keys are all in `allowed`, each with the type the
/// prelude expects.
fn object_keys(value: &Value, allowed: &[&str]) -> bool {
    let Value::Object(options) = value else {
        return false;
    };
    options.iter().all(|(key, value)| {
        allowed.contains(&key.as_str())
            && match key.as_str() {
                "silent" => value.is_boolean(),
                "grep" => value.is_string(),
                "units" => value.as_array().is_some_and(|units| {
                    units
                        .iter()
                        .all(|unit| unit.is_string() || unit.is_number())
                }),
                _ => false,
            }
    })
}

/// `commit({subject, body, ...})`: the subject passed inside the options
/// instead of first. Oh My Pi rejects a subject that is not a non-empty string
/// before Git runs, so the call commits nothing, but the eval is still judged
/// as the draft's commit. The keys are the ones `commit(subject, options)`
/// takes, plus `subject`; `amend` keeps its review.
fn subject_in_options(options: &Map<String, Value>) -> bool {
    let subject = options.get("subject");
    let rest: Map<String, Value> = options
        .iter()
        .filter(|(key, _)| key.as_str() != "subject")
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    subject.is_none_or(|subject| subject.as_str().is_some_and(|text| !text.trim().is_empty()))
        && commit_options(&Value::Object(rest))
}

/// `commit(subject, options)`: a body as a string or lines, `fixes`,
/// `noVerify` (which only skips hooks) and `silent`. A string or an array in
/// the options place carries no option at all: the prelude throws on it
/// before Git runs. `amend` rewrites an earlier commit and keeps its review.
fn commit_options(value: &Value) -> bool {
    match value {
        Value::String(_) => true,
        Value::Array(lines) => lines.iter().all(Value::is_string),
        Value::Object(options) => options.iter().all(|(key, value)| match key.as_str() {
            "body" => strings(value),
            "fixes" => match value {
                Value::Array(items) => items
                    .iter()
                    .all(|item| item.is_string() || item.is_number()),
                other => other.is_string() || other.is_number(),
            },
            "noVerify" | "silent" => value.is_boolean(),
            _ => false,
        }),
        _ => false,
    }
}
