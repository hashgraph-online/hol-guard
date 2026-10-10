//! Literal-only parser for Oh My Pi's `eval` bridge.
//!
//! OMP's Codex-style code mode routes tool calls through one JavaScript
//! program, so the host hook sees only an opaque `eval`. This module accepts
//! a deliberately tiny language: statements built from `tool.read`,
//! `tool.grep`, `tool.glob` and `tool.bash` calls whose arguments are object
//! literals of scalar literals, or the SDK's `await read(literal_path)` helper,
//! plus `display`/`log`, `const`/`let` bindings,
//! `Promise.all`, `JSON.stringify`, and `.text`. Every extracted call is then
//! evaluated as the equivalent standalone tool; any non-allow reviews the
//! whole program. Everything else, including comments, templates with
//! interpolation, operators, other identifiers and non-`js` languages, is
//! rejected rather than interpreted.

use super::{strict_tool_input, OmpContext};
use crate::pretool::generic::extract::GenericSignals;
use crate::pretool::generic::result::{generic_action, generic_result};
use guard_contracts::{PreToolActionTypeV1, PreToolOperationV1, PreToolResultV1};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

const MAX_CODE_BYTES: usize = 16 * 1024;
const MAX_CALLS: usize = 24;
const MAX_DEPTH: usize = 12;

#[path = "generic_omp_eval_tokens.rs"]
mod tokens;
use tokens::{tokenize, Token};

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Lit {
    Str(String),
    Scalar(Value),
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct Call {
    pub(super) tool: String,
    pub(super) args: Vec<(String, Lit)>,
    sdk_read_helper: bool,
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    declared: HashSet<String>,
    calls: Vec<Call>,
}

const RESERVED: &[&str] = &[
    "read",
    "tool",
    "display",
    "log",
    "console",
    "Promise",
    "JSON",
    "await",
    "async",
    "const",
    "let",
    "var",
    "function",
    "class",
    "new",
    "this",
    "import",
    "require",
    "process",
    "eval",
    "Function",
    "globalThis",
    "window",
    "global",
    "fetch",
    "return",
    "if",
    "else",
    "for",
    "while",
    "do",
    "try",
    "catch",
    "throw",
    "delete",
    "typeof",
    "void",
    "yield",
    "with",
    "in",
    "instanceof",
    "of",
    "true",
    "false",
    "null",
    "undefined",
    "text",
    "constructor",
    "prototype",
    "__proto__",
];

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        token
    }

    fn eat(&mut self, punct: char) -> Option<()> {
        (self.next()? == Token::Punct(punct)).then_some(())
    }

    fn eat_ident(&mut self, name: &str) -> Option<()> {
        matches!(self.next()?, Token::Ident(ref ident) if ident == name).then_some(())
    }

    fn at(&self, punct: char) -> bool {
        self.peek() == Some(&Token::Punct(punct))
    }

    fn ident(&mut self) -> Option<String> {
        match self.next()? {
            Token::Ident(ident) => Some(ident),
            _ => None,
        }
    }

    fn program(&mut self) -> Option<()> {
        while self.peek().is_some() {
            if self.at(';') {
                self.pos += 1;
                continue;
            }
            self.statement()?;
            // A `(`, `[`, `.`, operator or (template) string after an
            // expression continues it even across a newline, so the host would
            // run a different program. Only `;`, the end, or a statement that
            // starts with a word (where JavaScript inserts the semicolon) may
            // follow.
            match self.peek() {
                None | Some(Token::Punct(';')) | Some(Token::Ident(_)) => {}
                Some(_) => return None,
            }
        }
        Some(())
    }

    fn binding_name(&mut self) -> Option<String> {
        let name = self.ident()?;
        (!RESERVED.contains(&name.as_str())).then_some(name)
    }

    fn statement(&mut self) -> Option<()> {
        match self.peek()? {
            Token::Ident(word) if word == "const" || word == "let" => {
                self.pos += 1;
                let mut names = Vec::new();
                if self.at('[') {
                    self.pos += 1;
                    while !self.at(']') {
                        names.push(self.binding_name()?);
                        if self.at(',') {
                            self.pos += 1;
                        } else {
                            break;
                        }
                    }
                    self.eat(']')?;
                } else {
                    names.push(self.binding_name()?);
                }
                self.eat('=')?;
                self.value(0)?;
                self.declared.extend(names);
                Some(())
            }
            Token::Ident(word) if word == "display" || word == "log" => {
                self.pos += 1;
                self.paren_value()
            }
            Token::Ident(word) if word == "console" => {
                self.pos += 1;
                self.eat('.')?;
                self.eat_ident("log")?;
                self.paren_value()
            }
            _ => self.value(0),
        }
    }

    fn paren_value(&mut self) -> Option<()> {
        self.eat('(')?;
        self.value(0)?;
        self.eat(')')
    }

    fn value(&mut self, depth: usize) -> Option<()> {
        if depth > MAX_DEPTH {
            return None;
        }
        match self.next()? {
            Token::Ident(word) => match word.as_str() {
                "await" => self.awaited(depth)?,
                "tool" => self.tool_call(depth)?,
                "Promise" => self.promise_all(depth)?,
                "JSON" => {
                    self.eat('.')?;
                    self.eat_ident("stringify")?;
                    self.eat('(')?;
                    self.value(depth + 1)?;
                    self.eat(')')?;
                }
                "true" | "false" | "null" => {}
                name if self.declared.contains(name) => {}
                _ => return None,
            },
            Token::Str(_) | Token::Num(_) => {}
            Token::Punct('(') => {
                self.value(depth + 1)?;
                self.eat(')')?;
            }
            Token::Punct('[') => {
                while !self.at(']') {
                    self.value(depth + 1)?;
                    if self.at(',') {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                self.eat(']')?;
            }
            Token::Punct('{') => self.display_object(depth)?,
            _ => return None,
        }
        // Only the `.text` accessor may follow a value.
        while self.at('.') {
            self.pos += 1;
            self.eat_ident("text")?;
        }
        Some(())
    }

    fn display_object(&mut self, depth: usize) -> Option<()> {
        while !self.at('}') {
            match self.next()? {
                Token::Ident(name) if self.at(',') || self.at('}') => {
                    if !self.declared.contains(&name) {
                        return None;
                    }
                }
                Token::Ident(_) | Token::Str(_) => {
                    self.eat(':')?;
                    self.value(depth + 1)?;
                }
                _ => return None,
            }
            if self.at(',') {
                self.pos += 1;
            } else {
                break;
            }
        }
        self.eat('}')
    }

    fn awaited(&mut self, depth: usize) -> Option<()> {
        match self.next()? {
            Token::Ident(word) if word == "tool" => self.tool_call(depth),
            Token::Ident(word) if word == "read" => self.read_helper(),
            Token::Ident(word) if word == "Promise" => self.promise_all(depth),
            Token::Punct('(') => {
                self.value(depth + 1)?;
                self.eat(')')
            }
            _ => None,
        }
    }

    fn read_helper(&mut self) -> Option<()> {
        self.eat('(')?;
        let Token::Str(path) = self.next()? else {
            return None;
        };
        // The SDK resolves raw filesystem paths against cwd. It does not
        // expand ~, parse line selectors, or normalize Windows separators.
        // Reject spellings the standalone tool would interpret differently.
        if path.starts_with('~')
            || path.contains("://")
            || path.contains(['\\', '$'])
            || path.trim() != path
            || path.chars().any(char::is_control)
            || self.calls.len() >= MAX_CALLS
        {
            return None;
        }
        self.eat(')')?;
        self.calls.push(Call {
            tool: "read".to_owned(),
            args: vec![("path".to_owned(), Lit::Str(path))],
            sdk_read_helper: true,
        });
        Some(())
    }

    fn promise_all(&mut self, depth: usize) -> Option<()> {
        self.eat('.')?;
        self.eat_ident("all")?;
        self.eat('(')?;
        self.value(depth + 1)?;
        self.eat(')')
    }

    fn tool_call(&mut self, _depth: usize) -> Option<()> {
        self.eat('.')?;
        let tool = self.ident()?;
        if !matches!(tool.as_str(), "read" | "grep" | "glob" | "bash") {
            return None;
        }
        self.eat('(')?;
        self.eat('{')?;
        let mut args: Vec<(String, Lit)> = Vec::new();
        while !self.at('}') {
            let key = match self.next()? {
                Token::Ident(key) | Token::Str(key) => key,
                _ => return None,
            };
            if args.iter().any(|(seen, _)| *seen == key) {
                return None;
            }
            self.eat(':')?;
            let lit = match self.next()? {
                Token::Str(text) => Lit::Str(text),
                Token::Num(number) => Lit::Scalar(number),
                Token::Ident(word) if word == "true" => Lit::Scalar(json!(true)),
                Token::Ident(word) if word == "false" => Lit::Scalar(json!(false)),
                _ => return None,
            };
            args.push((key, lit));
            if self.at(',') {
                self.pos += 1;
            } else {
                break;
            }
        }
        self.eat('}')?;
        self.eat(')')?;
        if self.calls.len() >= MAX_CALLS {
            return None;
        }
        self.calls.push(Call {
            tool,
            args,
            sdk_read_helper: false,
        });
        Some(())
    }
}

/// Parse a complete program into its ordered tool calls, or `None` when any
/// byte falls outside the grammar. At least one call is required.
pub(super) fn parse_program(code: &str) -> Option<Vec<Call>> {
    if code.len() > MAX_CODE_BYTES {
        return None;
    }
    let mut parser = Parser {
        tokens: tokenize(code)?,
        pos: 0,
        declared: HashSet::new(),
        calls: Vec::new(),
    };
    parser.program()?;
    (!parser.calls.is_empty()).then_some(parser.calls)
}

#[test]
fn literal_read_helper_is_parsed_as_one_read() {
    let calls = parse_program("display(await read('README.md'))").unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].tool, "read");
}

/// Map one literal call onto the equivalent standalone tool payload.
fn standalone_payload(call: &Call, context: &OmpContext<'_>) -> Option<Value> {
    let mut input = Map::new();
    for (key, lit) in &call.args {
        let allowed_string = match call.tool.as_str() {
            "read" => &["path"][..],
            "grep" => &["pattern", "path", "glob", "type"][..],
            "glob" => &["pattern", "path"][..],
            // The shell inherits the workspace; only an explicit `.` matches.
            _ => &["command", "cwd"][..],
        };
        match lit {
            Lit::Str(text) if allowed_string.contains(&key.as_str()) => {
                if call.sdk_read_helper && text.contains(':') {
                    let path = std::path::Path::new(text);
                    let candidate = if path.is_absolute() {
                        path.to_path_buf()
                    } else {
                        std::path::Path::new(context.path.cwd?).join(path)
                    };
                    // A colon can be a literal filename, but the SDK never
                    // strips read selectors. Prove that the exact file exists.
                    if !candidate.is_file() {
                        return None;
                    }
                }
                if call.tool == "bash" && key == "cwd" {
                    if text != "." {
                        return None;
                    }
                    continue;
                }
                input.insert(key.clone(), Value::String(text.clone()));
            }
            Lit::Str(_) => return None,
            // Only modeled options on read-only tools survive; the shell and
            // unknown options are reviewed rather than silently dropped.
            Lit::Scalar(value) if super::modeled_scalar(&call.tool, key, value) => {
                input.insert(key.clone(), value.clone());
            }
            Lit::Scalar(_) => return None,
        }
    }
    let required = match call.tool.as_str() {
        "read" => "path",
        "grep" => "pattern",
        "bash" => "command",
        _ => "",
    };
    if !required.is_empty() && !input.contains_key(required) {
        return None;
    }
    Some(json!({"tool_name": call.tool, "tool_input": Value::Object(input)}))
}

pub(super) fn evaluate(
    payload: &Value,
    signals: &GenericSignals,
    context: &OmpContext<'_>,
) -> Option<PreToolResultV1> {
    if !signals.path_values.is_empty() {
        return None;
    }
    let input = strict_tool_input(payload)?;
    if input.get("language")?.as_str()? != "js"
        || !input.iter().all(|(key, value)| match key.as_str() {
            "code" | "language" | "title" => value.is_string(),
            "reset" => value.is_boolean(),
            "timeout" => value.is_number(),
            _ => false,
        })
    {
        return None;
    }
    let calls = parse_program(input.get("code")?.as_str()?)?;
    let mut ran_shell = false;
    for call in &calls {
        let inner = standalone_payload(call, context)?;
        ran_shell |= call.tool == "bash";
        let result = crate::pretool::generic::evaluate_envelope(
            context.harness,
            context.event,
            &inner,
            context.controls,
            context.deadline,
            context.path,
            context.execution_environment,
            true,
        );
        if result.minimum_action != "allow" || result.action.sensitive_target {
            return None;
        }
    }
    let (action_type, operation) = if ran_shell {
        (PreToolActionTypeV1::Command, PreToolOperationV1::Execute)
    } else {
        (PreToolActionTypeV1::FileRead, PreToolOperationV1::Read)
    };
    Some(generic_result(
        generic_action(context.harness, context.event, action_type, operation, true, false),
        "allow",
        "native_omp_eval_bounded_tools",
        "The Rust authority parsed this eval as literal Oh My Pi tool calls and proved each one allowed on its own.",
    ))
}
