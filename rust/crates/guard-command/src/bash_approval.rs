//! Bounded, non-executing Bash analysis for a frozen launch.
//!
//! This produces reachable argv and redirections, not permission. The resident
//! must resolve every command, judge current policy and bind actual execution
//! before using the result. Unknown shell syntax is never a partial success.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tree_sitter::{Node, ParseOptions, Parser};

mod commands;
mod descriptor_context;
pub use descriptor_context::is_descriptor_reference;
pub mod curl_startup;
pub mod delivery;
pub mod graph;
mod source;
pub mod subject;
#[cfg(test)]
mod tests;
mod words;

pub const MAX_SOURCE_BYTES: usize = 1024 * 1024;
const MAX_OPERATIONS: usize = 1024;
const MAX_LOOP_VALUES: usize = 64;
const MAX_DEPTH: usize = 64;
const MAX_WORD_BYTES: usize = 32 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub argv: Vec<String>,
    pub line: usize,
    pub command_start: usize,
    pub command_end: usize,
    #[serde(default)]
    pub pipeline_input: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Redirect {
    pub path: String,
    pub append: bool,
    pub line: usize,
    pub start: usize,
    pub end: usize,
    pub statement_start: usize,
    #[serde(skip)]
    pub(crate) top_level: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Analysis {
    pub operations: Vec<Operation>,
    pub writes: Vec<Redirect>,
    // Only the in-process graph builder receives captured source bodies.
    #[serde(skip)]
    sources: Vec<source::Occurrence>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Uncertainty {
    pub reason: &'static str,
    pub line: usize,
}

type Result<T> = std::result::Result<T, Uncertainty>;

/// Arguments include the original script path at index zero, as Bash sees it.
/// Environment must be the resident's selected launch environment. No lookup
/// falls back to the evaluator process's environment or filesystem.
pub fn analyze(
    source: &str,
    argv: &[String],
    environment: &BTreeMap<String, String>,
) -> Result<Analysis> {
    analyze_before(
        source,
        argv,
        environment,
        Instant::now() + Duration::from_millis(100),
    )
}

/// A graph shares one resident-owned deadline across its entry and helpers.
pub fn analyze_before(
    source: &str,
    argv: &[String],
    environment: &BTreeMap<String, String>,
    deadline: Instant,
) -> Result<Analysis> {
    analyze_inner(source, argv, environment, deadline, None)
}

fn analyze_inner(
    source: &str,
    argv: &[String],
    environment: &BTreeMap<String, String>,
    deadline: Instant,
    source_context: Option<source::Context<'_>>,
) -> Result<Analysis> {
    let names = source_context
        .as_ref()
        .map(source::Context::environment_names)
        .unwrap_or(&[]);
    if names.len() > 4096 || names.iter().map(String::len).sum::<usize>() > MAX_SOURCE_BYTES {
        return Err(Uncertainty {
            reason: "bash_environment_bounds",
            line: 1,
        });
    }
    let context_bytes = argv.iter().map(String::len).sum::<usize>()
        + environment
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum::<usize>();
    if source.len() > MAX_SOURCE_BYTES
        || source.contains('\0')
        || argv.is_empty()
        || argv.len() > 256
        || argv.iter().any(|value| value.len() > MAX_WORD_BYTES)
        || environment
            .values()
            .any(|value| value.len() > MAX_WORD_BYTES)
        || context_bytes > MAX_SOURCE_BYTES
    {
        return Err(Uncertainty {
            reason: "bash_input_bounds",
            line: 1,
        });
    }
    if Instant::now() >= deadline {
        return Err(Uncertainty {
            reason: "bash_analysis_timeout",
            line: 1,
        });
    }
    let exported_names: BTreeSet<String> = environment
        .keys()
        .cloned()
        .chain(names.iter().cloned())
        .collect();
    if exported_names.iter().any(|key| {
        key.starts_with("BASH_FUNC_")
            || key.starts_with("__BASH_FUNC")
            || matches!(
                key.as_str(),
                "BASH_ENV" | "ENV" | "SHELLOPTS" | "BASHOPTS" | "POSIXLY_CORRECT"
            )
    }) || environment
        .values()
        .any(|value| value.trim_start().starts_with("()"))
    {
        return Err(Uncertainty {
            reason: "bash_startup_inputs_unbound",
            line: 1,
        });
    }
    let tree = parse(source, deadline)?;
    let mut state = State {
        source,
        argv,
        variables: environment.clone(),
        analysis: Analysis::default(),
        stopped: false,
        deadline,
        steps: 0,
        expanded_bytes: 0,
        total_effects: 0,
        source_context,
        exported_names: &exported_names,
        pipeline_input: false,
    };
    state.walk(tree.root_node(), 0)?;
    Ok(state.analysis)
}

fn parse(source: &str, deadline: Instant) -> Result<tree_sitter::Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .map_err(|_| Uncertainty {
            reason: "bash_parser_unavailable",
            line: 1,
        })?;
    let mut read = |offset, _| source.as_bytes().get(offset..).unwrap_or_default();
    let mut cancelled = |_: &tree_sitter::ParseState| Instant::now() >= deadline;
    let options = ParseOptions::new().progress_callback(&mut cancelled);
    let tree = parser
        .parse_with_options(&mut read, None, Some(options))
        .ok_or(Uncertainty {
            reason: "bash_parse_incomplete",
            line: 1,
        })?;
    if tree.root_node().has_error() {
        return Err(Uncertainty {
            reason: "bash_syntax_error",
            line: 1,
        });
    }
    Ok(tree)
}

struct State<'a, 'context> {
    source: &'a str,
    argv: &'a [String],
    variables: BTreeMap<String, String>,
    analysis: Analysis,
    stopped: bool,
    deadline: Instant,
    steps: usize,
    expanded_bytes: usize,
    total_effects: usize,
    source_context: Option<source::Context<'context>>,
    exported_names: &'context BTreeSet<String>,
    pipeline_input: bool,
}

impl State<'_, '_> {
    fn text(&self, node: Node<'_>) -> &str {
        &self.source[node.byte_range()]
    }

    fn error(&self, node: Node<'_>, reason: &'static str) -> Uncertainty {
        Uncertainty {
            reason,
            line: node.start_position().row + 1,
        }
    }

    fn field<'a>(&self, node: Node<'a>, name: &str) -> Result<Node<'a>> {
        node.child_by_field_name(name)
            .ok_or_else(|| self.error(node, "bash_missing_field"))
    }

    fn walk(&mut self, node: Node<'_>, depth: usize) -> Result<()> {
        self.steps += 1;
        if Instant::now() >= self.deadline {
            return Err(self.error(node, "bash_analysis_timeout"));
        }
        if self.steps > 4096
            || depth > MAX_DEPTH
            || self.analysis.operations.len() + self.analysis.writes.len() > MAX_OPERATIONS
        {
            return Err(self.error(node, "bash_analysis_bounds"));
        }
        if self.stopped {
            return Ok(());
        }
        match node.kind() {
            "comment" => Ok(()),
            "program" | "do_group" => {
                for index in 0..node.child_count() {
                    let child = node.child(index).unwrap();
                    if !child.is_named() && !matches!(child.kind(), ";" | "do" | "done") {
                        return Err(self.error(child, "bash_control_operator"));
                    }
                }
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    self.walk(child, depth + 1)?;
                }
                Ok(())
            }
            "variable_assignment" => {
                let name = self.field(node, "name")?;
                if name.kind() != "variable_name" || !words::ordinary_variable(self.text(name)) {
                    return Err(self.error(name, "bash_special_assignment"));
                }
                if self.exported_names.contains(self.text(name)) {
                    return Err(self.error(name, "bash_exported_environment_assignment_unproven"));
                }
                let value_node = self.field(node, "value")?;
                if &self.source[name.end_byte()..value_node.start_byte()] != "=" {
                    return Err(self.error(node, "bash_assignment_operator"));
                }
                let value = self.word(value_node, true)?;
                self.charge(value.len(), value_node)?;
                self.variables.insert(self.text(name).to_owned(), value);
                Ok(())
            }
            "command" => self.command(node, depth),
            "case_statement" => self.case(node, depth),
            "for_statement" => self.for_loop(node, depth),
            "redirected_statement" => {
                let body = self.field(node, "body")?;
                let mut cursor = node.walk();
                for redirect in node.children_by_field_name("redirect", &mut cursor) {
                    self.redirect(redirect, node.start_byte())?;
                }
                self.walk(body, depth + 1)
            }
            "pipeline" => {
                for index in 0..node.child_count() {
                    let child = node.child(index).unwrap();
                    if !child.is_named() && child.kind() != "|" {
                        return Err(self.error(child, "bash_pipeline_operator"));
                    }
                }
                // Bash runs pipeline members in subshell environments. A
                // declaration inside one must not authorize a following line.
                let mut cursor = node.walk();
                let previous_input = self.pipeline_input;
                for (index, child) in node.named_children(&mut cursor).enumerate() {
                    let variables = self.variables.clone();
                    self.pipeline_input = index > 0;
                    self.walk(child, depth + 1)?;
                    self.variables = variables;
                    self.stopped = false;
                }
                self.pipeline_input = previous_input;
                Ok(())
            }
            _ => Err(self.error(node, "bash_unsupported_statement")),
        }
    }

    fn for_loop(&mut self, node: Node<'_>, depth: usize) -> Result<()> {
        let variable = self.field(node, "variable")?;
        if !words::ordinary_variable(self.text(variable)) {
            return Err(self.error(variable, "bash_special_assignment"));
        }
        if self.exported_names.contains(self.text(variable)) {
            return Err(self.error(variable, "bash_exported_environment_assignment_unproven"));
        }
        let mut cursor = node.walk();
        let mut values = Vec::new();
        for value in node.children_by_field_name("value", &mut cursor) {
            if values.len() >= MAX_LOOP_VALUES {
                return Err(self.error(value, "bash_loop_bounds"));
            }
            let expanded = self.word(value, false)?;
            self.charge(expanded.len(), value)?;
            values.push(expanded);
        }
        if values.is_empty() || values.len() > MAX_LOOP_VALUES {
            return Err(self.error(node, "bash_loop_bounds"));
        }
        let body = self.field(node, "body")?;
        for value in values {
            self.variables.insert(self.text(variable).to_owned(), value);
            self.walk(body, depth + 1)?;
            if self.stopped {
                break;
            }
        }
        Ok(())
    }

    fn case(&mut self, node: Node<'_>, depth: usize) -> Result<()> {
        let value = self.word(self.field(node, "value")?, true)?;
        let mut cursor = node.walk();
        for item in node
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "case_item")
        {
            for index in 0..item.child_count() {
                let child = item.child(index).unwrap();
                if !child.is_named() && !matches!(child.kind(), ")" | "(" | "|" | ";;" | ";") {
                    return Err(self.error(child, "bash_control_operator"));
                }
            }
            if item.child_by_field_name("fallthrough").is_some() {
                return Err(self.error(item, "bash_case_fallthrough"));
            }
            let mut patterns_cursor = item.walk();
            let mut selected = false;
            for pattern in item.children_by_field_name("value", &mut patterns_cursor) {
                let raw = self.text(pattern);
                selected |= if raw == "*" {
                    true
                } else {
                    self.word(pattern, false)? == value
                };
            }
            if selected {
                let mut body_cursor = item.walk();
                for child in item.named_children(&mut body_cursor) {
                    if item.field_name_for_child(child_index(item, child)) != Some("value") {
                        self.walk(child, depth + 1)?;
                    }
                }
                break;
            }
        }
        Ok(())
    }
}

fn child_index(parent: Node<'_>, child: Node<'_>) -> u32 {
    (0..parent.child_count())
        .find(|index| parent.child(*index) == Some(child))
        .unwrap_or(parent.child_count()) as u32
}
