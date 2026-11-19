//! Whether a Python launch runs Guard's Codex hook: `python -m` the CLI, the
//! daemon bridge script, or an inline `-c` script that imports the CLI and
//! hands it Codex hook arguments. The script is parsed, never run.

use tree_sitter::{Node, Parser};

use super::codex_owner_home::BRIDGE_SCRIPT;
use super::codex_python_imports::Calls;
use super::codex_python_values::{kids, string_value, text, walk};
use crate::cursor_hook_command::Syntax;

/// `has_codex_harness_tokens`.
pub(super) fn has_codex_harness<S: AsRef<str>>(tokens: &[Option<S>]) -> bool {
    tokens
        .iter()
        .enumerate()
        .any(|(index, token)| match token.as_ref().map(AsRef::as_ref) {
            Some("--harness=codex") => true,
            Some("--harness") => {
                matches!(tokens.get(index + 1), Some(Some(next)) if next.as_ref() == "codex")
            }
            _ => false,
        })
}

/// `_codex_hook_arguments`.
fn codex_hook_arguments<S: AsRef<str>>(arguments: &[Option<S>]) -> bool {
    let is = |token: Option<&Option<S>>, want: &str| matches!(token, Some(Some(value)) if value.as_ref() == want);
    let payload = if is(arguments.first(), "guard") {
        &arguments[1..]
    } else {
        arguments
    };
    is(payload.first(), "hook") && has_codex_harness(payload)
}

fn known(tokens: &[String]) -> Vec<Option<&str>> {
    tokens.iter().map(|token| Some(token.as_str())).collect()
}

/// `_python_hook_payload`: the arguments after the interpreter's options.
fn python_payload(tokens: &[String]) -> Vec<String> {
    let mut payload = tokens.to_vec();
    while let Some(option) = payload.first().cloned() {
        if !option.starts_with('-') || option == "-" || option == "--" {
            break;
        }
        if option.starts_with("--") {
            let used = if option == "--check-hash-based-pycs" {
                2
            } else {
                1
            };
            payload.drain(..used.min(payload.len()));
            continue;
        }
        let flags: Vec<(usize, char)> = option.char_indices().skip(1).collect();
        let mut consumed = 1;
        for (offset, flag) in flags {
            let rest = &option[offset + flag.len_utf8()..];
            if flag == 'c' || flag == 'm' {
                let mut out = vec![format!("-{flag}")];
                if !rest.is_empty() {
                    out.push(rest.to_owned());
                }
                out.extend(payload.into_iter().skip(1));
                return out;
            }
            if flag == 'W' || flag == 'X' {
                consumed = if rest.is_empty() { 2 } else { 1 };
                break;
            }
        }
        payload.drain(..consumed.min(payload.len()));
    }
    payload
}

/// `python_codex_hook_command`.
pub(super) fn python_codex_hook_command(tokens: &[String], syntax: &Syntax) -> bool {
    let payload = python_payload(tokens.get(1..).unwrap_or_default());
    let first = payload.first().map(String::as_str);
    if first == Some("--") {
        return payload
            .get(1)
            .is_some_and(|script| syntax.name(script) == BRIDGE_SCRIPT);
    }
    if first == Some("-m")
        && payload.get(1).map(String::as_str) == Some("codex_plugin_scanner.cli")
        && codex_hook_arguments(&known(&payload[2..]))
    {
        return true;
    }
    if first.is_some_and(|script| syntax.name(script) == BRIDGE_SCRIPT) {
        return true;
    }
    first == Some("-c")
        && payload
            .get(1)
            .is_some_and(|script| inline_codex_hook(script, &payload[2..]))
}

fn parse(script: &str) -> Option<tree_sitter::Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(script, None)?;
    let root = tree.root_node();
    // Python 2 statements parse here but are syntax errors to Python 3.
    let python2 = walk(root)
        .into_iter()
        .any(|node| matches!(node.kind(), "print_statement" | "exec_statement"));
    (!root.has_error() && !python2).then_some(tree)
}

/// `_imports_guard_cli`.
fn imports_guard_cli(root: Node<'_>, script: &str) -> bool {
    let dotted = |node: Node<'_>| {
        let parts: Vec<&str> = kids(node)
            .into_iter()
            .map(|part| text(part, script))
            .collect();
        parts.join(".")
    };
    let imported = |node: Node<'_>| {
        let name = match node.kind() {
            "aliased_import" => node.child_by_field_name("name"),
            _ => Some(node),
        };
        name.map(dotted).unwrap_or_default()
    };
    let names = |node: Node<'_>| -> Vec<String> {
        let mut cursor = node.walk();
        let found: Vec<Node<'_>> = node.children_by_field_name("name", &mut cursor).collect();
        found.into_iter().map(imported).collect()
    };
    for node in walk(root) {
        match node.kind() {
            "import_statement" => {
                if names(node)
                    .iter()
                    .any(|name| name == "codex_plugin_scanner.cli")
                {
                    return true;
                }
            }
            "import_from_statement" => {
                let module = node
                    .child_by_field_name("module_name")
                    .filter(|module| module.kind() == "dotted_name")
                    .map(dotted);
                match module.as_deref() {
                    Some("codex_plugin_scanner.cli") => return true,
                    Some("codex_plugin_scanner")
                        if names(node).iter().any(|name| name == "cli") =>
                    {
                        return true;
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    Calls::new(script).imports_guard(root)
}

/// `_inline_python_codex_hook`: static imports and argv, nothing run.
pub(super) fn inline_codex_hook(script: &str, trailing: &[String]) -> bool {
    if script.contains('\0') {
        return false;
    }
    let Some(tree) = parse(script) else {
        return false;
    };
    let root = tree.root_node();
    if !imports_guard_cli(root, script) {
        return false;
    }
    if codex_hook_arguments(&known(trailing)) {
        return true;
    }
    for node in walk(root) {
        if !matches!(
            node.kind(),
            "list"
                | "tuple"
                | "expression_list"
                | "pattern_list"
                | "tuple_pattern"
                | "list_pattern"
        ) {
            continue;
        }
        let mut values: Vec<Option<String>> = kids(node)
            .into_iter()
            .map(|item| string_value(item, script))
            .collect();
        if values.first() == Some(&Some("guard".to_owned())) {
            values.remove(0);
        }
        if values.first() != Some(&Some("hook".to_owned())) {
            continue;
        }
        // A dynamic harness operand cannot prove this is an unrelated handler.
        let dynamic = values.iter().enumerate().any(|(index, value)| {
            value.as_deref() == Some("--harness") && values.get(index + 1) == Some(&None)
        });
        if dynamic || codex_hook_arguments(&values) {
            return true;
        }
    }
    false
}
