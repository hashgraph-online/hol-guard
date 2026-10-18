//! Command arguments, redirections and allocation bounds.

use super::{
    child_index, Node, Operation, Redirect, Result, State, MAX_OPERATIONS, MAX_SOURCE_BYTES,
};

impl State<'_, '_> {
    pub(super) fn command(&mut self, node: Node<'_>, depth: usize) -> Result<()> {
        self.claim_effect(node)?;
        let name = self.field(node, "name")?;
        let name = name
            .named_child(0)
            .ok_or_else(|| self.error(name, "bash_dynamic_command"))?;
        if !matches!(name.kind(), "word" | "raw_string") {
            return Err(self.error(name, "bash_dynamic_command"));
        }
        let mut argv = vec![self.word(name, false)?];
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match node
                .field_name_for_child(child_index(node, child))
                .unwrap_or("")
            {
                "name" => (),
                "argument" => {
                    if argv.len() >= 256 {
                        return Err(self.error(child, "bash_argument_bounds"));
                    }
                    let value = self.word(child, false)?;
                    self.charge(value.len(), child)?;
                    argv.push(value);
                }
                "redirect" => self.redirect(child, node.start_byte())?,
                _ => return Err(self.error(child, "bash_command_environment_or_subshell")),
            }
        }
        if matches!(argv[0].as_str(), "source" | ".") {
            return self.source_command(node, name, argv, depth);
        }
        if argv[0] == "return" {
            return Err(self.error(node, "bash_source_return_unproven"));
        }
        if matches!(argv[0].as_str(), "test" | "[")
            && argv[1..]
                .iter()
                .any(|value| value == "-t" || super::is_descriptor_reference(value))
        {
            return Err(self.error(node, "bash_process_descriptor_unproven"));
        }
        if matches!(argv[0].as_str(), "test" | "[") && !modeled_test(&argv) {
            // Filesystem predicates can inspect process-relative descriptor
            // aliases. This profile supports only literal string/integer tests.
            return Err(self.error(node, "bash_test_context_unproven"));
        }
        // These alter parsing, resolution or shell startup. They need their
        // own semantics and must never become ordinary allowlisted commands.
        if matches!(
            argv[0].as_str(),
            "eval"
                | "exec"
                | "export"
                | "readonly"
                | "declare"
                | "typeset"
                | "alias"
                | "unalias"
                | "enable"
                | "builtin"
                | "command"
                | "trap"
                | "shopt"
                | "unset"
                | "read"
                | "mapfile"
                | "getopts"
                | "cd"
                | "pushd"
                | "popd"
        ) {
            return Err(self.error(node, "bash_dynamic_shell_state"));
        }
        if argv[0] == "set" && argv != ["set", "-euo", "pipefail"] {
            return Err(self.error(node, "bash_shell_options"));
        }
        if matches!(
            argv[0].as_str(),
            "bind"
                | "break"
                | "builtin"
                | "caller"
                | "compgen"
                | "complete"
                | "compopt"
                | "continue"
                | "dirs"
                | "disown"
                | "fc"
                | "fg"
                | "bg"
                | "hash"
                | "help"
                | "history"
                | "jobs"
                | "kill"
                | "let"
                | "local"
                | "logout"
                | "popd"
                | "pushd"
                | "pwd"
                | "readarray"
                | "select"
                | "shift"
                | "suspend"
                | "times"
                | "type"
                | "ulimit"
                | "umask"
                | "wait"
                | "enable"
        ) {
            return Err(self.error(node, "bash_unmodeled_builtin"));
        }
        if argv[0] == "printf" {
            let index = if argv.get(1).is_some_and(|arg| arg == "--") {
                2
            } else {
                1
            };
            let format = argv
                .get(index)
                .ok_or_else(|| self.error(node, "bash_printf_format"))?;
            let mut chars = format.chars();
            if format.starts_with('-') && index == 1 {
                return Err(self.error(node, "bash_printf_state"));
            }
            while let Some(character) = chars.next() {
                if character == '%' && !matches!(chars.next(), Some('%' | 's' | 'b' | 'q')) {
                    return Err(self.error(node, "bash_printf_state"));
                }
            }
        }
        if argv[0] == "exit" {
            if argv.len() > 2 || argv.get(1).is_some_and(|v| v.parse::<u8>().is_err()) {
                return Err(self.error(node, "bash_dynamic_exit"));
            }
            self.stopped = true;
        }
        self.charge(argv[0].len(), node)?;
        self.analysis.operations.push(Operation {
            argv,
            line: node.start_position().row + 1,
            command_start: name.start_byte(),
            command_end: name.end_byte(),
        });
        Ok(())
    }

    pub(super) fn redirect(&mut self, node: Node<'_>, statement_start: usize) -> Result<()> {
        self.claim_effect(node)?;
        if node.kind() != "file_redirect" || node.child_by_field_name("descriptor").is_some() {
            return Err(self.error(node, "bash_redirect_unsupported"));
        }
        let destination = self.field(node, "destination")?;
        let prefix = self.source[node.start_byte()..destination.start_byte()].trim();
        if !matches!(prefix, ">" | ">>") {
            return Err(self.error(node, "bash_redirect_unsupported"));
        }
        let path = self.word(destination, false)?;
        self.charge(path.len(), destination)?;
        let mut ancestor = node.parent();
        let mut top_level = true;
        while let Some(parent) = ancestor {
            top_level &= matches!(
                parent.kind(),
                "program" | "command" | "redirected_statement"
            );
            ancestor = parent.parent();
        }
        self.analysis.writes.push(Redirect {
            path,
            append: prefix == ">>",
            line: node.start_position().row + 1,
            start: node.start_byte(),
            end: node.end_byte(),
            statement_start,
            top_level,
        });
        Ok(())
    }

    fn claim_effect(&mut self, node: Node<'_>) -> Result<()> {
        self.total_effects += 1;
        if self.total_effects > MAX_OPERATIONS {
            return Err(self.error(node, "bash_analysis_bounds"));
        }
        Ok(())
    }

    pub(super) fn charge(&mut self, bytes: usize, node: Node<'_>) -> Result<()> {
        self.expanded_bytes = self.expanded_bytes.saturating_add(bytes);
        if self.expanded_bytes > MAX_SOURCE_BYTES
            || self.analysis.operations.len() + self.analysis.writes.len() >= MAX_OPERATIONS
        {
            return Err(self.error(node, "bash_expanded_data_bounds"));
        }
        Ok(())
    }
}

fn modeled_test(argv: &[String]) -> bool {
    let mut arguments = &argv[1..];
    if argv[0] == "[" {
        if arguments.last().is_none_or(|value| value != "]") {
            return false;
        }
        arguments = &arguments[..arguments.len() - 1];
    }
    match arguments {
        [] | [_] => true,
        [flag, _] => matches!(flag.as_str(), "-n" | "-z"),
        [left, operator, right] => match operator.as_str() {
            "=" | "==" | "!=" => true,
            "-eq" | "-ne" | "-gt" | "-ge" | "-lt" | "-le" => {
                left.parse::<i64>().is_ok() && right.parse::<i64>().is_ok()
            }
            _ => false,
        },
        _ => false,
    }
}
