//! Exact words only: no command substitution, splitting, globbing or indirection.

use tree_sitter::Node;

use super::{Result, State, MAX_WORD_BYTES};

pub(super) fn ordinary_variable(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !name.starts_with("BASH")
        && !name.starts_with("DYLD_")
        && !name.starts_with("LD_")
        && !name.starts_with("LC_")
        && !name.starts_with("HIST")
        && !name.starts_with("__HOL_GUARD_")
        && !matches!(
            name,
            "_" | "LINENO"
                | "RANDOM"
                | "SRANDOM"
                | "SECONDS"
                | "PPID"
                | "UID"
                | "EUID"
                | "FUNCNAME"
                | "DIRSTACK"
                | "GROUPS"
                | "OPTARG"
                | "OPTIND"
                | "OPTERR"
                | "PIPESTATUS"
                | "SHLVL"
                | "PWD"
                | "OLDPWD"
                | "PATH"
                | "HOME"
                | "IFS"
                | "CDPATH"
                | "ENV"
                | "SHELLOPTS"
                | "GLOBIGNORE"
                | "LANG"
                | "LANGUAGE"
                | "TZ"
                | "TMOUT"
                | "FUNCNEST"
                | "POSIXLY_CORRECT"
                | "IGNOREEOF"
                | "MAIL"
                | "MAILPATH"
                | "MAILCHECK"
                | "PS1"
                | "PS2"
                | "PS3"
                | "PS4"
                | "PROMPT_COMMAND"
        )
}

impl State<'_, '_> {
    pub(super) fn word(&self, node: Node<'_>, quoted: bool) -> Result<String> {
        let value = self.word_inner(node, quoted)?;
        if value.len() > MAX_WORD_BYTES {
            return Err(self.error(node, "bash_word_bounds"));
        }
        Ok(value)
    }

    fn word_inner(&self, node: Node<'_>, quoted: bool) -> Result<String> {
        match node.kind() {
            "word" | "number" | "extglob_pattern" => {
                let value = self.text(node);
                if value.is_empty()
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-/:+=%@,".contains(&b))
                {
                    return Err(self.error(node, "bash_word_expansion"));
                }
                Ok(value.to_owned())
            }
            "raw_string" => {
                let raw = self.text(node);
                raw.strip_prefix('\'')
                    .and_then(|s| s.strip_suffix('\''))
                    .map(str::to_owned)
                    .ok_or_else(|| self.error(node, "bash_quoted_word"))
            }
            "string" => {
                let mut result = String::new();
                let mut expected = node.start_byte() + 1;
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if child.start_byte() != expected {
                        return Err(self.error(node, "bash_dynamic_word"));
                    }
                    expected = child.end_byte();
                    let value = self.word(child, true)?;
                    if result.len() + value.len() > MAX_WORD_BYTES {
                        return Err(self.error(node, "bash_word_bounds"));
                    }
                    result.push_str(&value);
                }
                if expected + 1 != node.end_byte() {
                    return Err(self.error(node, "bash_dynamic_word"));
                }
                Ok(result)
            }
            "string_content" => {
                let mut value = String::new();
                let mut chars = self.text(node).chars().peekable();
                while let Some(ch) = chars.next() {
                    if ch == '\\' {
                        match chars.peek().copied() {
                            Some('$' | '`' | '"' | '\\') => value.push(chars.next().unwrap()),
                            Some('\n') => {
                                chars.next();
                            }
                            _ => value.push(ch),
                        }
                    } else {
                        value.push(ch);
                    }
                }
                Ok(value)
            }
            "concatenation" => {
                let mut result = String::new();
                let mut expected = node.start_byte();
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if child.start_byte() != expected {
                        return Err(self.error(node, "bash_dynamic_word"));
                    }
                    expected = child.end_byte();
                    let value = self.word(child, quoted)?;
                    if result.len() + value.len() > MAX_WORD_BYTES {
                        return Err(self.error(node, "bash_word_bounds"));
                    }
                    result.push_str(&value);
                }
                if expected != node.end_byte() {
                    return Err(self.error(node, "bash_dynamic_word"));
                }
                Ok(result)
            }
            "simple_expansion" | "expansion" if quoted => self.expansion(node),
            "simple_expansion" | "expansion" => Err(self.error(node, "bash_unquoted_expansion")),
            _ => Err(self.error(node, "bash_dynamic_word")),
        }
    }

    fn expansion(&self, node: Node<'_>) -> Result<String> {
        let raw = self.text(node);
        let inner = if node.kind() == "simple_expansion" {
            raw.strip_prefix('$').unwrap_or("")
        } else {
            raw.strip_prefix("${")
                .and_then(|s| s.strip_suffix('}'))
                .unwrap_or("")
        };
        let (name, default) = match inner.split_once(":-") {
            Some((name, value)) => (name, Some((value, true))),
            None => match inner.split_once('-') {
                Some((name, value)) => (name, Some((value, false))),
                None => (inner, None),
            },
        };
        let value = if !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()) {
            let index = name
                .parse::<usize>()
                .map_err(|_| self.error(node, "bash_parameter_bounds"))?;
            // Bash's $10 is $1 followed by a literal zero; braces are required.
            if node.kind() == "simple_expansion" && name.len() > 1 {
                return Err(self.error(node, "bash_parameter_bounds"));
            }
            self.argv.get(index).cloned()
        } else if matches!(name, "HOME") || ordinary_variable(name) {
            if self.exported_names.contains(name) && !self.variables.contains_key(name) {
                return Err(self.error(node, "bash_exported_environment_value_withheld"));
            }
            self.variables.get(name).cloned()
        } else {
            return Err(self.error(node, "bash_dynamic_parameter"));
        };
        if let Some((fallback, empty_too)) = default {
            // Only a literal default. The grammar parsed the whole expression,
            // but nested substitution and quote removal need separate support.
            if !fallback
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-/:".contains(&b))
            {
                return Err(self.error(node, "bash_dynamic_default"));
            }
            if value.is_none() || (empty_too && value.as_deref() == Some("")) {
                return Ok(fallback.to_owned());
            }
        }
        value.ok_or_else(|| self.error(node, "bash_unknown_variable"))
    }
}
