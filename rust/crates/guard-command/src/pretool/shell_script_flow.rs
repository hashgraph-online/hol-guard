use std::collections::BTreeSet;

use super::{explicit_post_method, mask_literals};

pub(super) fn credential_post(text: &str) -> bool {
    let Some(program) = python_body(text) else {
        return false;
    };
    let code = mask_literals(&program);
    let Some(statements) = top_level_statements(&code, &program) else {
        return false;
    };
    let mut values = BTreeSet::new();
    let mut requests = BTreeSet::new();
    let mut imports = BTreeSet::new();
    for (statement, raw) in statements {
        if let Some(module) = statement.strip_prefix("import ") {
            if !matches!(module, "json" | "os" | "urllib.request") {
                return false;
            }
            imports.insert(module);
            continue;
        }
        if let Some(arguments) = call_arguments(statement, "urllib.request.urlopen") {
            let request = arguments.split(',').next().unwrap_or_default().trim();
            return imports.contains("urllib.request") && requests.contains(request);
        }
        let Some((name, expression)) = statement.split_once('=') else {
            return false;
        };
        let name = name.trim();
        if !identifier(name) || matches!(name, "os" | "urllib" | "json") {
            return false;
        }
        values.remove(name);
        requests.remove(name);
        let expression = expression.trim_start();
        if let Some(arguments) = call_arguments(expression, "urllib.request.Request") {
            let raw_expression = raw
                .split_once('=')
                .map(|(_, value)| value.trim_start())
                .unwrap_or("");
            let Some(raw_arguments) = call_arguments(raw_expression, "urllib.request.Request")
            else {
                return false;
            };
            if imports.contains("urllib.request")
                && explicit_post_method(arguments, &raw_arguments.to_ascii_lowercase())
                && keyword_argument(arguments, "data")
                    .is_some_and(|data| tainted_expression(data, &values, imports.contains("os")))
            {
                requests.insert(name.to_owned());
            }
        } else if tainted_expression(expression, &values, imports.contains("os")) {
            values.insert(name.to_owned());
        } else if expression.contains('(') {
            // An unknown call can change bindings or prevent the later effect.
            return false;
        }
    }
    false
}

fn identifier(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn call_arguments<'a>(expression: &'a str, name: &str) -> Option<&'a str> {
    expression
        .strip_prefix(name)?
        .trim_start()
        .strip_prefix('(')?
        .strip_suffix(')')
}

fn tainted_expression(expression: &str, values: &BTreeSet<String>, os_imported: bool) -> bool {
    if expression
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .any(|token| matches!(token, "lambda" | "if" | "else" | "for" | "yield" | "await"))
    {
        return false;
    }
    let compact: String = expression
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();
    for (index, _) in compact.match_indices('(') {
        let prefix = &compact[..index];
        if !["json.dumps", "os.environ.get", ".encode"]
            .iter()
            .any(|allowed| prefix.ends_with(allowed))
        {
            return false;
        }
    }
    (os_imported && (compact.contains("os.environ[") || compact.contains("os.environ.get(")))
        || expression
            .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
            .any(|token| values.contains(token))
}

fn keyword_argument<'a>(arguments: &'a str, name: &str) -> Option<&'a str> {
    let mut depth = 0usize;
    let mut start = 0usize;
    for (index, byte) in arguments.bytes().chain(std::iter::once(b',')).enumerate() {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.checked_sub(1)?,
            b',' if depth == 0 => {
                let argument = arguments.get(start..index)?.trim();
                if let Some((key, value)) = argument.split_once('=') {
                    if key.trim() == name {
                        return Some(value.trim());
                    }
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    None
}

fn top_level_statements<'a>(code: &'a str, raw: &'a str) -> Option<Vec<(&'a str, &'a str)>> {
    let mut statements = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut offset = 0usize;
    for line in code.split_inclusive('\n') {
        if depth == 0 && !line.trim().is_empty() && line.starts_with(char::is_whitespace) {
            return None;
        }
        for byte in line.bytes() {
            match byte {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth = depth.checked_sub(1)?,
                b';' => return None,
                _ => {}
            }
        }
        offset += line.len();
        if depth == 0 {
            let segment = &code[start..offset];
            let leading = segment.len() - segment.trim_start().len();
            let statement = segment.trim();
            if !statement.is_empty() {
                // Literal/comment masking preserves offsets. Use code bounds
                // for both slices so a trailing comment cannot hide a call.
                let begin = start + leading;
                statements.push((statement, &raw[begin..begin + statement.len()]));
            }
            start = offset;
        }
    }
    (depth == 0).then_some(statements)
}

fn python_body(text: &str) -> Option<String> {
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if line.trim().is_empty() || line.starts_with('#') || line == "set -euo pipefail" {
            continue;
        }
        if line.starts_with("export ") && !line.contains(['$', ';', '&', '|', '`']) {
            continue;
        }
        let (command, delimiter) = line.split_once("<<")?;
        if !(command.starts_with("python3 - ") || command.starts_with("python - "))
            || command.contains(['$', ';', '&', '|', '`'])
        {
            return None;
        }
        let delimiter = delimiter.trim();
        let delimiter = if delimiter.starts_with(['\'', '"']) {
            let quote = delimiter.as_bytes()[0] as char;
            delimiter.strip_prefix(quote)?.strip_suffix(quote)?
        } else {
            delimiter
        };
        if !identifier(delimiter) {
            return None;
        }
        let mut body = String::new();
        for line in lines.by_ref() {
            if line == delimiter {
                return Some(body);
            }
            body.push_str(line);
            body.push('\n');
        }
        return None;
    }
    None
}
