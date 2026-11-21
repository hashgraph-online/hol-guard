//! The `key = value` entries of a Git configuration file, decoded as Git
//! reads them, for the sandbox's helper-path checks.

/// Keys of remotes and submodules that name refs, URLs or checkout paths,
/// never a program. Their other keys, such as `uploadpack` or `update`, can.
/// `safe.directory` names trusted repositories, often with a `*` pattern.
pub(super) fn names_data(section: &str, key: &str) -> bool {
    (matches!(section, "remote" | "submodule")
        && matches!(
            key,
            "url" | "pushurl" | "fetch" | "push" | "path" | "branch"
        ))
        || (section == "safe" && key == "directory")
}

/// Section, key and value of each `key = value` line. `None` when a header
/// carries text after its `]`: Git parses that as a key, as in
/// `[core] hooksPath = x`, and this reader does not.
pub(super) fn entries(config: &str) -> Option<Vec<(String, String, String)>> {
    let mut result = Vec::new();
    let mut section = String::new();
    for line in config.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[') {
            let (name, rest) = header.split_once(']')?;
            let rest = rest.trim();
            if !rest.is_empty() && !rest.starts_with(['#', ';']) {
                return None;
            }
            section = name
                .trim()
                .split(|c: char| c.is_whitespace() || c == '"')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            result.push((
                section.clone(),
                key.trim().to_ascii_lowercase(),
                decode_value(value.trim())?,
            ));
        }
    }
    Some(result)
}

/// A configuration value the way Git reads it: double-quoted spans lose their
/// quotes, and `\"` and `\\` (plus `\n`, `\t`, `\b`) become the character
/// they name. `None` for anything ambiguous: another escape, a trailing
/// backslash (line continuation) or an unterminated quote.
fn decode_value(raw: &str) -> Option<String> {
    let mut decoded = String::with_capacity(raw.len());
    let mut quoted = false;
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => quoted = !quoted,
            '\\' => match chars.next()? {
                '"' => decoded.push('"'),
                '\\' => decoded.push('\\'),
                'n' => decoded.push('\n'),
                't' => decoded.push('\t'),
                'b' => decoded.push('\u{8}'),
                _ => return None,
            },
            other => decoded.push(other),
        }
    }
    (!quoted).then_some(decoded)
}
