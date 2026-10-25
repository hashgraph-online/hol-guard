//! Environment variable references in MCP configs: read in any runtime's
//! syntax (`${NAME}`, `${env:NAME}`, `{env:NAME}`, `$NAME`) and kept as
//! `${NAME}` templates until a runtime's own syntax is written.

/// The variable a whole value references, when the value is one reference.
pub(crate) fn single_reference(value: &str) -> Option<String> {
    let (name, rest) = next_reference(value.trim())?;
    rest.is_empty().then_some(name)
}

/// The value with every reference written as `${NAME}`, when it has at least
/// one. A value with no reference is a literal and is not carried.
pub(crate) fn normalize_template(value: &str) -> Option<String> {
    let mut output = String::new();
    let mut found = false;
    let mut rest = value;
    while !rest.is_empty() {
        if let Some((name, after)) = next_reference(rest) {
            output.push_str(&format!("${{{name}}}"));
            found = true;
            rest = after;
            continue;
        }
        let mut chars = rest.chars();
        if let Some(character) = chars.next() {
            output.push(character);
        }
        rest = chars.as_str();
    }
    found.then_some(output)
}

/// The variables a `${NAME}` template references, in order.
pub(crate) fn template_variables(template: &str) -> Vec<String> {
    let mut names = Vec::new();
    render(template, |name| {
        names.push(name.to_owned());
        String::new()
    });
    names
}

/// The template with each `${NAME}` replaced by `write(NAME)`.
pub(crate) fn render(template: &str, mut write: impl FnMut(&str) -> String) -> String {
    let mut output = String::new();
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        output.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find('}') {
            Some(end) if is_variable(&after[..end]) => {
                output.push_str(&write(&after[..end]));
                rest = &after[end + 1..];
            }
            _ => {
                output.push_str("${");
                rest = after;
            }
        }
    }
    output.push_str(rest);
    output
}

/// A reference at the start of `value`, and the text after it.
fn next_reference(value: &str) -> Option<(String, &str)> {
    let braced = |inner: &str, prefix_len: usize| -> Option<(String, usize)> {
        let end = inner.find('}')?;
        let name = &inner[..end];
        let name = name.strip_prefix("env:").unwrap_or(name);
        is_variable(name).then(|| (name.to_owned(), prefix_len + end + 1))
    };
    let (name, consumed) = if let Some(inner) = value.strip_prefix("${") {
        braced(inner, 2)?
    } else if let Some(inner) = value.strip_prefix("{env:") {
        let (name, consumed) = braced(inner, 5)?;
        (name, consumed)
    } else if let Some(inner) = value.strip_prefix('$') {
        let end = inner
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(inner.len());
        let name = &inner[..end];
        if !is_variable(name) {
            return None;
        }
        (name.to_owned(), 1 + end)
    } else {
        return None;
    };
    Some((name, &value[consumed..]))
}

fn is_variable(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::{normalize_template, render, single_reference, template_variables};

    #[test]
    fn single_references_in_every_syntax() {
        for value in [
            "${GH_PAT}",
            "${env:GH_PAT}",
            "{env:GH_PAT}",
            "$GH_PAT",
            " $GH_PAT ",
        ] {
            assert_eq!(
                single_reference(value).as_deref(),
                Some("GH_PAT"),
                "{value}"
            );
        }
        for value in ["production", "Bearer ${GH_PAT}", "${}", "$1", "${A-B}", ""] {
            assert_eq!(single_reference(value), None, "{value}");
        }
    }

    #[test]
    fn header_templates_keep_text_and_normalize_references() {
        assert_eq!(
            normalize_template("Bearer {env:API_TOKEN}").as_deref(),
            Some("Bearer ${API_TOKEN}")
        );
        assert_eq!(
            normalize_template("$USER:${env:PASS}").as_deref(),
            Some("${USER}:${PASS}")
        );
        assert_eq!(normalize_template("Bearer sk-live-123"), None);
        assert_eq!(
            template_variables("${USER}:${PASS}"),
            vec!["USER".to_owned(), "PASS".to_owned()]
        );
        assert_eq!(
            render("Bearer ${API_TOKEN}", |name| format!("{{env:{name}}}")),
            "Bearer {env:API_TOKEN}"
        );
    }
}
