//! Agent Skills: the `SKILL.md` frontmatter each skill is listed by.

use std::collections::BTreeMap;
use std::path::Path;

use crate::model::{Diagnostic, Skill, Source};
use crate::walk;

pub(super) fn read_skill(root: &Path, source: &Source, diagnostics: &mut Vec<Diagnostic>) -> Skill {
    let dir = Path::new(&source.path)
        .parent()
        .map(walk::display)
        .unwrap_or_default();
    let fields = walk::read_text(&root.join(&source.path))
        .map(|text| frontmatter(&text))
        .unwrap_or_default();
    if fields.is_empty() {
        diagnostics.push(Diagnostic::error(
            "skill_frontmatter_missing",
            &source.path,
            "SKILL.md needs YAML frontmatter with name and description.",
        ));
    }
    Skill {
        name: fields.get("name").cloned(),
        description: fields.get("description").cloned(),
        dir,
    }
}

/// The scalar `key: value` fields of a leading `---` block. Folded (`>`) and
/// literal (`|`) scalars are joined into one line.
pub(crate) fn frontmatter(text: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let Some(body) = text
        .strip_prefix("---\n")
        .or_else(|| text.strip_prefix("---\r\n"))
    else {
        return fields;
    };
    let mut lines = body.lines().peekable();
    while let Some(line) = lines.next() {
        if line.trim_end() == "---" {
            return fields;
        }
        if line.starts_with([' ', '\t']) {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_owned();
        let mut value = value.trim().to_owned();
        if matches!(value.as_str(), ">" | "|" | ">-" | "|-" | ">+" | "|+") {
            let mut parts = Vec::new();
            while let Some(next) = lines.peek() {
                if !next.starts_with([' ', '\t']) && !next.trim().is_empty() {
                    break;
                }
                parts.push(next.trim().to_owned());
                lines.next();
            }
            value = parts
                .into_iter()
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
        }
        let unquoted = value
            .strip_prefix('"')
            .and_then(|inner| inner.strip_suffix('"'))
            .or_else(|| {
                value
                    .strip_prefix('\'')
                    .and_then(|inner| inner.strip_suffix('\''))
            })
            .map(str::to_owned)
            .unwrap_or(value);
        if !key.is_empty() && !unquoted.is_empty() {
            fields.insert(key, unquoted);
        }
    }
    // An unterminated block is not frontmatter.
    BTreeMap::new()
}

#[cfg(test)]
mod tests {
    use super::frontmatter;

    #[test]
    fn frontmatter_reads_scalars_and_folded_text() {
        let fields = frontmatter(
            "---\nname: pdf-tools\ndescription: >\n  Fill PDF forms\n  and extract text.\nlicense: \"MIT\"\n---\n# Body\n",
        );
        assert_eq!(fields["name"], "pdf-tools");
        assert_eq!(fields["description"], "Fill PDF forms and extract text.");
        assert_eq!(fields["license"], "MIT");
    }

    #[test]
    fn frontmatter_requires_a_closed_block() {
        assert!(frontmatter("---\nname: x\n").is_empty());
        assert!(frontmatter("name: x\n---\n").is_empty());
    }
}
