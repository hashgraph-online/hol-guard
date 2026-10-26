//! §6.2 and §7.1: the skills a client loads from `skills/`.

use std::fs;
use std::path::Path;

use super::paths::{read_inside, resolve_inside, Read};
use super::{Effect, Report, MAX_NAME, MAX_SKILLS, MAX_SKILL_DESCRIPTION};
use crate::detect::skill::frontmatter;

/// The skills a client would load from `skills/`, by name.
pub(super) fn discover_skills(root: &Path, report: &mut Report) -> Vec<String> {
    const PATH: &str = "skills";
    let dir = root.join(PATH);
    if fs::symlink_metadata(&dir).is_err() {
        return Vec::new();
    }
    let Some(resolved) = resolve_inside(root, &dir) else {
        report.error(
            "skills_outside_root",
            PATH,
            "4.1",
            Effect::InvalidComponent,
            "skills/ resolves outside the plugin folder; clients load no skills.",
        );
        return Vec::new();
    };
    if !resolved.is_dir() {
        report.error(
            "skills_not_directory",
            PATH,
            "6.2",
            Effect::InvalidComponent,
            "skills must be a folder; clients load no skills.",
        );
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(&resolved) else {
        report.error(
            "skills_unreadable",
            PATH,
            "6.2",
            Effect::InvalidComponent,
            "skills/ could not be read.",
        );
        return Vec::new();
    };
    let mut children = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            report.error(
                "skills_unreadable",
                PATH,
                "6.2",
                Effect::InvalidComponent,
                "skills/ could not be read.",
            );
            return Vec::new();
        };
        children.push(entry.file_name().to_string_lossy().into_owned());
        if children.len() > MAX_SKILLS {
            // Checking only some entries could pass a plugin whose
            // unchecked skills a client would skip.
            report.error(
                "skills_too_many",
                PATH,
                "6.2",
                Effect::InvalidComponent,
                format!("skills/ holds more than {MAX_SKILLS} entries, more than the Kit checks."),
            );
            return Vec::new();
        }
    }
    children.sort();
    let mut names = Vec::new();
    for child in children {
        let relative = format!("{PATH}/{child}/SKILL.md");
        let skill = dir.join(&child).join("SKILL.md");
        if fs::symlink_metadata(&skill).is_err() {
            continue;
        }
        let text = match read_inside(root, Path::new(&relative)) {
            Read::Outside => {
                report.error(
                    "skill_outside_root",
                    &relative,
                    "4.1",
                    Effect::SkipSkill,
                    "SKILL.md resolves outside the plugin folder.",
                );
                continue;
            }
            // Only a SKILL.md that is a regular file makes a skill.
            Read::Missing | Read::NotFile => continue,
            Read::Unreadable => {
                report.error(
                    "skill_unreadable",
                    &relative,
                    "7.1",
                    Effect::SkipSkill,
                    "SKILL.md must be readable UTF-8 of at most 1 MiB.",
                );
                continue;
            }
            Read::Text(text) => text,
        };
        let fields = frontmatter(&text);
        let name = fields.get("name").map(String::as_str).unwrap_or("");
        let description = fields.get("description").map(String::as_str).unwrap_or("");
        if !yaml_string(&text, "name") || !valid_skill_name(name) {
            report.error(
                "skill_name_invalid",
                &relative,
                "7.1",
                Effect::SkipSkill,
                "Agent Skills need a frontmatter `name` of 1-64 lowercase letters, digits and single hyphens.",
            );
        } else if name != child {
            report.error(
                "skill_name_mismatch",
                &relative,
                "7.1",
                Effect::SkipSkill,
                format!("The skill is named `{name}` but its folder is `{child}`; Agent Skills require them to match."),
            );
        } else if !yaml_string(&text, "description")
            || description.is_empty()
            || description.chars().count() > MAX_SKILL_DESCRIPTION
        {
            report.error(
                "skill_description_invalid",
                &relative,
                "7.1",
                Effect::SkipSkill,
                "Agent Skills need a frontmatter `description` of 1-1024 characters.",
            );
        } else {
            names.push(name.to_owned());
        }
    }
    names
}

/// Whether a skill can travel in an Agent Plugins package as
/// `skills/<name>/`: a valid Agent Skills name and a description of 1-1024
/// characters.
pub(crate) fn portable_skill(name: Option<&str>, description: Option<&str>) -> bool {
    name.is_some_and(valid_skill_name)
        && description.is_some_and(|description| {
            !description.is_empty() && description.chars().count() <= MAX_SKILL_DESCRIPTION
        })
}

/// The Agent Skills name rule: 1-64 of `a-z0-9-`, no leading, trailing or
/// doubled hyphen.
fn valid_skill_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--")
}

/// Whether the frontmatter value of `key` is a YAML string. The frontmatter
/// reader keeps the text after the colon, so `[a, b]`, `{}`, `null`, `true`
/// or `12` would otherwise pass as strings; YAML 1.2 types those as a list,
/// a map, null, a boolean and a number. Quoted and block scalars are strings.
fn yaml_string(text: &str, key: &str) -> bool {
    let raw = text
        .lines()
        .skip(1)
        .take_while(|line| line.trim_end() != "---")
        .filter(|line| !line.starts_with([' ', '\t']))
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name.trim() == key).then(|| value.trim())
        });
    let Some(raw) = raw else {
        return true;
    };
    if raw.starts_with(['"', '\'', '>', '|']) {
        return true;
    }
    !(raw.starts_with(['[', '{', '&', '*', '!'])
        || matches!(
            raw,
            "~" | "null" | "Null" | "NULL" | "true" | "True" | "TRUE" | "false" | "False" | "FALSE"
        )
        || yaml_number(&raw.to_ascii_lowercase()))
}

fn yaml_number(value: &str) -> bool {
    let unsigned = value.strip_prefix(['-', '+']).unwrap_or(value);
    if matches!(unsigned, ".inf" | ".nan") {
        return true;
    }
    if let Some(digits) = value.strip_prefix("0x") {
        return !digits.is_empty() && digits.chars().all(|c| c.is_ascii_hexdigit());
    }
    if let Some(digits) = value.strip_prefix("0o") {
        return !digits.is_empty() && digits.chars().all(|c| matches!(c, '0'..='7'));
    }
    unsigned.starts_with(|c: char| c.is_ascii_digit() || c == '.')
        && unsigned.chars().any(|c| c.is_ascii_digit())
        && unsigned
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | '-' | '+'))
        && value.parse::<f64>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::yaml_string;

    fn skill(line: &str) -> String {
        format!("---\n{line}\nname: ok\n---\nBody\n")
    }

    #[test]
    fn only_yaml_strings_count_as_descriptions() {
        for line in [
            "description: Helps with widgets.",
            "description: \"[quoted]\"",
            "description: 'null'",
            "description: >",
            "description: version 2.0 notes",
            "description: 1.2.3",
        ] {
            assert!(yaml_string(&skill(line), "description"), "{line}");
        }
        for line in [
            "description: [not, a, string]",
            "description: {a: 1}",
            "description: null",
            "description: ~",
            "description: true",
            "description: 12",
            "description: -3.5e2",
            "description: .inf",
            "description: 0x1F",
        ] {
            assert!(!yaml_string(&skill(line), "description"), "{line}");
        }
    }
}
