//! Deterministic version edits for `package.json` text.
//!
//! A fix edit replaces only the bytes inside one version-spec string, so every
//! other byte of the manifest (key order, indentation, line endings, trailing
//! newline) survives. The edit is planned from a scan of the raw text rather
//! than from a parsed and re-serialized document. Anything that is not a plain
//! `major.minor.patch` range under a recognised dependency section is refused
//! with a reason code instead of being guessed at.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Sections whose entries are direct dependencies of the package itself.
const DEPENDENCY_SECTIONS: [&str; 3] = ["dependencies", "devDependencies", "optionalDependencies"];
const MAX_DEPTH: usize = 100;

type Code = &'static str;

/// One spec replacement; `start` and `end` are byte offsets into the text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FixEdit {
    pub(crate) section: String,
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) from_spec: String,
    pub(crate) to_spec: String,
}

struct Declaration {
    section: &'static str,
    start: usize,
    end: usize,
    spec: Option<String>,
}

struct Member {
    key: String,
    value_start: usize,
    value_end: usize,
}

/// Walk valid JSON text and report where each value sits.
struct Scanner<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Scanner<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Result<u8, Code> {
        self.bytes
            .get(self.pos)
            .copied()
            .ok_or("manifest_invalid_json")
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.bytes.get(self.pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn first_value(&mut self) -> usize {
        self.skip_whitespace();
        self.pos
    }

    /// The content range of the string at the cursor; the cursor ends after
    /// its closing quote.
    fn string(&mut self) -> Result<(usize, usize), Code> {
        if self.peek()? != b'"' {
            return Err("manifest_invalid_json");
        }
        let start = self.pos + 1;
        self.pos = start;
        loop {
            match self.peek()? {
                b'\\' => self.pos += 2,
                b'"' => {
                    self.pos += 1;
                    return Ok((start, self.pos - 1));
                }
                _ => self.pos += 1,
            }
        }
    }

    fn colon(&mut self) -> Result<(), Code> {
        self.skip_whitespace();
        if self.peek()? != b':' {
            return Err("manifest_invalid_json");
        }
        self.pos += 1;
        self.skip_whitespace();
        Ok(())
    }

    fn comma(&mut self) -> Result<(), Code> {
        self.skip_whitespace();
        if self.peek()? == b',' {
            self.pos += 1;
        }
        Ok(())
    }

    fn members(&mut self, start: usize) -> Result<Vec<Member>, Code> {
        self.pos = start + 1;
        let mut found = Vec::new();
        loop {
            self.skip_whitespace();
            if self.peek()? == b'}' {
                return Ok(found);
            }
            let quoted = self.pos;
            let (_, content_end) = self.string()?;
            let key: String = serde_json::from_slice(&self.bytes[quoted..=content_end])
                .map_err(|_| "manifest_invalid_json")?;
            self.colon()?;
            let value_start = self.pos;
            self.skip_value(0)?;
            found.push(Member {
                key,
                value_start,
                value_end: self.pos,
            });
            self.comma()?;
        }
    }

    fn skip_value(&mut self, depth: usize) -> Result<(), Code> {
        if depth > MAX_DEPTH {
            return Err("manifest_too_deep");
        }
        match self.peek()? {
            b'"' => self.string().map(|_| ()),
            b'{' => self.skip_container(b'}', depth, true),
            b'[' => self.skip_container(b']', depth, false),
            _ => {
                let begin = self.pos;
                while !matches!(
                    self.bytes.get(self.pos),
                    None | Some(b',' | b']' | b'}' | b' ' | b'\t' | b'\n' | b'\r')
                ) {
                    self.pos += 1;
                }
                if self.pos == begin {
                    return Err("manifest_invalid_json");
                }
                Ok(())
            }
        }
    }

    fn skip_container(&mut self, closer: u8, depth: usize, keyed: bool) -> Result<(), Code> {
        self.pos += 1;
        loop {
            self.skip_whitespace();
            if self.peek()? == closer {
                self.pos += 1;
                return Ok(());
            }
            if keyed {
                self.string()?;
                self.colon()?;
            }
            self.skip_value(depth + 1)?;
            self.comma()?;
        }
    }
}

fn parse_document(text: &str) -> Result<Value, Code> {
    let document: Value = serde_json::from_str(text).map_err(|error| {
        if error.to_string().starts_with("recursion limit exceeded") {
            "manifest_too_deep"
        } else {
            "manifest_invalid_json"
        }
    })?;
    if document.is_object() {
        Ok(document)
    } else {
        Err("manifest_invalid_json")
    }
}

fn declarations(text: &str, package: &str) -> Result<Vec<Declaration>, Code> {
    parse_document(text)?;
    let mut scanner = Scanner::new(text);
    let top_start = scanner.first_value();
    let top = scanner.members(top_start)?;
    let mut found = Vec::new();
    for section in DEPENDENCY_SECTIONS {
        let mut sections = top.iter().filter(|member| member.key == section);
        let first = sections.next();
        if sections.next().is_some() {
            // JSON readers keep the last duplicate; which one counts is a guess.
            return Err("manifest_duplicate_section");
        }
        let Some(first) = first else { continue };
        if text.as_bytes().get(first.value_start) != Some(&b'{') {
            continue;
        }
        let entries: Vec<Member> = scanner
            .members(first.value_start)?
            .into_iter()
            .filter(|member| member.key == package)
            .collect();
        if entries.len() > 1 {
            return Err("manifest_duplicate_declaration");
        }
        let Some(entry) = entries.first() else {
            continue;
        };
        if text.as_bytes().get(entry.value_start) != Some(&b'"') {
            found.push(Declaration {
                section,
                start: entry.value_start,
                end: entry.value_end,
                spec: None,
            });
            continue;
        }
        let (start, end) = {
            scanner.pos = entry.value_start;
            scanner.string()?
        };
        found.push(Declaration {
            section,
            start,
            end,
            spec: Some(text[start..end].to_owned()),
        });
    }
    Ok(found)
}

fn is_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// `major.minor.patch` made only of ASCII digits.
fn is_plain_version(text: &str) -> bool {
    let mut parts = text.split('.');
    let three = parts
        .by_ref()
        .take(3)
        .filter(|part| is_digits(part))
        .count();
    three == 3 && parts.next().is_none()
}

/// An optional `^` or `~` and a plain version, with nothing after it.
fn plain_spec(spec: &str) -> Option<(&str, &str)> {
    let (operator, version) = match spec.as_bytes().first() {
        Some(b'^' | b'~') => spec.split_at(1),
        _ => ("", spec),
    };
    is_plain_version(version).then_some((operator, version))
}

fn compare_versions(left: &str, right: &str) -> Ordering {
    fn key(text: &str) -> Vec<(usize, &str)> {
        text.split('.')
            .map(|part| {
                let trimmed = part.trim_start_matches('0');
                (trimmed.len(), trimmed)
            })
            .collect()
    }
    key(left).cmp(&key(right))
}

fn unsupported_spec_reason(spec: &str) -> Code {
    let lowered = spec.trim().to_lowercase();
    if lowered.starts_with("workspace:") {
        return "spec_workspace_protocol";
    }
    if lowered.starts_with("npm:") {
        return "spec_npm_alias";
    }
    if ["file:", "link:", "portal:", ".", "/", "~/"]
        .iter()
        .any(|prefix| lowered.starts_with(prefix))
    {
        return "spec_local_path";
    }
    if lowered.contains("://")
        || ["git", "github:", "gitlab:", "bitbucket:", "http"]
            .iter()
            .any(|prefix| lowered.starts_with(prefix))
    {
        return "spec_git_or_url";
    }
    let mut chars = lowered.chars();
    let tag = chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'));
    if tag {
        "spec_dist_tag"
    } else {
        "spec_not_plain_semver"
    }
}

/// Plan the minimal spec edits that move `package` to `fix_version`.
pub(crate) fn plan_edits(
    text: &str,
    package: &str,
    fix_version: &str,
) -> Result<Vec<FixEdit>, Code> {
    if !is_plain_version(fix_version) {
        return Err("fix_version_not_plain_semver");
    }
    let found = declarations(text, package)?;
    if found.is_empty() {
        return Err("not_declared");
    }
    let mut edits = Vec::new();
    for declaration in found {
        let spec = declaration.spec.ok_or("spec_not_a_string")?;
        let Some((operator, version)) = plain_spec(&spec) else {
            return Err(unsupported_spec_reason(&spec));
        };
        if compare_versions(version, fix_version) != Ordering::Less {
            // The declared range already allows the fix, so the manifest is not
            // what pins the vulnerable version; raising it would be a downgrade.
            continue;
        }
        edits.push(FixEdit {
            section: declaration.section.to_owned(),
            start: declaration.start,
            end: declaration.end,
            to_spec: format!("{operator}{fix_version}"),
            from_spec: spec,
        });
    }
    if edits.is_empty() {
        return Err("declared_range_already_covers_fix");
    }
    edits.sort_by_key(|edit| edit.start);
    Ok(edits)
}

/// Apply `edits` to `text`. Every edit must still find its `from_spec` at its
/// offsets, must write a plain spec, and the result must be valid JSON.
pub(crate) fn apply_edits(text: &str, edits: &[FixEdit]) -> Result<String, Code> {
    let mut ordered: Vec<&FixEdit> = edits.iter().collect();
    ordered.sort_by_key(|edit| edit.start);
    let mut result = String::with_capacity(text.len());
    let mut cursor = 0;
    for edit in ordered {
        if edit.start < cursor || text.get(edit.start..edit.end) != Some(edit.from_spec.as_str()) {
            return Err("manifest_changed");
        }
        if plain_spec(&edit.to_spec).is_none() {
            return Err("edit_not_plain_spec");
        }
        result.push_str(&text[cursor..edit.start]);
        result.push_str(&edit.to_spec);
        cursor = edit.end;
    }
    result.push_str(&text[cursor..]);
    if parse_document(&result).is_err() {
        return Err("edit_produced_invalid_json");
    }
    Ok(result)
}

#[cfg(test)]
#[path = "workspace_fix_manifest_tests.rs"]
mod tests;
