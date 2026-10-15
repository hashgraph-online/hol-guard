//! Original credential rules and their sample suppression, executed natively.

use std::sync::OnceLock;
use std::time::Instant;

use fancy_regex::Regex as FancyRegex;
use fancy_regex::RegexBuilder as FancyBuilder;
use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    classifier: String,
    family: String,
    sensitivity: String,
    pattern: String,
    flags: u32,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tables {
    rules: Vec<Rule>,
    sample: String,
    documentation: String,
    expressions: Vec<String>,
    version_material: Value,
    legacy_markers: Vec<(String, String)>,
}

struct Patterns {
    tables: Tables,
    rules: Vec<Regex>,
    sample: FancyRegex,
    documentation: FancyRegex,
    expressions: Vec<FancyRegex>,
    version: String,
}

fn compile_fancy(pattern: &str) -> Result<FancyRegex, &'static str> {
    FancyBuilder::new(pattern)
        .backtrack_limit(100_000)
        .build()
        .map_err(|_| "content_pattern_unavailable")
}

fn patterns() -> Result<&'static Patterns, &'static str> {
    static PATTERNS: OnceLock<Result<Patterns, &'static str>> = OnceLock::new();
    PATTERNS
        .get_or_init(|| {
            let tables: Tables =
                serde_json::from_str(include_str!("content_sensitivity_patterns.json"))
                    .map_err(|_| "content_pattern_unavailable")?;
            let rules = tables
                .rules
                .iter()
                .map(|rule| {
                    // Python's MULTILINE flag can be supplied outside the pattern.
                    let pattern = if rule.flags & 8 != 0 {
                        format!("(?m){}", rule.pattern)
                    } else {
                        rule.pattern.clone()
                    };
                    // Recorded rules have no backreferences. The linear engine
                    // finishes on a long benign input; the backtracker overflows.
                    Regex::new(&pattern).map_err(|_| "content_pattern_unavailable")
                })
                .collect::<Result<Vec<_>, _>>()?;
            let sample = compile_fancy(&tables.sample)?;
            let documentation = compile_fancy(&format!("(?:{})\\z", tables.documentation))?;
            let expressions = tables
                .expressions
                .iter()
                .map(|pattern| compile_fancy(&format!("(?:{pattern})\\z")))
                .collect::<Result<Vec<_>, _>>()?;
            let version = digest(&tables.version_material)?;
            Ok(Patterns {
                tables,
                rules,
                sample,
                documentation,
                expressions,
                version,
            })
        })
        .as_ref()
        .map_err(|error| *error)
}

pub(super) fn digest(value: &Value) -> Result<String, &'static str> {
    // serde_json's default object representation sorts keys recursively.
    let encoded = serde_json::to_vec(value).map_err(|_| "content_digest_unavailable")?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

pub(super) fn version() -> Result<String, &'static str> {
    Ok(patterns()?.version.clone())
}

pub(super) fn legacy(text: &str) -> Result<Value, &'static str> {
    let text = text.to_lowercase();
    let mut families = patterns()?
        .tables
        .legacy_markers
        .iter()
        .filter(|(marker, _)| text.contains(marker))
        .map(|(_, family)| family.clone())
        .collect::<Vec<_>>();
    families.sort();
    families.dedup();
    Ok(json!(families))
}

fn matches(pattern: &FancyRegex, text: &str) -> Result<bool, &'static str> {
    pattern
        .is_match(text)
        .map_err(|_| "content_scan_unavailable")
}

fn assignment_value(text: &str) -> Option<&str> {
    let separator = [text.find(':'), text.find('=')]
        .into_iter()
        .flatten()
        .min()?;
    let value = text[separator + 1..].trim().trim_end_matches(',').trim();
    let value = if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        &value[1..value.len() - 1]
    } else {
        value
    };
    (!value.is_empty()).then_some(value)
}

fn sample_match(
    p: &Patterns,
    classifier: &str,
    text: &str,
    suppress: bool,
    documentation: bool,
) -> Result<bool, &'static str> {
    if !matches!(classifier, "credential-assignment" | "generic-bearer-token") {
        return Ok(false);
    }
    if classifier == "credential-assignment" {
        if let Some(value) = assignment_value(text) {
            for expression in &p.expressions {
                if matches(expression, value)? {
                    return Ok(true);
                }
            }
        }
    }
    if !suppress {
        return Ok(false);
    }
    if classifier == "generic-bearer-token" {
        let token = text.split_whitespace().next_back().unwrap_or("");
        let has_long_run = token
            .split(|ch: char| !ch.is_ascii_alphanumeric())
            .any(|part| part.len() >= 20);
        if matches(&p.sample, token)? && !has_long_run {
            return Ok(true);
        }
        return Ok(documentation && matches(&p.documentation, token)?);
    }
    if matches(&p.sample, text)? {
        return Ok(true);
    }
    Ok(documentation
        && assignment_value(text)
            .map(|value| matches(&p.documentation, value))
            .transpose()?
            .unwrap_or(false))
}

pub(super) fn content(
    text: Option<&str>,
    suppress: bool,
    documentation: bool,
    deadline: Instant,
) -> Result<Value, &'static str> {
    let Some(text) = text.filter(|text| !text.trim().is_empty()) else {
        return Ok(json!([]));
    };
    let p = patterns()?;
    let mut found = Vec::new();
    for (rule, pattern) in p.tables.rules.iter().zip(&p.rules) {
        if Instant::now() >= deadline {
            return Err("content_scan_deadline_exceeded");
        }
        for item in pattern.find_iter(text) {
            if Instant::now() >= deadline {
                return Err("content_scan_deadline_exceeded");
            }
            if !sample_match(p, &rule.classifier, item.as_str(), suppress, documentation)? {
                found.push(json!({"classifier": rule.classifier, "family": rule.family,
                    "sensitivity": rule.sensitivity, "reason": rule.reason}));
                break;
            }
        }
    }
    if Instant::now() >= deadline {
        return Err("content_scan_deadline_exceeded");
    }
    Ok(json!(found))
}
