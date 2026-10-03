use super::super::sensitive_command;
use crate::MAX_COMMAND_BYTES;
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::sync::OnceLock;

pub(super) const MAX_PRE_TOOL_DEPTH: usize = 32;
const MAX_PRE_TOOL_KEYS: usize = 512;
const MAX_PRE_TOOL_ARRAY_ITEMS: usize = 256;
const MAX_PRE_TOOL_STRINGS: usize = 128;
const MAX_NESTED_JSON_OBJECT_ITEMS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GenericExtractionError {
    Malformed,
    Ambiguous,
    Bounds,
}

#[derive(Debug, Default)]
pub(super) struct GenericSignals {
    pub(super) command: Option<String>,
    pub(super) tool_name: Option<String>,
    pub(super) package_present: bool,
    pub(super) package_values: Vec<String>,
    pub(super) path_values: Vec<String>,
    pub(super) url_values: Vec<String>,
    pub(super) prompt_present: bool,
    pub(super) env_reference: bool,
    pub(super) benign_prompt: bool,
    pub(super) guard_bypass_intent: bool,
    pub(super) prompt_injection_intent: bool,
    pub(super) exfil_intent: bool,
    pub(super) destructive_intent: bool,
    pub(super) subprocess_intent: bool,
    pub(super) content_sensitive: bool,
    pub(super) sensitive_target: bool,
    pub(super) independent_sensitive_target: bool,
    pub(super) event_hint: Option<String>,
}

fn bounded_payload(
    value: &Value,
    depth: usize,
    keys: &mut usize,
) -> Result<(), GenericExtractionError> {
    if depth > MAX_PRE_TOOL_DEPTH {
        return Err(GenericExtractionError::Bounds);
    }
    match value {
        Value::Object(record) => {
            *keys = keys.saturating_add(record.len());
            if *keys > MAX_PRE_TOOL_KEYS {
                return Err(GenericExtractionError::Bounds);
            }
            for child in record.values() {
                bounded_payload(child, depth.saturating_add(1), keys)?;
            }
        }
        Value::Array(items) => {
            if items.len() > MAX_PRE_TOOL_ARRAY_ITEMS {
                return Err(GenericExtractionError::Bounds);
            }
            for child in items {
                bounded_payload(child, depth.saturating_add(1), keys)?;
            }
        }
        Value::String(text) => {
            if text.len() > MAX_COMMAND_BYTES || text.chars().count() > MAX_COMMAND_BYTES {
                return Err(GenericExtractionError::Bounds);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn collect_maps<'a>(value: &'a Value, output: &mut Vec<&'a Map<String, Value>>) {
    match value {
        Value::Object(record) => {
            output.push(record);
            for child in record.values() {
                collect_maps(child, output);
            }
        }
        Value::Array(items) => {
            for child in items {
                collect_maps(child, output);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn bounded_string(value: &Value) -> Result<String, GenericExtractionError> {
    let text = value
        .as_str()
        .ok_or(GenericExtractionError::Malformed)?
        .trim();
    if text.is_empty() {
        return Err(GenericExtractionError::Malformed);
    }
    if text.len() > MAX_COMMAND_BYTES || text.chars().count() > MAX_COMMAND_BYTES {
        return Err(GenericExtractionError::Bounds);
    }
    Ok(text.to_owned())
}

fn append_strings(output: &mut Vec<String>, value: &Value) -> Result<(), GenericExtractionError> {
    if output.len() >= MAX_PRE_TOOL_STRINGS {
        return Err(GenericExtractionError::Bounds);
    }
    match value {
        Value::String(_) => output.push(bounded_string(value)?),
        Value::Array(items) => {
            if items.len() > MAX_PRE_TOOL_ARRAY_ITEMS {
                return Err(GenericExtractionError::Bounds);
            }
            for item in items {
                if output.len() >= MAX_PRE_TOOL_STRINGS {
                    return Err(GenericExtractionError::Bounds);
                }
                output.push(bounded_string(item)?);
            }
        }
        _ => return Err(GenericExtractionError::Malformed),
    }
    Ok(())
}

fn collect_key_strings(
    maps: &[&Map<String, Value>],
    keys: &[&str],
) -> Result<Vec<String>, GenericExtractionError> {
    let mut output = Vec::new();
    for record in maps {
        for key in keys {
            if let Some(value) = record.get(*key) {
                append_strings(&mut output, value)?;
            }
        }
    }
    Ok(output)
}

fn unique_string(values: Vec<String>) -> Result<Option<String>, GenericExtractionError> {
    let Some(first) = values.first() else {
        return Ok(None);
    };
    if values.iter().any(|value| value != first) {
        return Err(GenericExtractionError::Ambiguous);
    }
    Ok(Some(first.clone()))
}

fn command_from_value(value: &Value) -> Result<Vec<String>, GenericExtractionError> {
    command_from_value_at_depth(value, 0)
}

fn command_from_value_at_depth(
    value: &Value,
    depth: usize,
) -> Result<Vec<String>, GenericExtractionError> {
    if depth > MAX_PRE_TOOL_DEPTH {
        return Err(GenericExtractionError::Bounds);
    }
    match value {
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.starts_with('[') || trimmed.starts_with('{') {
                let parsed = parse_strict_nested_json(trimmed.as_bytes())?;
                return command_from_value_at_depth(&parsed, depth.saturating_add(1));
            }
            Ok(vec![bounded_string(value)?])
        }
        Value::Array(items) => {
            if items.len() != 1 {
                return Err(GenericExtractionError::Ambiguous);
            }
            command_from_value_at_depth(&items[0], depth.saturating_add(1))
        }
        Value::Object(record) => {
            let mut output = Vec::new();
            let mut found = false;
            for key in [
                "command",
                "cmd",
                "shell_command",
                "shellCommand",
                "commands",
            ] {
                if let Some(item) = record.get(key) {
                    found = true;
                    output.extend(command_from_value_at_depth(item, depth.saturating_add(1))?);
                }
            }
            if !found {
                return Err(GenericExtractionError::Malformed);
            }
            Ok(output)
        }
        _ => Err(GenericExtractionError::Malformed),
    }
}

fn collect_commands(
    maps: &[&Map<String, Value>],
) -> Result<Option<String>, GenericExtractionError> {
    let mut values = Vec::new();
    for record in maps {
        for key in [
            "command",
            "cmd",
            "shell_command",
            "shellCommand",
            "commands",
        ] {
            if let Some(value) = record.get(key) {
                values.extend(command_from_value(value)?);
            }
        }
        if let Some(value @ Value::String(text)) = record.get("parameters") {
            let trimmed = text.trim_start();
            if trimmed.starts_with('[') || trimmed.starts_with('{') {
                values.extend(command_from_value(value)?);
            }
        }
    }
    unique_string(values)
}

fn collect_tool_names(payload: &Value) -> Result<Option<String>, GenericExtractionError> {
    let Some(root) = payload.as_object() else {
        return Err(GenericExtractionError::Malformed);
    };
    let mut values = Vec::new();
    for key in [
        "tool_name",
        "toolName",
        "toolname",
        "tool",
        "name",
        "action",
        "operation",
    ] {
        if let Some(value) = root.get(key) {
            if !value.is_object() {
                values.push(bounded_string(value)?);
            }
        }
    }
    for key in ["tool_call", "toolCall", "preToolUse", "pre_tool_use"] {
        let Some(Value::Object(record)) = root.get(key) else {
            continue;
        };
        for name_key in ["tool_name", "toolName", "toolname", "name", "tool"] {
            if let Some(value) = record.get(name_key) {
                if !value.is_object() {
                    values.push(bounded_string(value)?);
                }
            }
        }
    }
    unique_string(values)
}

fn collect_event_hint(root: &Map<String, Value>) -> Result<Option<String>, GenericExtractionError> {
    unique_string(collect_key_strings(
        &[root],
        &[
            "event",
            "eventName",
            "hook_event_name",
            "hookEventName",
            "hook_name",
            "hookName",
        ],
    )?)
}

fn sensitive_text(values: &[String]) -> bool {
    values.iter().any(|value| sensitive_command(value))
}

fn authentication_requirement_pattern() -> &'static Regex {
    static AUTH_REQUIREMENT: OnceLock<Regex> = OnceLock::new();
    AUTH_REQUIREMENT.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:needs?|requires?)\s+(?:their|your|the user's|the operator's)\s+password\b",
        )
        .expect("bounded human authentication requirement")
    })
}

fn prompt_sensitive_text(value: &str) -> bool {
    static AUTH_CONTEXT: OnceLock<Regex> = OnceLock::new();
    static REFERENTIAL_ACCESS: OnceLock<Regex> = OnceLock::new();
    let requirement = authentication_requirement_pattern();
    if !requirement.is_match(value) {
        return sensitive_command(value);
    }
    let context = AUTH_CONTEXT.get_or_init(|| {
        Regex::new(r"(?i)\b(?:authentication|authenticate|login|log\s+in|sign\s+in|recovery|recover-authority|terminal)\b")
            .expect("bounded human authentication context")
    });
    for (index, matched) in requirement.find_iter(value).enumerate() {
        if index >= 16 {
            return true;
        }
        let start = value[..matched.start()]
            .rfind(['.', '!', '?', ';', '\n'])
            .map_or(0, |offset| offset + 1);
        let end = value[matched.end()..]
            .find(['.', '!', '?', ';', '\n'])
            .map_or(value.len(), |offset| matched.end() + offset);
        if !context.is_match(&value[start..end]) {
            return true;
        }
    }
    // Authentication requirements are not requests to obtain the credential.
    // Keep explicit targets and referential follow-up reads on the guarded path.
    let followup = REFERENTIAL_ACCESS.get_or_init(|| {
        Regex::new(r"(?i)\b(?:read|open|print|show|display|disclose|reveal|echo|cat|output|write|type|paste|post|email|forward|share|give|hand|provide|tell|return|summari[sz]e|dump|copy|retrieve|fetch|obtain|extract|capture|store|save|log|include|grab|access|upload|send|transfer)\s+(?:(?:the\s+)?(?:full\s+)?(?:contents?|value|text|data)\s+(?:of|from)\s+)?(?:it|them|those|these|that|this|me|us)\b|\bhand\s+over\s+(?:it|them|those|these|that|this|me|us)\b|\b(?:do|perform|execute|run|use)\s+(?:it|that|this|them)\s+(?:anyway|regardless)\b")
            .expect("bounded credential referential follow-up")
    });
    if followup.is_match(value) {
        return true;
    }
    sensitive_command(&requirement.replace_all(value, "human authentication"))
}

fn guard_bypass_prompt(values: &[String]) -> bool {
    values.iter().any(|value| {
        let lowered = value.to_ascii_lowercase();
        let normalized = lowered.split_whitespace().collect::<Vec<_>>().join(" ");
        [
            "disable hol-guard",
            "hol-guard disable",
            "hol-guard off",
            "hol-guard uninstall",
            "disable guard",
            "turn off guard",
            "uninstall guard",
            "use another mcp server",
            "guard-bypass",
            "guard_bypass",
        ]
        .iter()
        .any(|pattern| normalized.contains(pattern))
            || ["approval_policy=\"never\"", "approval_policy='never'"]
                .iter()
                .any(|pattern| normalized.replace(' ', "").contains(pattern))
    })
}

fn prompt_injection_intent(values: &[String]) -> bool {
    static INJECTION: OnceLock<Regex> = OnceLock::new();
    let pattern = INJECTION.get_or_init(|| {
        Regex::new(r"(?i)\b(?:ignore\s+(?:all\s+)?(?:previous|prior|earlier)\s+instructions?|ignore\s+(?:the\s+)?system\s+prompt|(?:do\s+not|don't)\s+(?:tell|notify|alert|inform)\s+(?:the\s+)?users?|hide\s+(?:this|it|the\s+(?:action|instruction|request))\s+from\s+(?:the\s+)?logs?|(?:reveal|print|show)\s+(?:the\s+)?(?:system\s+prompt|developer\s+instructions?)|(?:remove|strip)\s+(?:the\s+)?(?:guard\s+)?hooks?)\b")
            .expect("bounded prompt injection intent")
    });
    values.iter().any(|value| pattern.is_match(value))
}

fn exfil_prompt_intent(values: &[String]) -> bool {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        [
            r"(?i)\b(?:upload|exfiltrate|transfer|paste|gist|webhook)\b[^.!?;\n]{0,80}\b(?:contents?|data|payload|file|secret|token|key|credentials?|config|output)\b",
            r"(?i)\b(?:send|post|upload|transfer|paste|sync)\b[^.!?;\n]{0,120}(?:\.env\b|/\.ssh/|/\.aws/|\.npmrc\b|\.pypirc\b|\.authrc\b|\.envrc\b)[^.!?;\n]{0,80}\b(?:to|into|onto|via|through|over|at)\b[^.!?;\n]{0,80}(?:[a-z][a-z0-9+.-]*://|webhook|gist|pastebin|slack|discord|telegram|server|endpoint|url)",
            r"(?i)\b(?:send|post|upload|transfer|paste|sync)\b[^.!?;\n]{0,80}\b(?:to|into|onto|via|through|over|at)\b[^.!?;\n]{0,40}\b(?:webhook|gist|pastebin|slack|discord|telegram|server|endpoint|url)\b",
            r"(?i)\b(?:send|post|upload|transfer|paste|sync)\b[^.!?;\n]{0,80}\b(?:contents?|data|payload|file|secret|token|key|credentials?|config|output)\b[^.!?;\n]{0,40}\b(?:to|into|onto|via|through|over|at)\b[^.!?;\n]{0,40}(?:[a-z][a-z0-9+.-]*://|webhook|gist|pastebin|slack|discord|telegram|server|endpoint|url)",
        ]
        .into_iter()
        .map(|pattern| Regex::new(pattern).expect("bounded exfiltration prompt intent"))
        .collect()
    });
    values
        .iter()
        .any(|value| patterns.iter().any(|pattern| pattern.is_match(value)))
}

fn destructive_prompt_intent(values: &[String]) -> bool {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    static REFERENTIAL: OnceLock<Regex> = OnceLock::new();
    static FS_NOUN: OnceLock<Regex> = OnceLock::new();
    let pattern = PATTERN.get_or_init(|| {
        Regex::new(r"(?i)(?:\brm\s+-[a-z]*[rf]\b|\b(?:delete|remove|overwrite|truncate|chmod|chown|mv)\b[^.!?;\n]{0,60}\b(?:file|directory|repo|workspace|contents?)\b)")
            .expect("bounded destructive prompt intent")
    });
    let referential = REFERENTIAL.get_or_init(|| {
        Regex::new(r"(?i)\b(?:delete|remove|overwrite|truncate|chmod|chown|mv)\s+(?:all\s+of\s+)?(?:it|them|those|these)\b")
            .expect("bounded referential destructive prompt intent")
    });
    let fs_noun = FS_NOUN.get_or_init(|| {
        Regex::new(r"(?i)\b(?:files?|director(?:y|ies)|repo(?:sitory)?|workspace)\b")
            .expect("fs noun")
    });
    values.iter().any(|value| {
        pattern.is_match(&mask_destructive_prohibitions(value))
            || (referential.is_match(value) && fs_noun.is_match(value))
    })
}

fn mask_destructive_prohibitions(value: &str) -> String {
    static PROHIBITION: OnceLock<Regex> = OnceLock::new();
    static EXCEPTION: OnceLock<Regex> = OnceLock::new();
    let prohibition = PROHIBITION
        .get_or_init(|| {
            Regex::new(r"(?i)\b(?:never|do\s+not|don't|dont|must\s+not|should\s+not)\s+(?:delete|erase|wipe|format|kill|remove|overwrite|truncate|chmod|chown|mv)\b")
                .expect("bounded destructive action prohibition")
        });
    let exception = EXCEPTION.get_or_init(|| {
        Regex::new(r"(?i)\b(?:except|unless|until|without|if|but|besides|other\s+than|apart\s+from|aside\s+from|save\s+for|instead\s+of)\b")
            .expect("bounded conditional prohibition")
    });
    prohibition
        .replace_all(value, |captures: &regex::Captures<'_>| {
            let matched = captures.get(0).expect("matched prohibition");
            let tail = &value[matched.end()..];
            let clause = tail.split(['.', '!', '?', ';', '\n']).next().unwrap_or("");
            if exception.is_match(clause) {
                matched.as_str().to_owned()
            } else {
                "prohibited action".to_owned()
            }
        })
        .into_owned()
}

fn subprocess_prompt_intent(values: &[String]) -> bool {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    let pattern = PATTERN.get_or_init(|| {
        Regex::new(r"(?i)\b(?:bash\s+-c\b|sh\s+-c\b|zsh\s+-c\b|powershell\b|cmd\s+/c\b|subprocess\b|exec\s*\(|spawn\s*\()")
            .expect("bounded subprocess prompt intent")
    });
    values.iter().any(|value| pattern.is_match(value))
}

fn benign_prompt_text(text: &str) -> bool {
    static NEGATED_READ: OnceLock<Regex> = OnceLock::new();
    static DOCUMENTED_READ: OnceLock<Regex> = OnceLock::new();
    static DOCUMENTED_ENV: OnceLock<Regex> = OnceLock::new();
    static DOCUMENT_END: OnceLock<Regex> = OnceLock::new();
    static ENV_TEMPLATE: OnceLock<Regex> = OnceLock::new();
    static RISK_ACTION: OnceLock<Regex> = OnceLock::new();
    static REFERENT_ACTION: OnceLock<Regex> = OnceLock::new();

    let normalized = text.to_ascii_lowercase();
    let mut remainder = if prompt_sensitive_text(&normalized) {
        normalized.clone()
    } else {
        authentication_requirement_pattern()
            .replace_all(&normalized, "human authentication")
            .into_owned()
    };
    // Mask only the prohibited verb, never its targets or later instructions.
    remainder = mask_destructive_prohibitions(&remainder);
    let documents = [
        "create ",
        "write ",
        "draft ",
        "document ",
        "generate ",
        "outline ",
    ]
    .iter()
    .any(|prefix| normalized.trim_start().starts_with(prefix))
        && ["markdown", "docs", "documentation", "checklist", "guide"]
            .iter()
            .any(|target| normalized.contains(target));
    if documents {
        let documented_end = DOCUMENT_END.get_or_init(|| {
            Regex::new(r"(?i)(?:must\s+stay\s+blocked|reads?\s+require\s+approval)\s*[.!?]?\s*$")
                .expect("bounded documented guardrail ending")
        });
        if sensitive_command(&normalized) && !documented_end.is_match(&normalized) {
            return false;
        }
        let documented_read = DOCUMENTED_READ.get_or_init(|| {
            Regex::new(
                r"(?i)`(?:cat|read|head|tail|grep|rg)\s+[^`]{0,512}`\s+must\s+stay\s+blocked",
            )
            .expect("bounded documented read expression")
        });
        remainder = documented_read.replace_all(&remainder, " ").into_owned();
        let documented_env = DOCUMENTED_ENV.get_or_init(|| {
            Regex::new(r"(?i)`\.env(?:\.[a-z0-9_.-]+)?`\s+reads?\s+require\s+approval")
                .expect("bounded documented environment reference")
        });
        remainder = documented_env.replace_all(&remainder, " ").into_owned();
    }
    let negated_read = NEGATED_READ.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:never|do\s+not|don't|dont|must\s+not|should\s+not)\s+(?:read|open|print|show|dump|cat|inspect|copy|use|include|grab)\s+[`'"]?\.env(?:\.[a-z0-9_.-]+)?[`'"]?(?:\s+files?)?"#)
            .expect("bounded negated environment read")
    });
    let negated_suffix = negated_read
        .find_iter(&remainder)
        .last()
        .map(|matched| remainder[matched.end()..].to_owned());
    remainder = negated_read.replace_all(&remainder, " ").into_owned();
    if negated_suffix.is_some_and(|suffix| {
        REFERENT_ACTION
            .get_or_init(|| {
                Regex::new(r"(?i)\b(?:read|open|print|show|dump|copy|inspect|summari[sz]e|include|upload|send|transfer|use|grab|access|do(?:ing)?|perform|execute|run|follow|try)\b[^.!?;\n]{0,80}\b(?:it|them|those|these|its|their)\b")
                    .expect("bounded referential follow-up")
            })
            .is_match(&suffix)
    }) {
        return false;
    }
    let env_template = ENV_TEMPLATE
        .get_or_init(|| Regex::new(r"(?i)\.env\.example\b").expect("bounded template reference"));
    remainder = env_template.replace_all(&remainder, " ").into_owned();
    let risky_action = RISK_ACTION.get_or_init(|| {
        Regex::new(r"(?i)\b(?:rm\s+-[a-z]*[rf]\b|delete\b|erase\b|wipe\b|format\b|kill\b|upload\b|exfiltrat[a-z]*\b|transfer\b|curl\b|wget\b|sudo\b|bash\s+-c\b|sh\s+-c\b|powershell\b|cmd\s+/c\b|subprocess\b|spawn\s*\(|exec\s*\(|send\s+(?:data|payload|file|secret|token|credential)\b|post\s+(?:payload|data|file|secret)\b|sync\s+(?:output|data)\b|(?:send|post|sync|transfer)\s+(?:to|over|via|at)\s+(?:webhook|server|slack|discord|https?://)\b|then\s+(?:read|open|print|summari[sz]e|show|dump|include|use|grab|upload|send)\s+(?:it|them|those|files|secrets)\b|(?:now|then|afterwards|also)\s+(?:do|perform|execute|follow|run|use)\s+(?:it|that|this|them|example)\b)")
            .expect("bounded risky prompt action")
    });
    !sensitive_command(&remainder) && !risky_action.is_match(&remainder)
}

#[path = "generic_nested_json.rs"]
mod nested_json;
use nested_json::parse_strict_nested_json;

#[path = "generic_signals.rs"]
mod signals;
pub(super) use signals::extract_generic_signals;
