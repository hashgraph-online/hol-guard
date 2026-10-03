use super::{MAX_FACT_DEPTH, MAX_FACT_NODES, MAX_SELECTOR_VALUE_BYTES};
use guard_contracts::PreToolActionTypeV1;
use guard_secure_fs::sensitive_path_family;
use serde_json::{Map, Value};
use std::path::Path;

mod policy_enforcement_facts_tools;

pub(super) use policy_enforcement_facts_tools::{
    classify_tool_name, preferred_tool_name, risk_classes,
};

const PUBLISHER_KEYS: &[&str] = &[
    "publisher",
    "publisher_id",
    "publisherId",
    "publisher_name",
    "publisherName",
];
const ARTIFACT_KEYS: &[&str] = &[
    "artifact",
    "artifact_id",
    "artifactId",
    "package",
    "package_name",
    "packageName",
    "plugin_id",
    "pluginId",
    "extension_id",
    "extensionId",
    "skill_id",
    "skillId",
];
pub(super) const PATH_KEYS: &[&str] = &[
    "path",
    "file",
    "file_path",
    "filePath",
    "target_file",
    "targetFile",
    "target_directory",
    "targetDirectory",
];
const CHANGED_BOOL_KEYS: &[&str] = &[
    "changed",
    "hash_changed",
    "hashChanged",
    "changed_hash",
    "changedHash",
    "source_changed",
    "sourceChanged",
    "source_hash_changed",
    "sourceHashChanged",
    "content_changed",
    "contentChanged",
];
const CHANGED_CAPABILITY_KEYS: &[&str] = &["changed_capabilities", "changedCapabilities"];

#[derive(Debug, Default)]
pub(super) struct PolicyFacts {
    pub(super) publisher: Option<String>,
    pub(super) artifact: Option<String>,
    pub(super) changed_hash: bool,
    pub(super) sensitive_target: bool,
    pub(super) publisher_relevant: bool,
}

/// The same total order as the Python action lattice and the v3 snapshot
/// validator.  Keep this local to the native data plane so policy composition
/// cannot depend on a Python semantic helper.
pub(super) fn collect_fact_maps<'a>(
    value: &'a Value,
    depth: usize,
    nodes: &mut usize,
    output: &mut Vec<&'a Map<String, Value>>,
) -> Result<(), String> {
    if depth > MAX_FACT_DEPTH {
        return Err("native_policy_request_bounds_exceeded".to_owned());
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_FACT_NODES {
        return Err("native_policy_request_bounds_exceeded".to_owned());
    }
    match value {
        Value::Object(record) => {
            output.push(record);
            for child in record.values() {
                collect_fact_maps(child, depth.saturating_add(1), nodes, output)?;
            }
        }
        Value::Array(items) => {
            for child in items {
                collect_fact_maps(child, depth.saturating_add(1), nodes, output)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

pub(super) fn bounded_selector_value(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_SELECTOR_VALUE_BYTES
        || value.chars().count() > MAX_SELECTOR_VALUE_BYTES
    {
        return Err("native_policy_selector_invalid".to_owned());
    }
    Ok(value.to_owned())
}

pub(super) fn optional_identity(
    maps: &[&Map<String, Value>],
    keys: &[&str],
) -> Result<Option<String>, String> {
    let mut selected: Option<String> = None;
    for record in maps {
        for key in keys {
            let Some(value) = record.get(*key) else {
                continue;
            };
            // Some harnesses carry a full artifact/publisher object. It is not
            // an authenticated selector, so leave it unknown and apply the
            // conservative unknown-publisher floor instead of guessing.
            let Some(value) = value.as_str() else {
                if key.ends_with("_id") || key.ends_with("Id") {
                    return Err("native_policy_selector_invalid".to_owned());
                }
                continue;
            };
            let value = bounded_selector_value(value)?;
            if selected
                .as_deref()
                .is_some_and(|previous| previous != value)
            {
                return Err("native_policy_selector_conflict".to_owned());
            }
            selected = Some(value);
        }
    }
    Ok(selected)
}

pub(super) fn path_values_sensitive(maps: &[&Map<String, Value>]) -> Result<bool, String> {
    let mut sensitive = false;
    for record in maps {
        for key in PATH_KEYS {
            let Some(value) = record.get(*key) else {
                continue;
            };
            let values: Vec<&str> = match value {
                Value::String(value) => vec![value.as_str()],
                Value::Array(values) => values
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .ok_or_else(|| "native_policy_path_invalid".to_owned())
                    })
                    .collect::<Result<_, _>>()?,
                // An object under `file` or `path` is metadata, not a path
                // selector. The native source reader still validates it.
                Value::Object(_) | Value::Null | Value::Bool(_) | Value::Number(_) => continue,
            };
            sensitive |= values
                .into_iter()
                .any(|value| sensitive_path_family(Path::new(value)).is_some());
        }
    }
    Ok(sensitive)
}

pub(super) fn sensitive_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace(['_', '-'], "");
    [
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "privatekey",
        "apikey",
        "accesskey",
        "authorization",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

/// Borrow only the top-level arguments of a known Codex command envelope.
/// The caller supplies the normalized `codex` harness; other harness names,
/// tools, action types and empty commands retain ordinary sensitive-key checks.
fn codex_command_budget_input<'a>(
    payload: &'a Value,
    harness: &str,
    action_type: PreToolActionTypeV1,
) -> Option<&'a Map<String, Value>> {
    if harness != "codex" || action_type != PreToolActionTypeV1::Command {
        return None;
    }
    let envelope = payload.as_object()?;
    if !matches!(
        envelope.get("tool_name").and_then(Value::as_str),
        Some("exec_command" | "functions.exec_command")
    ) {
        return None;
    }
    let input = envelope.get("tool_input")?.as_object()?;
    let command = input.get("cmd")?.as_str()?;
    if command.trim().is_empty() {
        return None;
    }
    Some(input)
}

pub(super) fn payload_sensitive_target(
    maps: &[&Map<String, Value>],
    codex_budget_input: Option<&Map<String, Value>>,
    codex_wait_process: Option<&Map<String, Value>>,
) -> Result<bool, String> {
    let mut sensitive = path_values_sensitive(maps)?;
    // Traversal borrows maps from the original JSON tree. Identity, rather
    // than value equality, excludes nested and sibling copies. Zero is also
    // numeric metadata; this does not interpret its budget semantics or relax
    // command, path, intrinsic or managed floors.
    for record in maps {
        for (key, value) in *record {
            if key == "sensitive_target" {
                let value = value
                    .as_bool()
                    .ok_or_else(|| "native_policy_sensitive_target_invalid".to_owned())?;
                sensitive |= value;
            } else if sensitive_key(key)
                && !((key == "max_output_tokens"
                    && value.as_u64().is_some()
                    && codex_budget_input.is_some_and(|input| std::ptr::eq(*record, input)))
                    || (key == "startToken"
                        && codex_wait_process.is_some_and(|input| std::ptr::eq(*record, input))))
            {
                // Only the numeric output budget in this exact Codex command
                // argument object is metadata. Credential-shaped strings,
                // nested data and every other sensitive selector still count.
                sensitive = true;
            }
        }
    }
    Ok(sensitive)
}

fn codex_browser_process_metadata<'a>(
    payload: &'a Value,
    harness: &str,
) -> Option<&'a Map<String, Value>> {
    if harness != "codex" {
        return None;
    }
    let process = payload
        .as_object()?
        .get("guard_codex_browser_wait_process")?
        .as_object()?;
    if process.len() != 2
        || !process
            .get("pid")?
            .as_u64()
            .is_some_and(|pid| pid > 0 && pid <= u32::MAX as u64)
    {
        return None;
    }
    let token = process.get("startToken")?.as_str()?;
    let valid = if let Some(ticks) = token
        .strip_prefix("linux:")
        .or_else(|| token.strip_prefix("windows:"))
    {
        !ticks.is_empty() && ticks.len() <= 20 && ticks.bytes().all(|ch| ch.is_ascii_digit())
    } else if let Some(started) = token.strip_prefix("posix:") {
        let fields: Vec<_> = started.split_whitespace().collect();
        fields.len() == 5
            && matches!(
                fields[0],
                "Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat" | "Sun"
            )
            && matches!(
                fields[1],
                "Jan"
                    | "Feb"
                    | "Mar"
                    | "Apr"
                    | "May"
                    | "Jun"
                    | "Jul"
                    | "Aug"
                    | "Sep"
                    | "Oct"
                    | "Nov"
                    | "Dec"
            )
            && fields[2].len() <= 2
            && fields[2]
                .parse::<u8>()
                .is_ok_and(|day| (1..=31).contains(&day))
            && fields[3].len() == 8
            && fields[3].split(':').count() == 3
            && fields[3]
                .split(':')
                .zip([23, 59, 60])
                .all(|(field, limit)| {
                    field.len() == 2 && field.parse::<u8>().is_ok_and(|value| value <= limit)
                })
            && fields[4].len() == 4
            && fields[4].bytes().all(|ch| ch.is_ascii_digit())
    } else {
        false
    };
    valid.then_some(process)
}

pub(super) fn optional_changed_bool(maps: &[&Map<String, Value>]) -> Result<bool, String> {
    let mut selected: Option<bool> = None;
    let mut select = |value: bool| -> Result<(), String> {
        if selected.is_some_and(|previous| previous != value) {
            return Err("native_policy_changed_hash_conflict".to_owned());
        }
        selected = Some(value);
        Ok(())
    };
    for record in maps {
        for key in CHANGED_BOOL_KEYS {
            let Some(value) = record.get(*key) else {
                continue;
            };
            let value = value
                .as_bool()
                .ok_or_else(|| "native_policy_changed_hash_invalid".to_owned())?;
            select(value)?;
        }
        for key in CHANGED_CAPABILITY_KEYS {
            let Some(value) = record.get(*key) else {
                continue;
            };
            match value {
                Value::String(value) => {
                    let changed = value.trim().eq_ignore_ascii_case("changed_hash")
                        || value.trim().eq_ignore_ascii_case("hash_changed")
                        || value.trim().eq_ignore_ascii_case("source_changed");
                    if changed {
                        select(true)?;
                    }
                }
                Value::Array(values) => {
                    for item in values {
                        let item = item
                            .as_str()
                            .ok_or_else(|| "native_policy_changed_hash_invalid".to_owned())?;
                        if item.eq_ignore_ascii_case("changed_hash")
                            || item.eq_ignore_ascii_case("hash_changed")
                            || item.eq_ignore_ascii_case("source_changed")
                        {
                            select(true)?;
                        }
                    }
                }
                _ => return Err("native_policy_changed_hash_invalid".to_owned()),
            }
        }
    }
    Ok(selected.unwrap_or(false))
}

pub(super) fn optional_hash(
    maps: &[&Map<String, Value>],
    keys: &[&str],
) -> Result<Option<String>, String> {
    let mut selected: Option<String> = None;
    for record in maps {
        for key in keys {
            let Some(value) = record.get(*key) else {
                continue;
            };
            let Some(value) = value.as_str() else {
                return Err("native_policy_changed_hash_invalid".to_owned());
            };
            let value = bounded_selector_value(value)?;
            if selected
                .as_deref()
                .is_some_and(|previous| previous != value)
            {
                return Err("native_policy_changed_hash_conflict".to_owned());
            }
            selected = Some(value);
        }
    }
    Ok(selected)
}

pub(super) fn payload_changed_hash(maps: &[&Map<String, Value>]) -> Result<bool, String> {
    let explicit = optional_changed_bool(maps)?;
    let previous = optional_hash(
        maps,
        &["previous_hash", "previousHash", "prior_hash", "priorHash"],
    )?;
    let current = optional_hash(
        maps,
        &[
            "current_hash",
            "currentHash",
            "actual_hash",
            "actualHash",
            "source_hash",
            "sourceHash",
            "output_sha256",
            "outputSha256",
        ],
    )?;
    Ok(explicit || previous.is_some() && current.is_some() && previous != current)
}

pub(super) fn payload_facts(
    payload: &Value,
    harness: &str,
    action_type: PreToolActionTypeV1,
    reason_code: &str,
) -> Result<PolicyFacts, String> {
    let mut maps = Vec::new();
    let mut nodes = 0usize;
    collect_fact_maps(payload, 0, &mut nodes, &mut maps)?;
    let publisher = optional_identity(&maps, PUBLISHER_KEYS)?;
    let artifact = optional_identity(&maps, ARTIFACT_KEYS)?;
    let budget_input = codex_command_budget_input(payload, harness, action_type);
    // Only an exact root-level, syntactically bounded process start identity
    // is timing metadata. Nested copies, extra keys, credentials and command
    // floors retain ordinary enforcement. This grants no process authority.
    let wait_process = codex_browser_process_metadata(payload, harness);
    let sensitive_target = payload_sensitive_target(&maps, budget_input, wait_process)?
        || reason_code.contains("secret")
        || reason_code.contains("credential")
        || reason_code.contains("exfiltration");
    let publisher_relevant = publisher.is_some()
        || artifact.is_some()
        || matches!(
            action_type,
            PreToolActionTypeV1::Package | PreToolActionTypeV1::McpTool
        );
    Ok(PolicyFacts {
        publisher,
        artifact,
        changed_hash: payload_changed_hash(&maps)?,
        sensitive_target,
        publisher_relevant,
    })
}
