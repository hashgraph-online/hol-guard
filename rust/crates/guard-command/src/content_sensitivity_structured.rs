//! Declared schema presence scanning; no personal inference or value disclosure.

use std::collections::{BTreeSet, HashMap};
use std::time::Instant;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::json_tree::{self, Node};
use super::patterns;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Field {
    pub path: Vec<String>,
    pub role: String,
    pub value_type: String,
    pub category: Option<String>,
}

pub(super) fn fields(value: &Value) -> Result<Vec<Field>, String> {
    let raw = value.as_array().ok_or("declared schema size is invalid")?;
    for field in raw {
        if !field["path"].is_array()
            || !field["path"]
                .as_array()
                .is_some_and(|path| path.iter().all(Value::is_string))
        {
            return Err("declared field path is invalid".into());
        }
        if !field["value_type"].is_string() {
            return Err("declared field type is invalid".into());
        }
        if !field["role"].is_string() {
            return Err("declared field role is invalid".into());
        }
        if !field["category"].is_null() && !field["category"].is_string() {
            return Err(if field["role"] == "protected_personal" {
                "protected personal category is invalid"
            } else {
                "declared field role is invalid"
            }
            .into());
        }
    }
    let fields: Vec<Field> = serde_json::from_value(value.clone())
        .map_err(|_| "declared schema size is invalid".to_owned())?;
    if fields.is_empty() || fields.len() > 64 {
        return Err("declared schema size is invalid".into());
    }
    let segment = Regex::new(r"\A[A-Za-z][A-Za-z0-9_]{0,63}\z")
        .map_err(|_| "declared field path is invalid")?;
    let mut paths = BTreeSet::new();
    for field in &fields {
        if field.path.is_empty()
            || field.path.len() > 8
            || field.path.iter().any(|part| !segment.is_match(part))
        {
            return Err("declared field path is invalid".into());
        }
        if !matches!(field.value_type.as_str(), "string" | "integer") {
            return Err("declared field type is invalid".into());
        }
        if field.role == "protected_personal" {
            if !matches!(
                field.category.as_deref(),
                Some("person_name" | "email_address" | "employee_id")
            ) {
                return Err("protected personal category is invalid".into());
            }
        } else if field.role != "ordinary" || field.category.is_some() {
            return Err("declared field role is invalid".into());
        }
        if !paths.insert(field.path.clone()) {
            return Err("declared schema contains duplicate paths".into());
        }
    }
    Ok(fields)
}

pub(super) fn version(fields: Option<&[Field]>) -> Result<String, &'static str> {
    let fields = fields.unwrap_or_default().iter().map(|field| json!({
        "path":field.path,"role":field.role,"type":field.value_type,"category":field.category
    })).collect::<Vec<_>>();
    patterns::digest(&json!({"classifier":"structured-sensitive-v1",
        "credentialRules":patterns::version()?,"fields":fields}))
}

struct Scan {
    matches: Vec<Value>,
    bytes: usize,
    fields: usize,
    version: String,
}

impl Scan {
    fn result(&self, status: &str, reason: &str, complete: bool) -> Value {
        json!({"status":status,"matches":self.matches.iter().take(16).collect::<Vec<_>>(),
            "complete":complete,"reason_code":reason,"bytes_scanned":self.bytes,
            "fields_scanned":self.fields,"rule_version":self.version})
    }
}

pub(super) fn scan(
    text: &str,
    fields: Option<&[Field]>,
    deadline: Instant,
) -> Result<Value, &'static str> {
    let mut scan = Scan {
        matches: Vec::new(),
        bytes: 0,
        fields: 0,
        version: version(fields)?,
    };
    if text.len() > 65_536 {
        return Ok(scan.result("unsupported", "input_too_large", false));
    }
    let chars = text.chars().collect::<Vec<_>>();
    let mut tail = String::new();
    let mut credentials = Vec::<Value>::new();
    let mut seen = BTreeSet::new();
    let mut complete = true;
    for chunk in chars.chunks(4096) {
        if Instant::now() >= deadline {
            return Ok(scan.result("unsupported", "scan_budget_exhausted", false));
        }
        let chunk = chunk.iter().collect::<String>();
        scan.bytes += chunk.len();
        let window = tail + &chunk;
        let found =
            patterns::content(Some(&window), true, false, deadline).and_then(|suppressed| {
                if suppressed.as_array().is_some_and(Vec::is_empty) {
                    patterns::content(Some(&window), false, false, deadline)
                } else {
                    Ok(suppressed)
                }
            });
        let found = match found {
            Ok(found) => found,
            Err("content_scan_deadline_exceeded") => {
                return Ok(scan.result("unsupported", "scan_budget_exhausted", false));
            }
            Err(error) => return Err(error),
        };
        for found in found.as_array().ok_or("content_scan_unavailable")? {
            let classifier = found["classifier"]
                .as_str()
                .ok_or("content_scan_unavailable")?;
            if seen.insert(classifier.to_owned()) {
                credentials.push(found.clone());
            }
        }
        if credentials
            .iter()
            .any(|found| matches!(found["sensitivity"].as_str(), Some("high" | "critical")))
            || credentials.len() >= 16
        {
            complete = false;
            break;
        }
        tail = window
            .chars()
            .rev()
            .take(8192)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
    }
    scan.matches.extend(credentials.iter().take(16).map(|found| json!({
        "category":format!("credential.{}",found["classifier"].as_str().unwrap_or_default()),
        "sensitivity":found["sensitivity"],"field_path":[],"reason":"declared_credential_pattern_present"
    })));
    if Instant::now() >= deadline {
        return Ok(scan.result("unsupported", "scan_budget_exhausted", false));
    }
    if text.contains('\\') {
        return Ok(scan.result("unsupported", "encoded_or_escaped_content", false));
    }
    let Some(fields) = fields else {
        return Ok(scan.result(
            if scan.matches.is_empty() {
                "no_declared_match"
            } else {
                "matched"
            },
            "credential_scan",
            complete,
        ));
    };
    let tree = match json_tree::parse(text) {
        Ok(tree) => tree,
        Err(()) => return Ok(scan.result("unsupported", "invalid_or_duplicate_json", false)),
    };
    if !matches!(tree, Node::Object(_)) {
        return Ok(scan.result("unsupported", "root_object_required", false));
    }
    let declared = fields
        .iter()
        .map(|field| (field.path.clone(), field))
        .collect::<HashMap<_, _>>();
    let objects = fields
        .iter()
        .flat_map(|field| (1..field.path.len()).map(|n| field.path[..n].to_vec()))
        .collect::<BTreeSet<_>>();
    let mut stack = vec![(Vec::<String>::new(), &tree)];
    let mut nodes = 0;
    while let Some((path, node)) = stack.pop() {
        if Instant::now() >= deadline {
            return Ok(scan.result("unsupported", "scan_budget_exhausted", false));
        }
        nodes += 1;
        if nodes > 128 || path.len() > 8 {
            return Ok(scan.result("unsupported", "structure_limit_exceeded", false));
        }
        match node {
            Node::Object(pairs) => {
                if declared.contains_key(&path) {
                    return Ok(scan.result("unsupported", "field_type_invalid", false));
                }
                if !path.is_empty() && !objects.contains(&path) {
                    return Ok(scan.result("unsupported", "unknown_field", false));
                }
                for (key, child) in pairs {
                    let mut child_path = path.clone();
                    child_path.push(key.clone());
                    stack.push((child_path, child));
                }
            }
            Node::Array => return Ok(scan.result("unsupported", "array_unsupported", false)),
            Node::Scalar(value) => {
                scan.fields += 1;
                if scan.fields > 64 {
                    return Ok(scan.result("unsupported", "field_limit_exceeded", false));
                }
                let Some(field) = declared.get(&path) else {
                    return Ok(scan.result("unsupported", "unknown_field", false));
                };
                let is_integer = value
                    .as_number()
                    .is_some_and(|number| !number.to_string().contains(['.', 'e', 'E']));
                if !(field.value_type == "string" && value.is_string()
                    || field.value_type == "integer" && is_integer)
                {
                    return Ok(scan.result("unsupported", "field_type_invalid", false));
                }
                let present =
                    value.as_str().is_some_and(|value| !value.trim().is_empty()) || is_integer;
                if field.role == "protected_personal" && present {
                    scan.matches.push(json!({"category":format!("personal.{}",field.category.as_deref().unwrap_or_default()),
                        "sensitivity":"high","field_path":path,"reason":"declared_protected_field_present"}));
                    if scan.matches.len() > 16 {
                        return Ok(scan.result("unsupported", "match_limit_exceeded", false));
                    }
                }
            }
        }
    }
    Ok(scan.result(
        if scan.matches.is_empty() {
            "no_declared_match"
        } else {
            "matched"
        },
        "declared_schema_scan",
        complete,
    ))
}

pub(super) fn unsupported(fields: Option<&[Field]>, reason: &str) -> Result<Value, &'static str> {
    Ok(Scan {
        matches: Vec::new(),
        bytes: 0,
        fields: 0,
        version: version(fields)?,
    }
    .result("unsupported", reason, false))
}

pub(super) fn canonical(value: &Value) -> Option<String> {
    let text = value.as_str()?;
    if text.is_empty() || text.len() > 65_536 || text.contains('\\') {
        return None;
    }
    let tree = json_tree::parse(text).ok()?;
    if !matches!(tree, Node::Object(_)) {
        return None;
    }
    let canonical = serde_json::to_string(&json_tree::canonical(&tree)?).ok()?;
    (canonical == text).then_some(canonical)
}
