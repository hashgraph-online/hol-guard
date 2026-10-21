//! MCP tool-call risk categories. Python supplies artifact and argument DTOs.
use fancy_regex::Regex;
use guard_contracts::{BrowserIntentV1, BrowserMcpArtifactV1};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::OnceLock;

const NAMES: [&str; 15] = [
    "filesystem_access",
    "command_execution",
    "destructive_mutation",
    "outbound_network",
    "privileged_system_mutation",
    "secret_access",
    "tool_schema_mismatch",
    "browser_navigation",
    "browser_inspection",
    "browser_interaction",
    "browser_transfer",
    "browser_privileged",
    "browser_external_domain",
    "browser_shared_profile",
    "browser_sensitive_surface",
];
const FILESYSTEM: u16 = 1;
const COMMAND: u16 = 1 << 1;
const DESTRUCTIVE: u16 = 1 << 2;
const NETWORK: u16 = 1 << 3;
const PRIVILEGED: u16 = 1 << 4;
const SECRET: u16 = 1 << 5;

struct Patterns {
    command: Regex,
    network: Regex,
    secret: Regex,
    privileged: Regex,
    ip: Regex,
    read: Regex,
    write: Regex,
    run: Regex,
}
fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let compile = |text: &str| Regex::new(text).expect("static MCP risk pattern must compile");
        Patterns {
            command: compile(r"(?<![a-z0-9_])(subprocess|child_process|childprocess|popen|os\.system|runtime\.exec)(?![a-z0-9_])|(?<![a-z0-9_])(spawn|execfile|system)(?:_sync)?[\s\x{001c}-\x{001f}]*\("),
            network: compile(r"https?://|(?<![a-z0-9])(curl|wget|fetch|axios|requests)(?![a-z0-9])|(?<![a-z0-9_])(?:socket|net|dns)[\s\x{001c}-\x{001f}]*[.(]|(?<![a-z0-9_])(?:create_connection|getaddrinfo|gethostbyname|sendto|recvfrom)[\s\x{001c}-\x{001f}]*\(|(?<![a-z0-9_])(?:urllib(?:\.request)?|http\.client|https?)[\s\x{001c}-\x{001f}]*\.|(?<![a-z0-9_])(udp|tcp|socks|proxy|tunnel|port_forward|port-forward)(?![a-z0-9_])"),
            secret: compile(r"(?<![a-z0-9_-])\.(env|ssh|npmrc|pypirc)(?![a-z0-9_-])|(?<![a-z0-9])(id[_-]?rsa|credentials|token|secret|passwd)(?![a-z0-9])"),
            privileged: compile(r"(?<![a-z0-9])(sudo|chmod|chown|launchctl|systemctl)(?![a-z0-9])"),
            ip: compile(r"(?i)(?<![0-9a-z])\[?([0-9a-f:.]{3,})\]?(?![0-9a-z])"),
            read: compile(r"\bread files?\b|\bopen files?\b|\bview files?\b"),
            write: compile(r"(?<![a-z0-9])(delete|remove|write)(?![a-z0-9])"),
            run: compile(r"\brun command|(?<![a-z0-9])(execute|shell)(?![a-z0-9])"),
        }
    })
}

fn normalized(text: &str) -> String {
    normalized_parts(text, "")
}
fn normalized_parts(first: &str, second: &str) -> String {
    let mut output =
        String::with_capacity(first.len() + second.len() + usize::from(!second.is_empty()));
    let mut previous = None;
    for ch in first
        .chars()
        .chain((!second.is_empty()).then_some(' '))
        .chain(second.chars())
    {
        if ch.is_ascii_uppercase()
            && previous.is_some_and(|prev: char| prev.is_ascii_lowercase() || prev.is_ascii_digit())
        {
            output.push(' ');
        }
        output.extend(ch.to_lowercase());
        previous = Some(ch);
    }
    output
}
fn matches(pattern: &Regex, text: &str) -> Result<bool, &'static str> {
    pattern
        .is_match(text)
        .map_err(|_| "native_mcp_risk_pattern_failed")
}
fn key_categories(key: &str) -> u16 {
    let mut key = normalized(key);
    key.retain(|ch| ch.is_ascii_alphanumeric());
    match key.as_str() {
        "file" | "filepath" | "filepaths" | "files" | "path" | "paths" | "source"
        | "sourcepath" | "sourcepaths" | "sources" | "target" | "targetpath" | "targetpaths"
        | "targets" => FILESYSTEM,
        "command" | "cmd" | "script" | "shell" => COMMAND,
        "callback" | "endpoint" | "uri" | "url" | "urls" | "webhook" => NETWORK,
        _ => 0,
    }
}
fn argument_categories(value: &Value) -> u16 {
    if !value.is_object() {
        return 0;
    }
    let mut pending = vec![value];
    let mut categories = 0;
    while let Some(current) = pending.pop() {
        match current {
            Value::Object(object) => {
                for (key, item) in object {
                    categories |= key_categories(key);
                    pending.push(item);
                }
            }
            Value::Array(items) => pending.extend(items),
            _ => (),
        }
    }
    categories
}
fn anchor<'a>(root: &'a Value, name: &str) -> Option<&'a Value> {
    let mut pending = vec![root];
    while let Some(current) = pending.pop() {
        match current {
            Value::Object(object) => {
                if object.get("$anchor").and_then(Value::as_str) == Some(name)
                    || object.get("$dynamicAnchor").and_then(Value::as_str) == Some(name)
                {
                    return Some(current);
                }
                pending.extend(object.values());
            }
            Value::Array(items) => pending.extend(items),
            _ => (),
        }
    }
    None
}
fn resolve_ref<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    if let Some(pointer) = reference.strip_prefix("#/") {
        let mut current = root;
        for part in pointer.split('/') {
            let token = if part.contains('~') {
                Cow::Owned(part.replace("~1", "/").replace("~0", "~"))
            } else {
                Cow::Borrowed(part)
            };
            current = match current {
                Value::Object(object) => object.get(token.as_ref())?,
                Value::Array(items) => {
                    if token.is_empty() || !token.chars().all(|ch| ch.is_ascii_digit()) {
                        return None;
                    }
                    items.get(token.parse::<usize>().ok()?)?
                }
                _ => return None,
            };
        }
        Some(current)
    } else {
        let name = reference.strip_prefix('#')?;
        if name.is_empty() {
            Some(root)
        } else {
            anchor(root, name)
        }
    }
}
fn schema_categories(root: &Value) -> u16 {
    if !root.is_object() && !root.is_array() {
        return 0;
    }
    let mut pending = vec![(root, None)];
    let mut visited = HashSet::new();
    let mut references = HashSet::new();
    let mut categories = 0;
    while let Some((current, schema_root)) = pending.pop() {
        match current {
            Value::Object(object) => {
                let schema_root = schema_root.unwrap_or(current);
                if !visited.insert(current as *const Value) {
                    continue;
                }
                if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                    if references.insert(reference) {
                        if let Some(resolved) = resolve_ref(schema_root, reference) {
                            pending.push((resolved, Some(schema_root)));
                        }
                    }
                }
                if let Some(properties) = object.get("properties").and_then(Value::as_object) {
                    for (key, item) in properties {
                        categories |= key_categories(key);
                        pending.push((item, Some(schema_root)));
                    }
                }
                for key in [
                    "additionalProperties",
                    "allOf",
                    "anyOf",
                    "contains",
                    "else",
                    "if",
                    "items",
                    "oneOf",
                    "prefixItems",
                    "propertyNames",
                    "then",
                    "unevaluatedItems",
                    "unevaluatedProperties",
                ] {
                    if let Some(child) = object.get(key) {
                        pending.push((child, Some(schema_root)));
                    }
                }
                for key in ["dependentSchemas", "patternProperties"] {
                    if let Some(children) = object.get(key).and_then(Value::as_object) {
                        pending.extend(children.values().map(|child| (child, Some(schema_root))));
                    }
                }
            }
            Value::Array(items) => pending.extend(items.iter().map(|child| (child, schema_root))),
            _ => (),
        }
    }
    categories
}
fn contains_ip(text: &str) -> Result<bool, &'static str> {
    // Python's IGNORECASE treats dotless i as ASCII i at the IP boundary.
    let text = if text.contains('\u{0131}') {
        Cow::Owned(text.replace('\u{0131}', "i"))
    } else {
        Cow::Borrowed(text)
    };
    for capture in patterns().ip.captures_iter(text.as_ref()) {
        let capture = capture.map_err(|_| "native_mcp_risk_pattern_failed")?;
        let mut candidate = capture.get(1).expect("IP capture exists").as_str();
        if candidate.bytes().filter(|ch| *ch == b':').count() == 1 && candidate.contains('.') {
            candidate = candidate.split_once(':').unwrap().0;
        }
        if candidate.trim_matches('.').parse::<IpAddr>().is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn evaluate_tool_risk(
    artifact: &BrowserMcpArtifactV1,
    arguments: &Value,
) -> Result<Vec<String>, &'static str> {
    let p = patterns();
    let mut serialized = Vec::new();
    if !arguments.is_null() {
        guard_contracts::write_python_default_json(arguments, &mut serialized)?;
    }
    let serialized =
        std::str::from_utf8(&serialized).map_err(|_| "native_mcp_risk_serialization_failed")?;
    let combined = normalized_parts(&artifact.name, serialized);
    let operation = artifact
        .command
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(&artifact.name)
        .rsplit('/')
        .find(|value| !value.is_empty())
        .unwrap_or("");
    let operation = normalized(operation);
    let (token_bits, dangerous_name) = operation
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .fold((0, false), |(bits, dangerous), token| {
            let category = match token {
                "delete" | "remove" | "rm" | "destroy" | "erase" => DESTRUCTIVE,
                "shell" | "bash" | "exec" | "execute" | "command" | "powershell" => COMMAND,
                _ => 0,
            };
            (
                bits | category,
                dangerous
                    || matches!(
                        token,
                        "bash"
                            | "cmd"
                            | "command"
                            | "delete"
                            | "destroy"
                            | "exec"
                            | "execute"
                            | "patch"
                            | "remove"
                            | "rm"
                            | "run"
                            | "script"
                            | "shell"
                            | "write"
                    ),
            )
        });
    let arg = argument_categories(arguments);
    let schema = artifact
        .metadata
        .get("tool_schema")
        .map_or(0, schema_categories);
    let description = artifact
        .metadata
        .get("tool_description")
        .and_then(Value::as_str)
        .map(normalized);
    let mut description_bits = 0;
    if let Some(description) = description.as_deref() {
        if matches(&p.read, description)? {
            description_bits |= FILESYSTEM;
        }
        if matches(&p.write, description)? {
            description_bits |= DESTRUCTIVE;
        }
        if matches(&p.run, description)? {
            description_bits |= COMMAND;
        }
    }
    let browser = crate::browser_mcp_intent::browser_risk_facts(artifact, arguments);
    let navigation = browser
        .as_ref()
        .is_some_and(|browser| browser.intent == BrowserIntentV1::Navigation);
    let mut bits = arg | schema | description_bits | token_bits;
    if matches(&p.command, &combined)? {
        bits |= COMMAND;
    }
    if !navigation && (matches(&p.network, &combined)? || contains_ip(&combined)?) {
        bits |= NETWORK;
    }
    if matches(&p.secret, &combined)? {
        bits |= SECRET;
    }
    if matches(&p.privileged, &combined)? {
        bits |= PRIVILEGED;
    }
    let mismatch_schema = if navigation {
        schema & !NETWORK
    } else {
        schema
    };
    if mismatch_schema & (COMMAND | DESTRUCTIVE | NETWORK) != 0 && !dangerous_name {
        bits |= 1 << 6;
    }
    if let Some(browser) = browser {
        if arg & FILESYSTEM == 0 && description_bits & FILESYSTEM == 0 {
            bits &= !FILESYSTEM;
        }
        use BrowserIntentV1::*;
        match browser.intent {
            Navigation => {
                bits |= 1 << 7;
                bits &= !NETWORK;
                if browser.external_domain {
                    bits |= 1 << 12;
                }
            }
            Inspect => bits |= 1 << 8,
            Interact => bits |= 1 << 9,
            Transfer => bits |= 1 << 10,
            Privileged => bits |= 1 << 11,
        }
        if browser.shared_profile {
            bits |= 1 << 13;
        }
        if browser.sensitive_surface {
            bits |= 1 << 14;
        }
    }
    let mut categories = Vec::with_capacity(bits.count_ones() as usize);
    for (index, name) in NAMES.iter().enumerate() {
        if bits & (1 << index) != 0 {
            categories.push((*name).to_owned());
        }
    }
    Ok(categories)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_risk_respects_unicode_case_insensitive_boundary() {
        for (name, expected) in [
            ("\u{0131}192.168.1.1/safe", Vec::<String>::new()),
            ("192.168.1.1/safe", vec!["outbound_network".to_owned()]),
        ] {
            let artifact = BrowserMcpArtifactV1 {
                name: name.to_owned(),
                command: None,
                metadata: Default::default(),
            };
            assert_eq!(
                evaluate_tool_risk(&artifact, &Value::Null).unwrap(),
                expected
            );
        }
    }
}
