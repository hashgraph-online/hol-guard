//! Browser MCP semantic authority. Python transports artifacts and arguments.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::OnceLock;

use guard_contracts::{
    BrowserAutomationIntentV1, BrowserIntentV1, BrowserMcpArgumentsV1, BrowserMcpArtifactV1,
    BrowserMcpDisplayIntentV1, BrowserMcpRequestV1, BrowserMcpResultV1, BrowserMethodV1,
    BrowserProfileModeV1, BrowserSensitiveSurfaceV1,
};
use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

use crate::cloud_audit_sync::{urlparse_path_end, urlsplit, urlunsplit, UrlSplit};
use crate::local_supply_chain::{unquote_plus, urlencode};
use crate::target_identities::py_str;

include!("browser_mcp_patterns.rs");

struct Patterns {
    server: RegexSet,
    package: RegexSet,
    chrome: Regex,
    playwright: Regex,
    other_browser: Regex,
    navigation: RegexSet,
    inspect: RegexSet,
    interact: RegexSet,
    transfer: RegexSet,
    privileged: RegexSet,
}

fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let set = |expressions: &[&str]| {
            RegexSetBuilder::new(expressions)
                .case_insensitive(true)
                .build()
                .expect("static browser regex set")
        };
        let regex = |expression: &str| {
            RegexBuilder::new(expression)
                .case_insensitive(true)
                .build()
                .expect("static browser regex")
        };
        Patterns {
            server: set(BROWSER_SERVER_NAME_PATTERNS),
            package: set(BROWSER_PACKAGE_PATTERNS),
            chrome: regex(r"chrome[\-_\s\x{001c}-\x{001f}]?devtools"),
            playwright: regex(r"@playwright/mcp|playwright"),
            other_browser: regex(r"browser[\-_\s\x{001c}-\x{001f}]?(tools|mcp)|puppeteer"),
            navigation: set(NAVIGATION_PATTERNS),
            inspect: set(INSPECT_PATTERNS),
            interact: set(INTERACT_PATTERNS),
            transfer: set(TRANSFER_PATTERNS),
            privileged: set(PRIVILEGED_PATTERNS),
        }
    })
}

// CPython IGNORECASE also folds dotless i and long s. Callers have already
// applied str.lower(), including its dotted-I expansion.
fn regex_text(text: &str) -> Cow<'_, str> {
    if text.contains(['\u{0131}', '\u{017f}']) {
        Cow::Owned(
            text.chars()
                .map(|ch| match ch {
                    '\u{0131}' => 'i',
                    '\u{017f}' => 's',
                    other => other,
                })
                .collect(),
        )
    } else {
        Cow::Borrowed(text)
    }
}

fn optional_str(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(|text| {
            text.trim_matches(|ch: char| {
                ch.is_whitespace() || matches!(ch, '\u{001c}'..='\u{001f}')
            })
        })
        .filter(|text| !text.is_empty())
}

fn scalar_text(value: Option<&Value>) -> Cow<'_, str> {
    match value {
        None => Cow::Borrowed(""),
        Some(Value::String(text)) => Cow::Borrowed(text),
        Some(value) => Cow::Owned(py_str(value)),
    }
}

fn is_browser_server(artifact: &BrowserMcpArtifactV1) -> bool {
    let server = scalar_text(artifact.metadata.get("server_name"));
    let mut combined = String::with_capacity(server.len() + artifact.name.len() + 1);
    combined.extend(server.chars().flat_map(char::to_lowercase));
    combined.push(' ');
    combined.extend(artifact.name.chars().flat_map(char::to_lowercase));
    let matchers = patterns();
    if matchers.server.is_match(&regex_text(&combined)) {
        return true;
    }
    if let Some(identity) = artifact
        .metadata
        .get("mcp_server_identity")
        .and_then(Value::as_object)
    {
        let package = scalar_text(identity.get("package_name")).to_lowercase();
        if matchers.package.is_match(&regex_text(&package)) {
            return true;
        }
    }
    if artifact
        .metadata
        .get("mcp_tool_identity")
        .is_some_and(Value::is_object)
    {
        let operation = artifact
            .command
            .as_deref()
            .filter(|text| !text.is_empty())
            .unwrap_or(&artifact.name)
            .to_lowercase();
        return [
            "browser_",
            "navigate",
            "screenshot",
            "snapshot",
            "click",
            "page",
        ]
        .iter()
        .any(|marker| operation.contains(marker))
            && ["browser", "chrome", "playwright", "devtools", "puppeteer"]
                .iter()
                .any(|marker| combined.contains(marker));
    }
    false
}

pub fn classify_operation(operation: &str, server_name: &str) -> Option<BrowserIntentV1> {
    use BrowserIntentV1::*;
    let operation = operation.to_lowercase();
    let server = server_name.to_lowercase();
    let server = regex_text(&server);
    let matchers = patterns();
    let chrome = matchers.chrome.is_match(&server);
    let playwright = matchers.playwright.is_match(&server);
    let categories = [Navigation, Inspect, Interact, Transfer, Privileged];
    if chrome {
        for (table, intent) in [
            CHROME_DEVTOOLS_NAVIGATION,
            CHROME_DEVTOOLS_INSPECT,
            CHROME_DEVTOOLS_INTERACT,
            CHROME_DEVTOOLS_TRANSFER,
            CHROME_DEVTOOLS_PRIVILEGED,
        ]
        .into_iter()
        .zip(categories)
        {
            if table.binary_search(&operation.as_str()).is_ok() {
                return Some(intent);
            }
        }
    }
    if playwright {
        for (table, intent) in [
            PLAYWRIGHT_NAVIGATION,
            PLAYWRIGHT_INSPECT,
            PLAYWRIGHT_INTERACT,
            PLAYWRIGHT_TRANSFER,
            PLAYWRIGHT_PRIVILEGED,
        ]
        .into_iter()
        .zip(categories)
        {
            if table.binary_search(&operation.as_str()).is_ok() {
                return Some(intent);
            }
        }
    }
    if chrome || playwright || matchers.other_browser.is_match(&server) {
        let operation = regex_text(&operation);
        for (expressions, intent) in [
            (&matchers.navigation, Navigation),
            (&matchers.privileged, Privileged),
            (&matchers.transfer, Transfer),
            (&matchers.interact, Interact),
            (&matchers.inspect, Inspect),
        ] {
            if expressions.is_match(&operation) {
                return Some(intent);
            }
        }
    }
    None
}

enum ArgumentValues<'a> {
    Borrowed(BTreeMap<&'a str, &'a Value>),
    Object(&'a Map<String, Value>),
    Parsed(Map<String, Value>),
}

impl ArgumentValues<'_> {
    fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Borrowed(values) => values.get(key).copied(),
            Self::Object(values) => values.get(key),
            Self::Parsed(values) => values.get(key),
        }
    }

    fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    fn keys(&self) -> impl Iterator<Item = &str> {
        let (borrowed, parsed) = match self {
            Self::Borrowed(values) => (Some(values), None),
            Self::Parsed(values) => (None, Some(values)),
            Self::Object(values) => (None, Some(*values)),
        };
        borrowed
            .into_iter()
            .flat_map(|values| values.keys().copied())
            .chain(
                parsed
                    .into_iter()
                    .flat_map(|values| values.keys().map(String::as_str)),
            )
    }
}

struct Arguments<'a> {
    values: ArgumentValues<'a>,
    volatile: Vec<String>,
}

#[derive(Default)]
struct ParsedArguments {
    values: Map<String, Value>,
    volatile: Vec<String>,
}

impl<'de> Deserialize<'de> for ParsedArguments {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ArgumentVisitor;
        impl<'de> Visitor<'de> for ArgumentVisitor {
            type Value = ParsedArguments;
            fn expecting(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                out.write_str("a browser argument object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ParsedArguments, A::Error> {
                let mut arguments = ParsedArguments::default();
                while let Some((key, value)) = map.next_entry::<String, Value>()? {
                    if VOLATILE_FIELDS.binary_search(&key.as_str()).is_ok()
                        && !arguments.values.contains_key(&key)
                    {
                        arguments.volatile.push(key.clone());
                    }
                    arguments.values.insert(key, value);
                }
                Ok(arguments)
            }
        }
        deserializer.deserialize_map(ArgumentVisitor)
    }
}

fn arguments(value: &BrowserMcpArgumentsV1) -> Result<Arguments<'_>, &'static str> {
    match value {
        BrowserMcpArgumentsV1::Mapping { entries } => {
            let mut values = BTreeMap::new();
            let mut volatile = Vec::new();
            for (key, value) in entries {
                if values.insert(key.as_str(), value).is_some() {
                    return Err("native_browser_argument_key_duplicated");
                }
                if VOLATILE_FIELDS.binary_search(&key.as_str()).is_ok() {
                    volatile.push(key.clone());
                }
            }
            Ok(Arguments {
                values: ArgumentValues::Borrowed(values),
                volatile,
            })
        }
        BrowserMcpArgumentsV1::Json { text } => {
            let parsed: ParsedArguments = serde_json::from_str(text).unwrap_or_default();
            Ok(Arguments {
                values: ArgumentValues::Parsed(parsed.values),
                volatile: parsed.volatile,
            })
        }
        BrowserMcpArgumentsV1::Other => Ok(Arguments {
            values: ArgumentValues::Parsed(Map::new()),
            volatile: Vec::new(),
        }),
    }
}

fn tool_operation(artifact: &BrowserMcpArtifactV1) -> &str {
    if let Some(command) = artifact
        .command
        .as_deref()
        .filter(|command| !command.is_empty())
    {
        return command;
    }
    if let Some(name) = artifact
        .metadata
        .get("mcp_tool_identity")
        .and_then(Value::as_object)
        .and_then(|identity| optional_str(identity.get("tool_name")))
    {
        return name;
    }
    artifact.name.rsplit(':').next().unwrap_or(&artifact.name)
}

fn target_url<'a>(values: &'a ArgumentValues<'_>) -> Option<&'a str> {
    for key in URL_ARGUMENT_KEYS {
        if let Some(url) = optional_str(values.get(key)) {
            return Some(url);
        }
    }
    if let Some(url) = values
        .get("locator")
        .and_then(Value::as_object)
        .and_then(|locator| optional_str(locator.get("url")))
    {
        return Some(url);
    }
    values
        .get("arguments")
        .and_then(Value::as_object)
        .and_then(|nested| optional_str(nested.get("url")))
}

fn hostname(parts: &UrlSplit) -> Option<&str> {
    let netloc = parts.netloc.rsplit('@').next().unwrap_or(&parts.netloc);
    let host = if let Some(bracketed) = netloc.strip_prefix('[') {
        bracketed.split_once(']')?.0
    } else {
        netloc.split(':').next()?
    };
    (!host.is_empty()).then_some(host)
}

fn domain(parts: &UrlSplit) -> Option<String> {
    let host = hostname(parts)?;
    // urllib preserves the case of an IPv6 zone identifier.
    Some(if let Some((address, zone)) = host.split_once('%') {
        format!("{}%{}", address.to_lowercase(), zone)
    } else {
        host.to_lowercase()
    })
}

fn path_prefix(parts: &UrlSplit) -> String {
    parts.path[..urlparse_path_end(parts)].to_owned()
}

fn query_key(key: &str) -> String {
    key.chars()
        .flat_map(char::to_lowercase)
        .filter(char::is_ascii_alphanumeric)
        .collect()
}

fn redacted_query(query: &str) -> String {
    let pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|field| !field.is_empty())
        .map(|field| {
            let (key, value) = field.split_once('=').unwrap_or((field, ""));
            let key = unquote_plus(key);
            let value = if REDACT_QUERY_KEYS
                .binary_search(&query_key(&key).as_str())
                .is_ok()
            {
                "[redacted]".to_owned()
            } else {
                unquote_plus(value)
            };
            (key, value)
        })
        .collect();
    urlencode(&pairs)
}

fn redacted_fragment(fragment: &str) -> String {
    if fragment.is_empty() {
        return String::new();
    }
    if fragment.starts_with('/') || fragment.starts_with("!/") {
        return match fragment.split_once('?') {
            Some((route, query)) => format!("{route}?{}", redacted_query(query)),
            None => fragment.to_owned(),
        };
    }
    if !fragment.contains('=') {
        return String::new();
    }
    redacted_query(fragment)
}

fn redacted_url(parts: &UrlSplit) -> String {
    urlunsplit(
        &parts.scheme,
        &parts.netloc,
        &parts.path,
        &redacted_query(&parts.query),
        &redacted_fragment(&parts.fragment),
    )
}

fn profile_mode(metadata: &Map<String, Value>) -> BrowserProfileModeV1 {
    use BrowserProfileModeV1::*;
    let identity_args = metadata
        .get("mcp_server_identity")
        .and_then(Value::as_object)
        .and_then(|identity| identity.get("args"))
        .and_then(Value::as_array);
    let direct_args = metadata.get("args").and_then(Value::as_array);
    let server_args = metadata.get("server_args").and_then(Value::as_array);
    let flags = |prefixes: &[&str]| {
        [identity_args, direct_args, server_args]
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(Value::as_str)
            .any(|arg| prefixes.iter().any(|prefix| arg.starts_with(prefix)))
    };
    if flags(ISOLATED_FLAGS) {
        return Isolated;
    }
    if flags(REMOTE_DEBUG_FLAGS) {
        return RemoteDebugging;
    }
    if flags(PROFILE_DIR_FLAGS) {
        return Dedicated;
    }
    if flags(&["--shared", "--no-isolated"]) {
        return Shared;
    }
    Unknown
}

fn sensitive_surfaces(
    operation: &str,
    values: &ArgumentValues<'_>,
    metadata: &Map<String, Value>,
) -> Vec<BrowserSensitiveSurfaceV1> {
    let mut surfaces = Vec::new();
    visit_sensitive_surfaces(operation, values, metadata, |surface| {
        if !surfaces.contains(&surface) {
            surfaces.push(surface);
        }
    });
    surfaces
}

fn visit_sensitive_surfaces(
    operation: &str,
    values: &ArgumentValues<'_>,
    metadata: &Map<String, Value>,
    mut add: impl FnMut(BrowserSensitiveSurfaceV1),
) {
    use BrowserSensitiveSurfaceV1::*;
    let operation = operation.to_lowercase();
    let description = metadata
        .get("tool_description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();
    let keys: Vec<String> = values.keys().map(|key| key.to_lowercase()).collect();
    let schema = metadata
        .get("tool_schema")
        .filter(|value| value.is_object());
    let mut schema_keys = Vec::new();
    fn collect(schema: &Value, depth: usize, keys: &mut Vec<String>) {
        if depth > 20 {
            return;
        }
        match schema {
            Value::Object(object) => {
                if let Some(properties) = object.get("properties").and_then(Value::as_object) {
                    keys.extend(properties.keys().map(|key| key.to_lowercase()));
                }
                for value in object.values() {
                    collect(value, depth + 1, keys);
                }
            }
            Value::Array(values) => {
                for value in values {
                    collect(value, depth + 1, keys);
                }
            }
            _ => (),
        }
    }
    if let Some(schema) = schema {
        collect(schema, 0, &mut schema_keys);
    }
    let active = |patterns: &[&str]| {
        patterns.iter().any(|pattern| {
            operation.contains(pattern)
                || description.contains(pattern)
                || keys.iter().any(|key| key.contains(pattern))
        })
    };
    let all = |patterns: &[&str]| {
        active(patterns)
            || patterns
                .iter()
                .any(|pattern| schema_keys.iter().any(|key| key.contains(pattern)))
    };
    let emulate_headers = operation == "emulate"
        && keys.iter().any(|key| {
            key.chars()
                .filter(|ch| *ch != '_')
                .eq("extrahttpheaders".chars())
        });
    if emulate_headers {
        add(AuthHeaders);
    }
    for (expressions, surface, active_only) in [
        (SENSITIVE_COOKIE_PATTERNS, Cookies, false),
        (SENSITIVE_STORAGE_PATTERNS, Storage, false),
        (SENSITIVE_AUTH_PATTERNS, AuthHeaders, false),
        (SENSITIVE_CDP_PATTERNS, Cdp, false),
        (SENSITIVE_SCRIPT_EVAL_PATTERNS, ScriptEval, true),
        (SENSITIVE_UPLOAD_PATTERNS, Upload, true),
        (SENSITIVE_DOWNLOAD_PATTERNS, Download, true),
        (SENSITIVE_CLIPBOARD_PATTERNS, Clipboard, false),
        (SENSITIVE_INTERCEPT_PATTERNS, NetworkIntercept, false),
    ] {
        if if active_only {
            active(expressions)
        } else {
            all(expressions)
        } && (surface != AuthHeaders || !emulate_headers)
        {
            add(surface);
        }
    }
    if schema_keys.iter().any(|key| {
        SENSITIVE_PASSWORD_PATTERNS
            .iter()
            .any(|pattern| key.contains(pattern))
    }) {
        add(PasswordField);
    }
}

fn normalize(
    artifact: &BrowserMcpArtifactV1,
    raw_arguments: &BrowserMcpArgumentsV1,
) -> Result<Option<BrowserAutomationIntentV1>, &'static str> {
    normalize_with_arguments(artifact, || arguments(raw_arguments))
}

/// Approval hashing needs the intent AND the volatile-field list (the exact
/// /sensitive argument digests drop volatile keys before hashing).
pub fn normalize_approval_intent(
    artifact: &BrowserMcpArtifactV1,
    raw_arguments: &Value,
) -> Result<Option<BrowserAutomationIntentV1>, &'static str> {
    normalize_with_arguments(artifact, || {
        let (values, volatile) = match raw_arguments {
            Value::Object(values) => {
                let volatile = values
                    .keys()
                    .filter(|key| VOLATILE_FIELDS.binary_search(&key.as_str()).is_ok())
                    .cloned()
                    .collect();
                (ArgumentValues::Object(values), volatile)
            }
            Value::String(text) => {
                let parsed = match serde_json::from_str::<Value>(text) {
                    Ok(Value::Object(map)) => map,
                    _ => Map::new(),
                };
                let volatile = parsed
                    .keys()
                    .filter(|key| VOLATILE_FIELDS.binary_search(&key.as_str()).is_ok())
                    .cloned()
                    .collect();
                (ArgumentValues::Parsed(parsed), volatile)
            }
            _ => (ArgumentValues::Parsed(Map::new()), Vec::new()),
        };
        Ok(Arguments { values, volatile })
    })
}

fn normalize_with_arguments<'a>(
    artifact: &BrowserMcpArtifactV1,
    read_arguments: impl FnOnce() -> Result<Arguments<'a>, &'static str>,
) -> Result<Option<BrowserAutomationIntentV1>, &'static str> {
    if !is_browser_server(artifact) {
        return Ok(None);
    }
    let server = scalar_text(artifact.metadata.get("server_name"));
    let operation = tool_operation(artifact);
    let Some(intent) = classify_operation(operation, &server) else {
        return Ok(None);
    };
    let arguments = read_arguments()?;
    let target = target_url(&arguments.values)
        .or_else(|| optional_str(artifact.metadata.get("browser_current_page_url")));
    let parsed = target.and_then(|target| urlsplit(target).ok());
    let server_identity = artifact
        .metadata
        .get("mcp_server_identity")
        .and_then(Value::as_object);
    let tool_identity = artifact
        .metadata
        .get("mcp_tool_identity")
        .and_then(Value::as_object);
    use BrowserIntentV1::*;
    let method = match intent {
        Navigation => BrowserMethodV1::Navigate,
        Inspect => BrowserMethodV1::Read,
        Interact => BrowserMethodV1::Interact,
        Transfer => BrowserMethodV1::Upload,
        Privileged => BrowserMethodV1::Privileged,
    };
    Ok(Some(BrowserAutomationIntentV1 {
        version: 1,
        intent,
        operation: operation.to_owned(),
        target_url: parsed
            .as_ref()
            .map(redacted_url)
            .or_else(|| target.map(str::to_owned)),
        target_origin: parsed
            .as_ref()
            .filter(|parts| !parts.scheme.is_empty() && !parts.netloc.is_empty())
            .map(|parts| format!("{}://{}", parts.scheme, parts.netloc)),
        target_domain: parsed.as_ref().and_then(domain),
        target_path_prefix: parsed.as_ref().map(path_prefix),
        method,
        profile_mode: profile_mode(&artifact.metadata),
        mcp_server_name: server.into_owned(),
        mcp_server_identity_hash: server_identity
            .and_then(|identity| optional_str(identity.get("identity_hash")))
            .map(str::to_owned),
        mcp_tool_name: operation.to_owned(),
        mcp_tool_identity_hash: tool_identity
            .and_then(|identity| optional_str(identity.get("identity_hash")))
            .map(str::to_owned),
        mcp_schema_hash: tool_identity
            .and_then(|identity| optional_str(identity.get("schema_hash")))
            .map(str::to_owned),
        sensitive_surface_flags: sensitive_surfaces(
            operation,
            &arguments.values,
            &artifact.metadata,
        ),
        volatile_fields_dropped: arguments.volatile,
    }))
}

fn display(
    intent: &BrowserMcpDisplayIntentV1,
    raw_arguments: &BrowserMcpArgumentsV1,
) -> Result<String, &'static str> {
    if let Some(domain) = intent
        .target_domain
        .as_ref()
        .filter(|domain| !domain.is_empty())
    {
        return Ok(domain.clone());
    }
    if let Some(origin) = intent
        .target_origin
        .as_ref()
        .filter(|origin| !origin.is_empty())
    {
        return Ok(origin.clone());
    }
    let arguments = arguments(raw_arguments)?;
    let operation = intent.operation.to_lowercase();
    let reads = operation.starts_with("get_") || operation.starts_with("read_");
    if operation.contains("network") {
        return Ok(if reads {
            "network request"
        } else {
            "network activity"
        }
        .to_owned());
    }
    if operation.contains("console") {
        return Ok(if reads {
            "console message"
        } else {
            "console messages"
        }
        .to_owned());
    }
    let element = [
        "uid",
        "ref",
        "selector",
        "element",
        "elementId",
        "nodeId",
        "backendNodeId",
        "from_uid",
        "to_uid",
    ]
    .iter()
    .any(|key| arguments.values.contains_key(key))
        || arguments
            .values
            .get("elements")
            .is_some_and(Value::is_array);
    let multiple = (arguments.values.contains_key("from_uid")
        && arguments.values.contains_key("to_uid"))
        || arguments
            .values
            .get("elements")
            .and_then(Value::as_array)
            .is_some_and(|values| values.len() > 1);
    if matches!(
        intent.intent,
        BrowserIntentV1::Interact | BrowserIntentV1::Transfer
    ) && element
    {
        return Ok(if multiple {
            "page elements"
        } else {
            "page element"
        }
        .to_owned());
    }
    Ok(match operation.as_str() {
        "list_pages" | "browser_list_pages" => "open pages",
        "select_page" | "close_page" | "browser_select_page" | "browser_close_page" => {
            "browser page"
        }
        _ => "current page",
    }
    .to_owned())
}

pub fn evaluate_browser_mcp(
    request: &BrowserMcpRequestV1,
) -> Result<BrowserMcpResultV1, &'static str> {
    Ok(match request {
        BrowserMcpRequestV1::Server { artifact } => BrowserMcpResultV1::Server {
            is_browser: is_browser_server(artifact),
        },
        BrowserMcpRequestV1::Classify {
            tool_operation,
            server_name,
        } => BrowserMcpResultV1::Classify {
            intent: classify_operation(tool_operation, server_name),
        },
        BrowserMcpRequestV1::Normalize {
            artifact,
            arguments,
        } => BrowserMcpResultV1::Normalize {
            intent: normalize(artifact, arguments)?.map(Box::new),
        },
        BrowserMcpRequestV1::Display { intent, arguments } => BrowserMcpResultV1::Display {
            target: display(intent, arguments)?,
        },
    })
}

pub(crate) struct BrowserRiskFacts {
    pub intent: BrowserIntentV1,
    pub external_domain: bool,
    pub shared_profile: bool,
    pub sensitive_surface: bool,
}

pub(crate) fn browser_risk_facts(
    artifact: &BrowserMcpArtifactV1,
    raw_arguments: &Value,
) -> Option<BrowserRiskFacts> {
    if !is_browser_server(artifact) {
        return None;
    }
    let server = scalar_text(artifact.metadata.get("server_name"));
    let operation = tool_operation(artifact);
    let intent = classify_operation(operation, &server)?;
    let values = match raw_arguments {
        Value::Object(object) => ArgumentValues::Object(object),
        Value::String(text) => {
            let parsed = serde_json::from_str::<Value>(text).ok();
            ArgumentValues::Parsed(match parsed {
                Some(Value::Object(object)) => object,
                _ => Map::new(),
            })
        }
        _ => ArgumentValues::Parsed(Map::new()),
    };
    let target = target_url(&values)
        .or_else(|| optional_str(artifact.metadata.get("browser_current_page_url")));
    let external_domain = target
        .and_then(|target| urlsplit(target).ok())
        .is_some_and(|parts| {
            hostname(&parts).is_some_and(|domain| {
                !domain.is_empty()
                    && !domain.eq_ignore_ascii_case("localhost")
                    && !matches!(domain, "127.0.0.1" | "::1")
            })
        });
    let mut sensitive_surface = false;
    visit_sensitive_surfaces(operation, &values, &artifact.metadata, |_| {
        sensitive_surface = true
    });
    Some(BrowserRiskFacts {
        intent,
        external_domain,
        shared_profile: matches!(
            profile_mode(&artifact.metadata),
            BrowserProfileModeV1::Shared | BrowserProfileModeV1::RemoteDebugging
        ),
        sensitive_surface,
    })
}
