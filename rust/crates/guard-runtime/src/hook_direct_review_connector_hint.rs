//! The connector-setup hint a connector-setup review is stored with, and the
//! risk classes it carries (`extension_allow_hint.py`). Part of the
//! resident's connector-setup review (`hook_direct_review_connector.rs`).

use std::collections::BTreeSet;

use guard_command::hook_responses::Object;
use guard_command::native_command_catalog::packaged_command_catalog;
use serde_json::{json, Value};

use super::{
    Connector, HookDirectDefer, HINT_SCHEMA, HINT_SURFACES, MAX_HINT_TEXT, MAX_NAME_CHARS,
    MAX_RISK_CLASSES,
};

/// `_observed_risk_classes`, filtered and capped as `connector_setup_hint`
/// keeps them. A rule id whose trim or case fold could differ from Python's
/// defers, as does a catalog the resident cannot load.
pub(super) fn observed_risk_classes(result: &Object) -> Result<Vec<String>, HookDirectDefer> {
    let observations = result
        .get("command_extensions")
        .and_then(Value::as_object)
        .and_then(|evidence| evidence.get("observations"));
    let Some(Value::Array(observations)) = observations else {
        return Ok(Vec::new());
    };
    let mut catalog = None;
    let mut classes = BTreeSet::new();
    for observation in observations {
        let Some(rule_id) = observation.get("rule_id").and_then(Value::as_str) else {
            continue;
        };
        if !rule_id
            .chars()
            .all(|item| item.is_ascii() && !('\x1c'..='\x1f').contains(&item))
        {
            return Err(HookDirectDefer::ReviewQueue);
        }
        let catalog = match &catalog {
            Some(catalog) => catalog,
            None => catalog
                .insert(packaged_command_catalog().map_err(|_| HookDirectDefer::ReviewQueue)?),
        };
        let Some((_, rule)) = catalog.get_rule(rule_id) else {
            continue;
        };
        classes.extend(rule.risk_classes.iter().cloned());
        if rule.severity == "critical"
            || rule
                .risk_classes
                .iter()
                .any(|item| item == "destructive_shell")
        {
            classes.insert("destructive".to_owned());
        }
    }
    Ok(classes
        .into_iter()
        .filter(|item| risk_class(item))
        .take(MAX_RISK_CLASSES)
        .collect())
}

/// `connector_setup_hint` through `validated_connector_setup_hint`: the hint
/// for a connector whose fields are all well formed, else null.
pub(super) fn setup_hint(connector: &Connector, risk_classes: &[String]) -> Value {
    let display_name = connector.display_name();
    let valid = identity_hash(&connector.identity_hash)
        && cli_id(&connector.cli_id)
        && display_text(&display_name)
        && HINT_SURFACES.contains(&connector.surface.as_str())
        && risk_classes.len() <= MAX_RISK_CLASSES
        && risk_classes.iter().all(|item| risk_class(item));
    if !valid {
        return Value::Null;
    }
    json!({
        "schema": HINT_SCHEMA,
        "identity_hash": connector.identity_hash,
        "cli_id": connector.cli_id,
        "surface": connector.surface,
        "display_name": display_name,
        "deep_link": deep_link(&connector.cli_id),
        "card_recommendation": {"state": "allowed", "capabilities": []},
        "risk_classes": risk_classes,
    })
}

/// `connector_setup_deep_link`: `quote(cli_id, safe='')`.
pub(super) fn deep_link(cli_id: &str) -> String {
    let mut quoted = String::with_capacity(cli_id.len());
    for byte in cli_id.bytes() {
        if byte.is_ascii_alphanumeric() || b"_.-~".contains(&byte) {
            quoted.push(char::from(byte));
        } else {
            quoted.push_str(&format!("%{byte:02X}"));
        }
    }
    format!("/extensions/local-cli/{quoted}")
}

/// `_IDENTITY_HASH`: `[0-9a-f]{64}`.
pub(super) fn identity_hash(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// `_CLI_ID`: `local-cli\.[A-Za-z0-9._@+-]{1,118}`.
pub(super) fn cli_id(text: &str) -> bool {
    text.strip_prefix("local-cli.").is_some_and(|rest| {
        (1..=118).contains(&rest.len())
            && rest
                .chars()
                .all(|item| item.is_ascii_alphanumeric() || "._@+-".contains(item))
    })
}

/// `_DISPLAY_NAME`: `[A-Za-z0-9@][A-Za-z0-9._@+/ -]{0,63}`.
pub(super) fn display_text(text: &str) -> bool {
    let mut chars = text.chars();
    text.len() <= MAX_HINT_TEXT
        && text.chars().count() <= MAX_NAME_CHARS
        && chars
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric() || first == '@')
        && chars.all(|item| item.is_ascii_alphanumeric() || "._@+/ -".contains(item))
}

/// `_RISK_CLASS`: `[a-z][a-z0-9_]{0,63}`.
pub(super) fn risk_class(text: &str) -> bool {
    let mut bytes = text.bytes();
    text.len() <= 64
        && bytes.next().is_some_and(|first| first.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}
