//! The Desktop objects (`mcp`, `plugins`) a ZCode install adds to
//! `config.json`, recorded so uninstall can take them out again.

use std::path::Path;

use serde_json::{Map, Value};

use super::path_text;
use crate::pyjson::PyVal;
use crate::zcode_hook_surface::{read_payload, render_file_over, DESKTOP_KEYS};

/// The install state's list of Desktop objects Guard added to `config.json`.
pub(super) const ADDED_KEYS: &str = "desktop_keys_added";

/// The keys a state record says install added to `config`. A record made for
/// another config file names nothing here.
fn recorded<'a>(state: &'a Map<String, Value>, config: &Path) -> Vec<&'a str> {
    let same_file = state.get("managed_config_path").and_then(Value::as_str)
        == Some(path_text(config).as_str());
    if !same_file {
        return Vec::new();
    }
    state
        .get(ADDED_KEYS)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|key| DESKTOP_KEYS.contains(key))
        .collect()
}

/// The Desktop objects install will add to `config`: those the file lacks,
/// plus those an earlier install into the same file added, so a reinstall
/// does not forget them.
pub(super) fn added_desktop_keys(
    text: Option<&str>,
    previous: &Map<String, Value>,
    config: &Path,
) -> Vec<String> {
    let mut added: Vec<String> = recorded(previous, config)
        .into_iter()
        .map(str::to_owned)
        .collect();
    // Install adds nothing to a file that does not exist yet.
    let Some(Ok(Some((payload, _)))) = text.map(read_payload) else {
        return added;
    };
    for key in DESKTOP_KEYS {
        let absent = !payload.iter().any(|(name, _)| name == key);
        if absent && !added.iter().any(|name| name == key) {
            added.push(key.to_owned());
        }
    }
    added
}

/// `text` without the objects install added to `config`, when they are still
/// empty. Any the user has filled since are kept.
pub(super) fn without_added_keys(
    text: String,
    state: &Map<String, Value>,
    config: &Path,
) -> String {
    let added = recorded(state, config);
    if added.is_empty() {
        return text;
    }
    let Ok(Some((mut payload, lone))) = read_payload(&text) else {
        return text;
    };
    let before = payload.len();
    payload.retain(|(key, value)| {
        !(added.contains(&key.as_str())
            && matches!(value, PyVal::Dict(entries) if entries.is_empty()))
    });
    if payload.len() == before {
        return text;
    }
    render_file_over(payload, lone, Some(&text)).unwrap_or(text)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_json::{json, Map, Value};

    use super::{added_desktop_keys, without_added_keys};

    fn state(config: &str) -> Map<String, Value> {
        json!({"managed_config_path": config, "desktop_keys_added": ["mcp", "plugins"]})
            .as_object()
            .unwrap()
            .clone()
    }

    #[test]
    fn a_record_for_another_config_file_is_not_reused() {
        let here = Path::new("/second/.zcode/cli/config.json");
        let other = state("/first/.zcode/cli/config.json");
        let text = "{\"mcp\": {}, \"plugins\": {}}";
        assert!(added_desktop_keys(Some(text), &other, here).is_empty());
        assert_eq!(without_added_keys(text.into(), &other, here), text);
    }

    #[test]
    fn a_record_for_this_config_file_is_kept_and_applied() {
        let here = Path::new("/first/.zcode/cli/config.json");
        let same = state("/first/.zcode/cli/config.json");
        let text = "{\"mcp\": {}, \"plugins\": {}}";
        assert_eq!(
            added_desktop_keys(Some(text), &same, here),
            ["mcp", "plugins"]
        );
        let cleaned: Value =
            serde_json::from_str(&without_added_keys(text.into(), &same, here)).unwrap();
        assert_eq!(cleaned, json!({}));
    }
}
