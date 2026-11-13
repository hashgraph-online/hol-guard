//! Per-harness writes of the settings update: the posture patch and the
//! named-profile cleanup of blanket ask policy (`config_preset_support.py`).

use std::collections::BTreeMap;

use crate::guard_config_harness::{loaded_postures, loaded_watch_stamps};
use crate::guard_config_update_coerce::normalize_posture;
use crate::guard_config_update_value::{get, is_str, remove, set, to_json, Table, Tv};
use crate::package_authority_config::VALID_SECURITY_LEVELS;
use crate::pyjson::PyVal;

type Payload = [(String, PyVal)];

fn incoming<'a>(payload: &'a Payload, key: &str) -> Option<&'a PyVal> {
    payload
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

fn incoming_str<'a>(payload: &'a Payload, key: &str) -> Option<&'a str> {
    incoming(payload, key).and_then(PyVal::as_str)
}

/// `apply_harness_posture_patch`: selecting Watch always restarts its window.
/// An untimed Watch (an app that keeps only CIGAR) gets no window, so it
/// never turns back to Protected on its own.
pub(crate) fn apply_harness_patch(
    next: &mut Table,
    patch: &[(&str, Option<&str>)],
    now: &str,
    untimed: bool,
) {
    let mut stored = loaded_postures(get(next, "harness_postures").map(to_json).as_ref());
    let mut stamps = loaded_watch_stamps(
        get(next, "harness_watch_entered_at").map(to_json).as_ref(),
        &stored,
    );
    for (harness, posture) in patch {
        let harness = (*harness).to_owned();
        match posture {
            None => {
                stored.remove(&harness);
                stamps.remove(&harness);
            }
            Some(posture) => {
                stored.insert(harness.clone(), (*posture).to_owned());
                if *posture == "watch" && !untimed {
                    stamps.insert(harness, now.to_owned());
                } else {
                    stamps.remove(&harness);
                }
            }
        }
    }
    for (key, values) in [
        ("harness_postures", stored),
        ("harness_watch_entered_at", stamps),
    ] {
        if values.is_empty() {
            remove(next, key);
        } else {
            set(next, key, string_table(values));
        }
    }
}

/// True when the stored CIGAR settings add project context to prompts.
pub(crate) fn cigar_ready(next: &Table) -> bool {
    let Some(config) = get(next, "context_assistance").map(to_json) else {
        return false;
    };
    let on = |path: &[&str]| {
        path.iter()
            .try_fold(&config, |value, key| value.get(*key))
            .and_then(serde_json::Value::as_bool)
            == Some(true)
    };
    on(&["enabled"])
        && on(&["features", "agent_context"])
        && on(&["sources", "workspace_documents"])
}

/// Once CIGAR stops adding context, an untimed Watch (kept only for CIGAR)
/// would leave the app unchecked with nothing running, so it gets the usual
/// revert window from now. `only` limits this to the named apps; existing
/// stamps are kept.
pub(crate) fn stamp_untimed_watch(next: &mut Table, now: &str, only: Option<&[&str]>) {
    let stored = loaded_postures(get(next, "harness_postures").map(to_json).as_ref());
    let mut stamps = loaded_watch_stamps(
        get(next, "harness_watch_entered_at").map(to_json).as_ref(),
        &stored,
    );
    let before = stamps.len();
    for (harness, posture) in &stored {
        let named = only.is_none_or(|names| names.contains(&harness.as_str()));
        if named && posture == "watch" && !stamps.contains_key(harness) {
            stamps.insert(harness.clone(), now.to_owned());
        }
    }
    if stamps.len() != before {
        set(next, "harness_watch_entered_at", string_table(stamps));
    }
}

/// `harness_cigar`: fold a per-app CIGAR patch into the stored choices.
pub(crate) fn apply_cigar_patch(next: &mut Table, patch: &[(&str, bool)]) {
    let mut stored =
        crate::guard_config_harness::loaded_cigar(get(next, "harness_cigar").map(to_json).as_ref());
    for (harness, off) in patch {
        if *off {
            stored.insert((*harness).to_owned(), "off".to_owned());
        } else {
            stored.remove(*harness);
        }
    }
    if stored.is_empty() {
        remove(next, "harness_cigar");
    } else {
        set(next, "harness_cigar", string_table(stored));
    }
}

pub(crate) fn string_table(values: BTreeMap<String, String>) -> Tv {
    Tv::Table(
        values
            .into_iter()
            .map(|(key, value)| (key, Tv::Str(value)))
            .collect(),
    )
}

/// `without_blanket_harness_reapproval`.
fn without_blanket(value: Option<&Tv>) -> Tv {
    let Some(Tv::Table(harnesses)) = value else {
        return Tv::Table(Table::new());
    };
    let blanket = |item: Option<&Tv>| is_str(item, "review") || is_str(item, "require-reapproval");
    let mut preserved = Table::new();
    for (harness, settings) in harnesses {
        match settings {
            Tv::Table(entries) => {
                let mut remaining = entries.clone();
                for key in ["action", "default_action"] {
                    if blanket(get(&remaining, key)) {
                        remove(&mut remaining, key);
                    }
                }
                if !remaining.is_empty() {
                    set(&mut preserved, harness, Tv::Table(remaining));
                }
            }
            other if blanket(Some(other)) => {}
            other => set(&mut preserved, harness, other.clone()),
        }
    }
    Tv::Table(preserved)
}

/// `apply_named_posture_harness_policy`.
pub(crate) fn apply_named_policy(next: &mut Table, payload: &Payload) {
    let empty =
        |key: &str| matches!(incoming(payload, key), Some(PyVal::Dict(items)) if items.is_empty());
    let selects_named_level = incoming_str(payload, "security_level")
        .is_some_and(|level| level != "custom" && VALID_SECURITY_LEVELS.contains(&level))
        && empty("risk_actions")
        && empty("harness_risk_actions");
    let requested = normalize_posture(incoming_str(payload, "protection_posture"));
    let current = normalize_posture(match get(next, "protection_posture") {
        Some(Tv::Str(text)) => Some(text.as_str()),
        _ => None,
    });
    let current_is_watch =
        current == Some("watch") || (current.is_none() && is_str(get(next, "mode"), "observe"));
    let leaves_watch = current_is_watch && matches!(requested, Some("protected" | "extra_careful"));
    if selects_named_level || leaves_watch {
        let harnesses = without_blanket(get(next, "harnesses"));
        set(next, "harnesses", harnesses);
    }
}
