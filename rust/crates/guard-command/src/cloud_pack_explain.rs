//! `explain`: what Guard derives from one example call to a pack action, and
//! the decision each shipped policy preset gives it.
//!
//! The call is checked against the action's argument bounds first, so an
//! example the action would refuse is reported as that refusal. Decisions are
//! the preset join the evaluator runs, with every declared window at zero and
//! a clean session; capability, obligation and consent checks come after it
//! and are not applied.
//!
//! The packs that ship in `contributions/cloud-actions/` are compiled in, so a
//! released CLI can explain a shipped action without a pack file.

use crate::cloud_pack::{pack_from_value, CloudActionPack, PackAction};
use crate::cloud_pack_facts::extract;
use crate::cloud_pack_request::{check_arguments, ArgumentError};
use crate::cloud_policy_pack::{shipped, FactCall, Preset};
use serde_json::{json, Map, Value};
use std::sync::LazyLock;

/// Every pack this build ships; tests read the same list.
pub(crate) const SHIPPED_SOURCES: [&str; 20] = [
    include_str!("../../../../contributions/cloud-actions/airtable.json"),
    include_str!("../../../../contributions/cloud-actions/asana.json"),
    include_str!("../../../../contributions/cloud-actions/atlassian.json"),
    include_str!("../../../../contributions/cloud-actions/box.json"),
    include_str!("../../../../contributions/cloud-actions/calendar.json"),
    include_str!("../../../../contributions/cloud-actions/docs.json"),
    include_str!("../../../../contributions/cloud-actions/drive.json"),
    include_str!("../../../../contributions/cloud-actions/dropbox.json"),
    include_str!("../../../../contributions/cloud-actions/github.json"),
    include_str!("../../../../contributions/cloud-actions/gmail.json"),
    include_str!("../../../../contributions/cloud-actions/hubspot-mcp.json"),
    include_str!("../../../../contributions/cloud-actions/notion.json"),
    include_str!("../../../../contributions/cloud-actions/notion-mcp.json"),
    include_str!("../../../../contributions/cloud-actions/onedrive.json"),
    include_str!("../../../../contributions/cloud-actions/outlook.json"),
    include_str!("../../../../contributions/cloud-actions/salesforce-mcp.json"),
    include_str!("../../../../contributions/cloud-actions/sheets.json"),
    include_str!("../../../../contributions/cloud-actions/slack.json"),
    include_str!("../../../../contributions/cloud-actions/stripe-mcp.json"),
    include_str!("../../../../contributions/cloud-actions/teams.json"),
];

static SHIPPED_PACKS: LazyLock<Vec<CloudActionPack>> = LazyLock::new(|| {
    // The shipped files are checked by the test suite; a broken file is a
    // build defect, not an input error.
    SHIPPED_SOURCES
        .iter()
        .map(|text| {
            serde_json::from_str(text)
                .ok()
                .and_then(|value| pack_from_value(value).ok())
                .expect("shipped cloud action pack")
        })
        .collect()
});

/// The shipped pack that declares `action_id`, if any.
pub fn shipped_pack_for(action_id: &str) -> Option<&'static CloudActionPack> {
    SHIPPED_PACKS
        .iter()
        .find(|pack| pack.action(action_id).is_some())
}

/// Facts and per-preset decisions for one example call.
pub fn explain(
    pack: &CloudActionPack,
    action: &PackAction,
    arguments: &Value,
) -> Result<Map<String, Value>, ArgumentError> {
    let record = check_arguments(action, arguments)?;
    let facts = extract(action, record);
    let call = FactCall {
        provider: &pack.provider.id,
        action_id: &action.action_id,
        effect: action.safety.effect,
        facts: &facts,
        session: None,
        windows: None,
    };
    let decisions: Map<String, Value> = Preset::ALL
        .into_iter()
        .map(|preset| {
            (
                preset.as_str().to_string(),
                json!(shipped(preset).decide(&call)),
            )
        })
        .collect();
    let mut result = Map::new();
    result.insert("providerId".into(), json!(pack.provider.id));
    result.insert("actionId".into(), json!(action.action_id));
    result.insert("effect".into(), json!(action.safety.effect));
    result.insert("facts".into(), json!(facts));
    result.insert("decisions".into(), Value::Object(decisions));
    Ok(result)
}
