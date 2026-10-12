//! Device-bound (v2) continuity planning and context cleanup.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use super::*;

pub(super) struct V2Item<'a> {
    identity_hash: &'a str,
    devices: Vec<&'a str>,
    state: &'a str,
}

pub(super) fn parse_v2_item<'a>(
    raw: &'a Value,
    seen: &mut BTreeSet<&'a str>,
) -> Planned<V2Item<'a>> {
    let Some(item) = raw
        .as_object()
        .filter(|item| has_exact_keys(item, V2_ITEM_FIELDS))
    else {
        return refuse("continuity item contains unsupported fields");
    };
    let Some(identity_hash) = item
        .get("identityHash")
        .and_then(Value::as_str)
        .filter(|hash| is_sha256(hash) && !seen.contains(hash))
    else {
        return refuse("invalid or duplicate continuity identity");
    };
    let devices = item
        .get("deviceIdentityHashes")
        .and_then(Value::as_array)
        .filter(|devices| !devices.is_empty() && devices.len() <= MAX_DEVICE_BINDINGS)
        .and_then(|devices| {
            devices
                .iter()
                .map(|device| device.as_str().filter(|device| is_sha256(device)))
                .collect::<Option<Vec<&str>>>()
        })
        .filter(|devices| devices.iter().collect::<BTreeSet<_>>().len() == devices.len());
    let Some(mut devices) = devices else {
        return refuse("invalid continuity device binding");
    };
    let Some(state) = item
        .get("state")
        .and_then(Value::as_str)
        .filter(|state| matches!(*state, "allowed" | "blocked" | "removed"))
    else {
        return refuse("invalid continuity setting");
    };
    seen.insert(identity_hash);
    devices.sort_unstable();
    Ok(V2Item {
        identity_hash,
        devices,
        state,
    })
}

pub(super) fn plan_v2(
    continuity: &Value,
    snapshot: &Snapshot<'_>,
    workspace: &str,
    device: &str,
) -> Planned<Value> {
    let frame = frame(continuity, SCHEMA_V2)?;
    let mut seen = BTreeSet::new();
    let mut items = frame
        .items
        .iter()
        .map(|raw| parse_v2_item(raw, &mut seen))
        .collect::<Planned<Vec<_>>>()?;
    items.sort_by(|left, right| left.identity_hash.cmp(right.identity_hash));
    let canonical = json!({
        "schemaVersion": frame.value["schemaVersion"],
        "revision": frame.value["revision"],
        "observedAt": frame.value["observedAt"],
        "expiresAt": frame.value["expiresAt"],
        "items": items.iter().map(|item| json!({
            "identityHash": item.identity_hash,
            "deviceIdentityHashes": item.devices,
            "state": item.state,
        })).collect::<Vec<_>>(),
    });
    let digest = sha256_hex(&dumps_sorted(&canonical).ok_or(Fail::Request)?);
    let device_hash = sha256_hex(&format!("{SCHEMA_V1}:device:{workspace}:{device}"));
    let binding = json!({
        "workspaceHash": sha256_hex(&format!("{SCHEMA_V1}:workspace:{workspace}")),
        "deviceHash": device_hash,
    });
    let previous = snapshot.previous.as_object();
    let same_context = previous.is_some_and(|previous| previous.get("binding") == Some(&binding));
    if same_context {
        require_monotonic(snapshot.previous, frame.revision, &digest)?;
    } else if previous.is_some_and(|previous| {
        previous.get("schema_version").and_then(Value::as_str) == Some(SCHEMA_V2)
            && !previous.get("binding").is_some_and(Value::is_object)
    }) {
        return refuse("prior v2 continuity binding is unavailable");
    }
    let stale = frame.expires <= timestamp(snapshot.now, "current time")?;
    let authority = &snapshot.authority;
    let mut by_scoped: BTreeMap<String, Vec<&Map<String, Value>>> = BTreeMap::new();
    for (_, local) in &authority.locals {
        if let Some(identity_hash) = local.get("identity_hash").and_then(Value::as_str) {
            by_scoped
                .entry(scoped_identity(workspace, identity_hash))
                .or_default()
                .push(local);
        }
    }
    let previous_items = previous
        .and_then(|previous| previous.get("items"))
        .and_then(Value::as_object);
    let previous_order = previous_items
        .map(|items| ordered_keys(items, &snapshot.previous_order))
        .unwrap_or_default();
    let mut plan = Plan::new();
    for item in &items {
        if !item.devices.contains(&device_hash.as_str()) {
            continue;
        }
        let scoped = item.identity_hash;
        let mut matches = by_scoped.get(scoped).cloned().unwrap_or_default();
        if matches.is_empty() {
            matches = previous_order
                .iter()
                .filter(|cli_id| {
                    previous_items
                        .and_then(|items| items.get(*cli_id))
                        .and_then(|prior| prior.get("workspace_identity_hash"))
                        .and_then(Value::as_str)
                        == Some(scoped)
                })
                .filter_map(|cli_id| authority.local(cli_id))
                .collect();
        }
        let evidence_for = |status: &str, reason: &str| {
            let mut evidence = Map::new();
            evidence.insert("workspace_identity_hash".to_owned(), json!(scoped));
            evidence.extend(frame.evidence());
            evidence.insert("status".to_owned(), json!(status));
            evidence.insert("reason".to_owned(), json!(reason));
            evidence
        };
        if matches.is_empty() {
            let pending = evidence_for("pending_observation", "local_identity_not_observed");
            plan.record(scoped, "pending_observation", Value::Object(pending));
            continue;
        }
        for local in matches {
            let cli_id = local["cli_id"].as_str().unwrap_or_default();
            let identity_hash = local.get("identity_hash").and_then(Value::as_str);
            if identity_hash.is_some() {
                plan.preconditions
                    .insert(cli_id.to_owned(), observation_precondition(Some(local)));
            }
            let (status, reason) = match identity_hash {
                _ if !observed(local) => ("pending_observation", "local_identity_not_observed"),
                _ if stale => ("stale", "cloud_observation_expired"),
                None => ("pending_observation", "local_identity_not_observed"),
                Some(hash) if scoped_identity(workspace, hash) != scoped => {
                    ("changed_identity", "identity_mismatch")
                }
                Some(hash)
                    if override_matches(snapshot.removals.get(cli_id), hash, frame.revision) =>
                {
                    ("locally_overridden", "local_authority_preserved")
                }
                Some(_) if item.state == "removed" => {
                    plan.updates.push(unset_update(local)?);
                    ("removed", "signed_cloud_tombstone")
                }
                Some(_) => {
                    if let Some(update) =
                        plan_exact_settings(authority, local, item.state, &Map::new())?
                    {
                        plan.updates.push(update);
                    }
                    ("applied", "same_scoped_identity")
                }
            };
            let mut evidence = evidence_for(status, reason);
            if let Some(hash) = identity_hash {
                evidence.insert("local_identity_hash".to_owned(), json!(hash));
            }
            plan.record(cli_id, status, Value::Object(evidence));
        }
    }
    if let (false, Some(previous)) = (same_context, previous) {
        plan_context_cleanup(&mut plan, snapshot, previous, &previous_order)?;
    }
    let mut state = frame.state(SCHEMA_V2, stale, &digest);
    state.insert("binding".to_owned(), binding);
    Ok(plan.answer(state, stale, Value::Null, true))
}

/// Unset prior applied grants that the new binding no longer projects.
fn plan_context_cleanup(
    plan: &mut Plan,
    snapshot: &Snapshot<'_>,
    previous: &Map<String, Value>,
    previous_order: &[String],
) -> Planned<()> {
    let Some(items) = previous.get("items").and_then(Value::as_object) else {
        return Ok(());
    };
    let cloud_revision = previous
        .get("cloud_revision")
        .filter(|revision| py_int(Some(revision)).is_some())
        .cloned()
        .unwrap_or_else(|| json!(0));
    let protected: BTreeSet<String> = plan.statuses.iter().map(|(key, _)| key.clone()).collect();
    let authority = &snapshot.authority;
    for cli_id in previous_order {
        let Some(raw) = items.get(cli_id).and_then(Value::as_object) else {
            continue;
        };
        if protected.contains(cli_id)
            || raw.get("status").and_then(Value::as_str) != Some("applied")
        {
            continue;
        }
        let prior_identity = raw
            .get("local_identity_hash")
            .or_else(|| raw.get("identity_hash"))
            .and_then(Value::as_str);
        let Some(prior_identity) = prior_identity else {
            continue;
        };
        let Some(local) = authority.local(cli_id).filter(|local| {
            local.get("identity_hash").and_then(Value::as_str) == Some(prior_identity)
                && observed(local)
        }) else {
            continue;
        };
        let revision = py_int(Some(&cloud_revision)).unwrap_or(0);
        if override_matches(snapshot.removals.get(cli_id), prior_identity, revision) {
            continue;
        }
        let granted = authority.grant(cli_id).is_some_and(|grant| {
            grant.get("identity_hash").and_then(Value::as_str) == Some(prior_identity)
        });
        if !granted {
            continue;
        }
        plan.preconditions
            .insert(cli_id.clone(), observation_precondition(Some(local)));
        plan.updates.push(unset_update(local)?);
        plan.events.push(json!([
            "custom_extension_continuity/removed",
            {
                "cloud_revision": cloud_revision,
                "status": "removed",
                "reason": "continuity_context_changed",
            }
        ]));
    }
    Ok(())
}
