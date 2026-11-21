//! Upload local receipts to Guard Cloud (`runner.sync_receipts`, up to the
//! Cloud answers). The caller builds the sync context, the fleet posture and
//! the workspace assessment summary, and applies the policy bundle and review
//! keys the answers carry. The upload applies the advisories and alert
//! preferences itself ([`crate::cloud_receipt_answers`]).
//!
//! The upload runs inside [`crate::cloud_bundle_fetch::brokered`]. Each round
//! resumes from [`UploadState`]: batches an earlier round delivered and
//! recorded are not sent again, and the batch a round left pending is rebuilt
//! byte for byte, so the next round reads its answer.

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::cloud_bundle_fetch::{resolve_auth, unreachable_message, SyncError};
use crate::cloud_event_sync::{
    answer_text, post, route_url, screen_supplied, synced_at, trusted_base, EventStore, Refusal,
    EVENT_TIMEOUTS,
};
use crate::cloud_receipt_answers::apply as apply_answers;
use crate::cloud_receipt_upload_rows::{
    advance_marker, cursor_backfill, fit_to_broker, plan, rowid, Plan, CURSOR_KEY,
    DETAIL_BACKFILL_MARKER,
};

/// `fleet_posture_common.LAST_SENT_STATE_KEY` / `FORCE_FULL_STATE_KEY`.
const POSTURE_LAST_SENT_KEY: &str = "fleet_posture_last";
const POSTURE_FORCE_FULL_KEY: &str = "fleet_posture_force_full";
/// `workspace_assessment_sync.DELIVERY_STATE_KEY`.
const WORKSPACE_DELIVERY_KEY: &str = "workspace_assessment_sync_delivery";
/// `workspace_assessment_sync.MAX_REQUEST_BYTES`.
const MAX_REQUEST_BYTES: i64 = 256 * 1024;
/// `_WORKSPACE_ASSESSMENT_KEY_OVERHEAD`: the `"workspaceAssessments":` key.
const WORKSPACE_KEY_OVERHEAD: i64 = 32;
const REAUTHORIZE: &str = "Guard authorization expired. Run `hol-guard connect` to sign in again.";
const INVALID_RESPONSE: &str = "Guard Cloud sync returned an invalid response payload.";

/// What the caller built for this sync.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UploadRequest {
    pub(crate) redaction_level: String,
    pub(crate) device_id: String,
    pub(crate) device_name: String,
    /// The local clock the sync started at.
    pub(crate) now: String,
    pub(crate) sync_context: Map<String, Value>,
    /// Rides on the first request only.
    #[serde(default)]
    pub(crate) fleet_posture: Option<FleetPosture>,
    /// `{"payload", "digest"}`, sent with the first request it fits in.
    #[serde(default)]
    pub(crate) workspace_assessments: Option<Value>,
    /// Python refreshes a refused sign-in once only when it resolved the
    /// sign-in itself.
    #[serde(default)]
    pub(crate) allow_auth_refresh: bool,
    /// One request with no receipts, sending only the context: the policy
    /// acknowledgement follow-up. No cursor or marker moves.
    #[serde(default)]
    pub(crate) context_only: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FleetPosture {
    pub(crate) payload: Value,
    pub(crate) next_state: Value,
    #[serde(default)]
    pub(crate) advanced_inventory: bool,
}

/// What earlier broker rounds of one upload already settled.
#[derive(Debug, Default)]
pub(crate) struct UploadState {
    auth: Option<Map<String, Value>>,
    plan: Option<Plan>,
    /// The batch whose refusal refreshed the sign-in. A replayed round reads
    /// the same refusal again and goes straight to the retry.
    refreshed_at: Option<usize>,
    processed: usize,
    /// The summary still waiting for a request with room for it.
    workspace_pending: Option<Value>,
    marker: Option<Value>,
    tally: Tally,
}

#[derive(Debug, Default)]
struct Tally {
    latest_rowid: Option<i64>,
    last_payload: Map<String, Value>,
    receipts_stored: i64,
    advisories: Vec<Value>,
    bundle_provided: bool,
    bundle_malformed: bool,
    bundle: Option<Value>,
    bundle_sync_payload: Value,
    delivery_provided: bool,
    delivery: Value,
    alert_preferences: Option<Value>,
    review_keys: Value,
}

/// One round of the upload.
pub(crate) fn upload_receipts(
    store: &EventStore<'_>,
    request: &UploadRequest,
    state: &mut UploadState,
) -> Result<Value, SyncError> {
    if state.auth.is_none() {
        let supplied = store.bundle.auth.as_ref().filter(|auth| !auth.is_empty());
        screen_supplied(supplied)?;
        let auth = resolve_auth(&store.bundle.resident, false, supplied)?;
        trusted_base(&auth)?;
        state.auth = Some(auth);
    }
    if state.plan.is_none() {
        let call = |method: &str, args: Value| store.call(method, args);
        let plan = if request.context_only {
            Plan::default()
        } else {
            plan(
                &call,
                store.payload(CURSOR_KEY)?.as_ref(),
                store.payload(DETAIL_BACKFILL_MARKER)?.as_ref(),
                &request.redaction_level,
                &request.now,
            )?
        };
        let plan = fit_to_broker(request, plan)?;
        state.marker = plan.marker.clone();
        state.workspace_pending = request.workspace_assessments.clone();
        state.plan = Some(plan);
    }
    let plan = state.plan.clone().unwrap_or_default();
    while state.processed < plan.batches.len() {
        let index = state.processed;
        let range = plan.batches[index].clone();
        let batch = &plan.rows[range.clone()];
        let (body, workspace_sent) = batch_body(request, &plan.projected[range], index, state);
        let payload = send(store, request, state, index, &body)?;
        record_batch(
            store,
            request,
            state,
            &plan,
            batch,
            index,
            workspace_sent,
            payload,
        )?;
        state.processed += 1;
    }
    finish(store, request, state, &plan)
}

/// The request body for one batch, and the summary it carries.
fn batch_body(
    request: &UploadRequest,
    projected: &[Option<Value>],
    index: usize,
    state: &UploadState,
) -> (Value, Option<Value>) {
    let receipts = Value::Array(projected.iter().flatten().cloned().collect());
    let mut context = request.sync_context.clone();
    if index == 0 {
        if let Some(posture) = &request.fleet_posture {
            context.insert("fleetPosture".to_owned(), posture.payload.clone());
        }
    }
    let mut workspace_sent = None;
    if let Some(pending) = &state.workspace_pending {
        let base = json!({"receipts": receipts, "syncContext": context});
        let base_size = i64::try_from(base.to_string().len()).unwrap_or(i64::MAX);
        if let Some(fitted) = fit_workspace(
            pending,
            MAX_REQUEST_BYTES - base_size - WORKSPACE_KEY_OVERHEAD,
        ) {
            context.insert("workspaceAssessments".to_owned(), fitted["payload"].clone());
            workspace_sent = Some(fitted);
        }
    }
    (
        json!({"receipts": receipts, "syncContext": context}),
        workspace_sent,
    )
}

/// `fit_workspace_assessment_to_request`: the summary is best-effort, so a
/// failure leaves it for a later request.
fn fit_workspace(built: &Value, max_bytes: i64) -> Option<Value> {
    let answer = crate::workspace_assessment_sync::dispatch(
        "workspace_assessment_fit",
        &json!({"payload": built.get("payload")?, "max_bytes": max_bytes}),
    )
    .ok()?;
    (answer.get("payload").is_some_and(Value::is_object)
        && answer.get("digest").is_some_and(Value::is_string))
    .then_some(answer)
}

fn receipts_url(auth: &Map<String, Value>) -> Result<String, SyncError> {
    route_url("receipts", &trusted_base(auth)?)
}

fn answer_object(answer: Option<Value>) -> Result<Map<String, Value>, SyncError> {
    match answer {
        Some(Value::Object(payload)) => Ok(payload),
        _ => Err(SyncError::Failed(INVALID_RESPONSE.to_owned())),
    }
}

/// `_cloud_edge_block_from_http_error`: Cloud's edge answered, not Guard Cloud.
fn edge_block(answer: Option<&Value>) -> Option<String> {
    answer?
        .get("edge_block")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// A refusal other than the 401 the caller may refresh past.
fn refusal_error(refusal: Refusal) -> SyncError {
    match refusal {
        Refusal::Http {
            status: 401,
            answer,
            ..
        } => edge_block(answer.as_ref()).map_or_else(
            || SyncError::AuthExpired(REAUTHORIZE.to_owned()),
            SyncError::Failed,
        ),
        Refusal::Http {
            status: 403,
            answer,
            ..
        } => {
            let message = answer_text(answer.as_ref(), "plan_message", 403);
            if answer
                .as_ref()
                .and_then(|answer| answer.get("plan_restricted"))
                == Some(&Value::Bool(true))
            {
                SyncError::NotAvailable {
                    message,
                    retryable: false,
                }
            } else {
                SyncError::Failed(message)
            }
        }
        Refusal::Http { status, answer, .. } => {
            SyncError::Failed(answer_text(answer.as_ref(), "sync_message", status))
        }
        Refusal::Transport(reason) => SyncError::Failed(unreachable_message(&reason)),
    }
}

/// POST one batch. A 401 refreshes the sign-in once per sync, only when the
/// caller did not supply it.
fn send(
    store: &EventStore<'_>,
    request: &UploadRequest,
    state: &mut UploadState,
    index: usize,
    body: &Value,
) -> Result<Map<String, Value>, SyncError> {
    let auth = state.auth.clone().unwrap_or_default();
    let refusal = match post(&auth, &receipts_url(&auth)?, body, true, EVENT_TIMEOUTS) {
        Ok(answer) => return answer_object(answer),
        Err(Err(error)) => return Err(error),
        Err(Ok(refusal)) => refusal,
    };
    let Refusal::Http {
        status: 401,
        answer,
        ..
    } = &refusal
    else {
        return Err(refusal_error(refusal));
    };
    let refreshable = request.allow_auth_refresh
        && edge_block(answer.as_ref()).is_none()
        && state.refreshed_at.is_none_or(|batch| batch == index);
    if !refreshable {
        return Err(refusal_error(refusal));
    }
    if state.refreshed_at.is_none() {
        let auth = resolve_auth(&store.bundle.resident, true, None)?;
        state.auth = Some(auth);
        state.refreshed_at = Some(index);
    }
    let auth = state.auth.clone().unwrap_or_default();
    match post(&auth, &receipts_url(&auth)?, body, true, EVENT_TIMEOUTS) {
        Ok(answer) => answer_object(answer),
        Err(Err(error)) => Err(error),
        Err(Ok(refusal)) => Err(refusal_error(refusal)),
    }
}

/// Record what Guard Cloud accepted from one batch, before the next is sent.
#[allow(clippy::too_many_arguments)]
fn record_batch(
    store: &EventStore<'_>,
    request: &UploadRequest,
    state: &mut UploadState,
    plan: &Plan,
    batch: &[Value],
    index: usize,
    workspace_sent: Option<Value>,
    payload: Map<String, Value>,
) -> Result<(), SyncError> {
    let response = Value::Object(payload);
    let stamp = synced_at(&response);
    // The posture and the summary are best-effort: a failed record only
    // means the next sync sends them again.
    if index == 0 {
        if let Some(posture) = &request.fleet_posture {
            if store
                .save(POSTURE_LAST_SENT_KEY, &posture.next_state, &stamp)
                .is_ok()
                && posture.advanced_inventory
            {
                let requested = store.payload(POSTURE_FORCE_FULL_KEY).ok().flatten();
                if requested
                    .is_some_and(|value| value.as_object().is_some_and(|map| !map.is_empty()))
                {
                    let _ = store.save(POSTURE_FORCE_FULL_KEY, &json!({}), &stamp);
                }
            }
        }
    }
    if response
        .get("fleetPostureRequest")
        .and_then(|request| request.get("inventory"))
        .and_then(Value::as_str)
        == Some("full")
    {
        let _ = store.save(
            POSTURE_FORCE_FULL_KEY,
            &json!({"requestedAt": stamp, "source": "cloud"}),
            &stamp,
        );
    }
    if let Some(fitted) = workspace_sent {
        state.workspace_pending = None;
        let sent_at = match &fitted["payload"]["generatedAt"] {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        let _ = store.save(
            WORKSPACE_DELIVERY_KEY,
            &json!({"digest": fitted["digest"], "sent_at": sent_at}),
            &sent_at,
        );
    }
    let tally = &mut state.tally;
    for row in batch {
        let in_cursor = row
            .get("receipt_id")
            .and_then(Value::as_str)
            .is_some_and(|id| plan.cursor_ids.contains(id));
        if let Some(id) = rowid(row).filter(|_| in_cursor) {
            tally.latest_rowid = Some(tally.latest_rowid.map_or(id, |latest| latest.max(id)));
        }
    }
    if let Some(updated) = state
        .marker
        .as_ref()
        .and_then(|marker| advance_marker(marker, batch, &stamp))
    {
        store.save(DETAIL_BACKFILL_MARKER, &updated, &stamp)?;
        state.marker = Some(updated);
    }
    if let Some(latest) = tally.latest_rowid {
        store.save(
            CURSOR_KEY,
            &json!({"last_rowid": latest, "synced_at": stamp}),
            &stamp,
        )?;
    }
    tally.accumulate(&response);
    Ok(())
}

impl Tally {
    fn accumulate(&mut self, response: &Value) {
        if let Some(stored) = response.get("receiptsStored").and_then(Value::as_i64) {
            self.receipts_stored += stored;
        }
        if let Some(advisories) = response.get("advisories").and_then(Value::as_array) {
            self.advisories
                .extend(advisories.iter().filter(|item| item.is_object()).cloned());
        }
        if let Some(bundle) = response.get("policyBundle") {
            self.bundle_provided = true;
            match bundle.as_object() {
                Some(map) if !map.is_empty() || self.bundle.is_none() => {
                    self.bundle = Some(bundle.clone());
                    self.bundle_sync_payload = response.clone();
                    self.delivery_provided = response.get("policyBundleDelivery").is_some();
                    self.delivery = response
                        .get("policyBundleDelivery")
                        .cloned()
                        .unwrap_or(Value::Null);
                }
                Some(_) => {}
                None => self.bundle_malformed = true,
            }
        }
        if let Some(preferences) = response.get("alertPreferences").and_then(Value::as_object) {
            if !preferences.is_empty() || self.alert_preferences.is_none() {
                self.alert_preferences = Some(Value::Object(preferences.clone()));
            }
        }
        if let Some(keys) = response.get("reviewVerificationKeys") {
            self.review_keys = keys.clone();
        }
        self.last_payload = response.as_object().cloned().unwrap_or_default();
    }
}

/// Save the backfill marker and the cursor, and report what the upload got.
fn finish(
    store: &EventStore<'_>,
    request: &UploadRequest,
    state: &UploadState,
    plan: &Plan,
) -> Result<Value, SyncError> {
    let tally = &state.tally;
    let last = Value::Object(tally.last_payload.clone());
    let now = synced_at(&last);
    if let Some(marker) = &state.marker {
        store.save(DETAIL_BACKFILL_MARKER, marker, &now)?;
    }
    let cursor = tally.latest_rowid.or(plan.prior_cursor);
    if let Some(rowid) = cursor {
        store.save(
            CURSOR_KEY,
            &json!({"last_rowid": rowid, "synced_at": now}),
            &now,
        )?;
    }
    // The policy acknowledgement follow-up ignores what Cloud answers it.
    let advisories_stored = if request.context_only {
        0
    } else {
        let call = |method: &str, args: Value| store.call(method, args);
        let save = |key: &str, payload: &Value, at: &str| store.save(key, payload, at);
        apply_answers(
            &call,
            &save,
            &tally.advisories,
            tally.alert_preferences.as_ref(),
            &now,
        )?
    };
    // The answer that carried the bundle is returned whole, for its
    // signature check; the bundle is its `policyBundle`.
    Ok(json!({
        "synced_at": last.get("syncedAt").cloned().unwrap_or(Value::Null),
        "now": now,
        "receipts": plan.projected.iter().flatten().count(),
        // Receipts too large for any request: the cursor moves past them.
        "receipts_skipped": plan.projected.iter().filter(|payload| payload.is_none()).count(),
        "receipts_stored": tally.receipts_stored,
        "advisories_stored": advisories_stored,
        "policy_bundle": {
            "provided": tally.bundle_provided,
            "malformed": tally.bundle_malformed,
            "sync_payload": tally.bundle_sync_payload,
            "delivery_provided": tally.delivery_provided,
            "delivery": tally.delivery,
        },
        "review_verification_keys": tally.review_keys,
        "receipt_cursor_rowid": cursor,
        "receipt_cursor_backfill": cursor_backfill(plan),
        "auth_refreshed": state.refreshed_at.is_some(),
    }))
}

#[cfg(test)]
#[path = "cloud_receipt_upload_tests.rs"]
mod tests;
