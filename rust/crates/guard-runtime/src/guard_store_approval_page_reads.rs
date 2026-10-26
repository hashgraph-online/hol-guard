//! Approval queue pages and counts: `GuardStore.list_approval_request_page`,
//! `GuardStore.count_approval_requests` and
//! `GuardStore.get_next_pending_request`. A page carries display summaries
//! (`_row_to_approval_summary`) only; full payloads keep the scope contract.

use base64ct::{Base64UrlUnpadded, Encoding};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::cloud_request_text::py_strip;
use crate::guard_store_approval_read_rows::{browser_launch_target, json_list, py_bool, py_int};
use crate::guard_store_approval_read_scope::{project, unavailable};
use crate::guard_store_approval_reads::{continuation, payloads, COLUMNS, PAGE_BYTES};
use crate::guard_store_args::Args;
use crate::guard_store_db::{query_all, query_one, Row, StoreError, StoreResult};
use crate::guard_store_json::dumps_sorted;
use crate::guard_store_silent_review::{py_str, raw};

pub(crate) const SUMMARY_COLUMNS: &str =
    "request_id, harness, artifact_id, artifact_name, artifact_type, \
     policy_action, decision_v2_json, action_envelope_json, changed_fields_json, source_scope, \
     config_path, workspace, launch_target, risk_summary, risk_headline, action_identity, \
     queue_group_id, dedupe_count, raw_command_text, fallback_cli_command, \
     watch_only_observation, review_command, created_at, last_seen_at, status";
const SEARCH_COLUMNS: [&str; 15] = [
    "artifact_name",
    "artifact_id",
    "risk_summary",
    "risk_headline",
    "trigger_summary",
    "why_now",
    "launch_summary",
    "launch_target",
    "raw_command_text",
    "fallback_cli_command",
    "review_command",
    "action_identity",
    "action_envelope_json",
    "decision_v2_json",
    "config_path",
];
pub(crate) const ORDER: &str = "order by last_seen_at desc, request_id desc";
/// `store_approvals.MAX_APPROVAL_PAGE_LIMIT`.
const MAX_PAGE_LIMIT: i64 = 200;
/// Pending payloads `get_next_pending_request` chooses from.
const NEXT_CANDIDATES: i64 = 10;
/// `store_approval_projection.APPROVAL_QUEUE_PREVIEW_MAX_LENGTH`.
const PREVIEW_MAX_CHARS: usize = 512;

/// The `where` clause of one queue read.
#[derive(Default)]
pub(crate) struct Filter {
    clauses: Vec<String>,
    params: Vec<Value>,
}

impl Filter {
    fn push(&mut self, clause: &str, params: Vec<Value>) {
        self.clauses.push(clause.to_owned());
        self.params.extend(params);
    }

    /// `column = ?` when the caller passed a value.
    pub(crate) fn equals(&mut self, column: &str, value: Option<&str>) {
        if let Some(value) = value {
            self.push(&format!("{column} = ?"), vec![Value::from(value)]);
        }
    }

    /// Rows after a `[last_seen_at, request_id]` page marker.
    pub(crate) fn after(&mut self, marker: Option<Vec<&str>>) -> StoreResult<()> {
        let Some(marker) = marker else {
            return Ok(());
        };
        let [last_seen_at, request_id] = marker[..] else {
            return Err(StoreError::Invalid("native_guard_store_args_invalid"));
        };
        self.push(
            "(last_seen_at < ? or (last_seen_at = ? and request_id < ?))",
            Vec::from([last_seen_at, last_seen_at, request_id].map(Value::from)),
        );
        Ok(())
    }

    /// Rows after the sort key of a chunk's last row, `after` from the
    /// previous chunk; a null `last_seen_at` sorts last.
    pub(crate) fn continue_after(&mut self, after: Option<&Value>) -> StoreResult<()> {
        let Some(after) = after else {
            return Ok(());
        };
        let Some([last_seen_at, Value::String(request_id)]) = after.as_array().map(Vec::as_slice)
        else {
            return Err(StoreError::Invalid("native_guard_store_args_invalid"));
        };
        let request_id = Value::from(request_id.as_str());
        if last_seen_at.is_null() {
            self.push(
                "(last_seen_at is null and request_id < ?)",
                vec![request_id],
            );
        } else {
            self.push(
                "(last_seen_at < ? or last_seen_at is null \
                 or (last_seen_at = ? and request_id < ?))",
                vec![last_seen_at.clone(), last_seen_at.clone(), request_id],
            );
        }
        Ok(())
    }

    /// `_approval_search_clause`: a case-folded substring of any searchable
    /// column, wildcards included.
    pub(crate) fn search(&mut self, search: Option<&str>) {
        let Some(search) = search else {
            return;
        };
        let terms: Vec<String> = SEARCH_COLUMNS
            .iter()
            .map(|column| format!("lower(coalesce({column}, '')) like lower(?)"))
            .collect();
        let pattern = format!("%{search}%");
        self.push(
            &format!("({})", terms.join(" or ")),
            SEARCH_COLUMNS
                .iter()
                .map(|_| Value::from(pattern.as_str()))
                .collect(),
        );
    }

    fn exclude_watch_only(&mut self, exclude: bool) {
        if exclude {
            self.push("watch_only_observation = 0", Vec::new());
        }
    }

    /// The `where ...` text, empty without clauses, and its parameters.
    pub(crate) fn finish(self) -> (String, Vec<Value>) {
        let sql = if self.clauses.is_empty() {
            String::new()
        } else {
            format!("where {}", self.clauses.join(" and "))
        };
        (sql, self.params)
    }
}

/// `count_approval_requests(status, harness, search, resolved_at_from,
/// resolved_at_before, exclude_watch_only)`.
pub(crate) fn count_approval_requests(
    connection: &Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let mut filter = queue_filter(args, args.opt_str("status")?)?;
    if let Some(from) = args.opt_str("resolved_at_from")? {
        filter.push("resolved_at >= ?", vec![Value::from(from)]);
    }
    if let Some(before) = args.opt_str("resolved_at_before")? {
        filter.push("resolved_at < ?", vec![Value::from(before)]);
    }
    count(connection, filter)
}

/// `list_approval_request_page(status, limit, cursor, harness, search,
/// include_totals, exclude_watch_only)` as bounded chunks:
/// `{"items": [...], "complete": bool}`. An incomplete chunk carries `after`
/// for the caller to pass back with `taken`, the items it holds; the chunk
/// that completes the page also carries `next_cursor`, `status` and, when
/// asked, the totals.
pub(crate) fn list_approval_request_page(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let page_limit = args.int("limit")?.clamp(1, MAX_PAGE_LIMIT);
    let taken = args
        .raw("taken")
        .map_or(Ok(0), |_| args.int("taken"))?
        .clamp(0, page_limit);
    let remaining = page_limit - taken;
    let status = args.opt_str("status")?;
    let mut filter = queue_filter(args, status)?;
    filter.after(args.strings("cursor")?)?;
    filter.continue_after(args.raw("after"))?;
    let (sql, mut params) = filter.finish();
    // One row past the page tells whether another page follows.
    params.push(Value::from(remaining + 1));
    let rows = query_all(
        connection,
        &format!("select {SUMMARY_COLUMNS} from approval_requests {sql} {ORDER} limit ?"),
        &params,
    )?;
    let has_more = rows.len() as i64 > remaining;
    let wanted = rows.len().min(usize::try_from(remaining).unwrap_or(0));
    let mut items = Vec::new();
    let mut bytes = 0;
    let mut summary_error = None;
    // Rows project one at a time and stop at the byte budget; rows past the
    // cut project in the chunk that returns them. Python projected every
    // fetched row before summarizing any, so a projection error wins over an
    // earlier summary error: once a summary fails, the remaining rows, the
    // probe row included, are still projected.
    for (index, row) in rows.iter().enumerate() {
        let projection = project(row, guard_home)?;
        if summary_error.is_some() || index >= wanted {
            continue;
        }
        match summary(row, &projection) {
            Ok(summary) => {
                bytes += serde_json::to_vec(&summary).map_or(0, |encoded| encoded.len());
                if !items.is_empty() && bytes > PAGE_BYTES {
                    break;
                }
                items.push(Value::Object(summary));
            }
            Err(error) => summary_error = Some(error),
        }
    }
    if let Some(error) = summary_error {
        return Err(error);
    }
    if items.len() < wanted {
        let after = continuation(&rows[items.len() - 1]);
        return Ok(json!({"items": items, "complete": false, "after": after}));
    }
    let next_cursor = match items.last() {
        Some(last) if has_more => Value::String(page_cursor(last)?),
        _ => Value::Null,
    };
    let label = status.filter(|status| !status.is_empty()).unwrap_or("all");
    let mut page = json!({
        "items": items,
        "complete": true,
        "next_cursor": next_cursor,
        "status": label,
    });
    if args.flag("include_totals")? {
        page["total_count"] = count(connection, queue_filter(args, status)?)?;
        page["total_pending_count"] = count(connection, queue_filter(args, Some("pending"))?)?;
    }
    Ok(page)
}

/// `get_next_pending_request(exclude_ids)`: the newest of the first pending
/// payloads whose id is not excluded.
pub(crate) fn get_next_pending_request(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
    owner: Option<&crate::policy_store::PolicySnapshotStore>,
) -> StoreResult<Value> {
    let excluded = args.strings("exclude_ids")?.unwrap_or_default();
    let rows = query_all(
        connection,
        &format!("select {COLUMNS} from approval_requests where status = ? {ORDER} limit ?"),
        &[Value::from("pending"), Value::from(NEXT_CANDIDATES)],
    )?;
    let projections = rows
        .iter()
        .map(|row| project(row, guard_home))
        .collect::<StoreResult<Vec<_>>>()?;
    let candidates = payloads(
        rows.iter().zip(projections).collect(),
        args.opt_str("cwd")?,
        owner.map(|owner| (connection, owner)),
    )?;
    Ok(candidates
        .into_iter()
        .find(|payload| {
            payload
                .get("request_id")
                .and_then(Value::as_str)
                .is_some_and(|request_id| !excluded.contains(&request_id))
        })
        .map_or(Value::Null, Value::Object))
}

/// The status, harness, search and watch-only clauses a page and its totals
/// share.
fn queue_filter(args: &Args<'_>, status: Option<&str>) -> StoreResult<Filter> {
    let mut filter = Filter::default();
    filter.equals("status", status);
    filter.equals("harness", args.opt_str("harness")?);
    filter.search(args.opt_str("search")?);
    filter.exclude_watch_only(args.flag("exclude_watch_only")?);
    Ok(filter)
}

fn count(connection: &Connection, filter: Filter) -> StoreResult<Value> {
    let (sql, params) = filter.finish();
    let row = query_one(
        connection,
        &format!("select count(*) as total from approval_requests {sql}"),
        &params,
    )?;
    Ok(row
        .and_then(|mut row| row.remove("total"))
        .unwrap_or_else(|| Value::from(0)))
}

/// `_encode_page_cursor`: the item's page marker as unpadded URL-safe
/// base64 of its compact sorted JSON.
fn page_cursor(item: &Value) -> StoreResult<String> {
    let marker = json!({
        "last_seen_at": item["last_seen_at"].clone(),
        "request_id": item["request_id"].clone(),
    });
    let encoded = dumps_sorted(&marker).ok_or_else(unavailable)?;
    Ok(Base64UrlUnpadded::encode_string(encoded.as_bytes()))
}

/// `_row_to_approval_summary`, field by field in Python's order.
pub(crate) fn summary(row: &Row, projection: &Value) -> StoreResult<Map<String, Value>> {
    let (launch_target, _) = browser_launch_target(raw(row, "launch_target"));
    let envelope = projection["action_envelope_json"].as_object();
    let text = |name: &str| py_str(row.get(name)).map(Value::String);
    let category = envelope
        .and_then(|envelope| envelope.get("command_category"))
        .filter(|category| {
            category
                .as_str()
                .is_some_and(|category| category.starts_with("command."))
        })
        .cloned()
        .unwrap_or(Value::Null);
    let mut payload = Map::new();
    for name in [
        "request_id",
        "harness",
        "artifact_id",
        "artifact_name",
        "artifact_type",
    ] {
        payload.insert(name.to_owned(), text(name)?);
    }
    payload.insert(
        "policy_action".to_owned(),
        projection["policy_action"].clone(),
    );
    payload.insert(
        "changed_fields".to_owned(),
        Value::Array(json_list(row, "changed_fields_json")?),
    );
    payload.insert("source_scope".to_owned(), text("source_scope")?);
    payload.insert("config_path".to_owned(), text("config_path")?);
    payload.insert("workspace".to_owned(), raw(row, "workspace"));
    payload.insert(
        "queue_preview".to_owned(),
        queue_preview(envelope, &launch_target),
    );
    payload.insert("launch_target".to_owned(), launch_target);
    payload.insert("queue_command_category".to_owned(), category);
    for name in [
        "risk_summary",
        "risk_headline",
        "raw_command_text",
        "fallback_cli_command",
    ] {
        payload.insert(name.to_owned(), raw(row, name));
    }
    payload.insert("review_command".to_owned(), text("review_command")?);
    payload.insert("action_identity".to_owned(), raw(row, "action_identity"));
    payload.insert("queue_group_id".to_owned(), raw(row, "queue_group_id"));
    payload.insert(
        "dedupe_count".to_owned(),
        py_int(&raw(row, "dedupe_count"))?,
    );
    payload.insert(
        "watch_only_observation".to_owned(),
        Value::Bool(py_bool(&raw(row, "watch_only_observation"))),
    );
    payload.insert("created_at".to_owned(), text("created_at")?);
    payload.insert("last_seen_at".to_owned(), raw(row, "last_seen_at"));
    payload.insert("display_status".to_owned(), text("status")?);
    if let Some(error) = projection["contract_error"].as_str() {
        payload.insert(
            "decision_contract_error".to_owned(),
            Value::String(error.to_owned()),
        );
    }
    Ok(payload)
}

/// `_approval_queue_preview`: the envelope command, else the display launch
/// target, stripped and cut to the preview length.
fn queue_preview(envelope: Option<&Map<String, Value>>, launch_target: &Value) -> Value {
    let command = envelope
        .and_then(|envelope| envelope.get("command"))
        .and_then(Value::as_str)
        .filter(|command| !py_strip(command).is_empty());
    let Some(normalized) = command.or_else(|| launch_target.as_str()).map(py_strip) else {
        return Value::Null;
    };
    if normalized.is_empty() {
        return Value::Null;
    }
    if normalized.chars().count() <= PREVIEW_MAX_CHARS {
        return Value::String(normalized.to_owned());
    }
    let mut cut: String = normalized.chars().take(PREVIEW_MAX_CHARS - 1).collect();
    cut.push('…');
    Value::String(cut)
}

#[cfg(all(test, unix))]
#[path = "guard_store_approval_page_reads_tests.rs"]
mod tests;
