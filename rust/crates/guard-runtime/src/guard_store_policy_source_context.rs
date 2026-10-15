//! `policy_source_contexts`: the remembered command, context, workspace label
//! and scope path shown next to each stored policy decision. One batch reads
//! the matching receipts, inventory rows and resolved approvals once, then
//! picks the newest exact match per decision, as the Python store did.

use std::collections::{BTreeSet, HashMap, HashSet};

use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{placeholders, query_all, Row, StoreError, StoreResult};
use crate::guard_store_json::py_strip;
use crate::guard_store_policy_source_labels::{
    hash_match_variants, is_generic_policy_reason, is_human_policy_label, is_runtime_exact_key,
    normalize_policy_scope_path, provenance_workspace_path, runtime_exact_family,
    runtime_exact_key, sanitize_remembered_command, scanner_evidence_fields, truthy,
    workspace_display_label,
};
use crate::guard_store_policy_source_rows::{approval_command, artifact_matches_candidate, cell};

const INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");

const RECEIPT_COLUMNS: &str =
    "receipt_id, artifact_name, capabilities_summary, provenance_summary, \
     source_scope, scanner_evidence_json, artifact_id, harness, artifact_hash, timestamp";
const INVENTORY_COLUMNS: &str = "artifact_name, launch_command, source_scope, harness, artifact_id";
const APPROVAL_COLUMNS: &str =
    "request_id, artifact_name, launch_summary, launch_target, workspace, \
     resolved_at, trigger_summary, resolution_scope, harness, artifact_id, artifact_hash";

struct Item {
    harness: String,
    artifact_id: Option<String>,
    artifact_hash: Option<String>,
    workspace: Option<String>,
    reason: Option<String>,
}

impl Item {
    fn id(&self) -> Option<&str> {
        self.artifact_id.as_deref()
    }

    fn hash(&self) -> Option<&str> {
        self.artifact_hash.as_deref()
    }

    /// Artifact-id buckets apply without a hash or with a runtime-exact hash.
    fn uses_artifact_buckets(&self) -> bool {
        truthy(self.id()) && (!truthy(self.hash()) || is_runtime_exact_key(self.hash()))
    }
}

fn parse_items(args: &Args) -> StoreResult<Vec<Item>> {
    let entries = args.raw("items").and_then(Value::as_array).ok_or(INVALID)?;
    entries
        .iter()
        .map(|entry| {
            let entry = entry.as_object().ok_or(INVALID)?;
            let field = |key: &str| -> StoreResult<Option<String>> {
                match entry.get(key) {
                    None | Some(Value::Null) => Ok(None),
                    Some(Value::String(value)) => Ok(Some(value.clone())),
                    Some(_) => Err(INVALID),
                }
            };
            Ok(Item {
                harness: field("harness")?.ok_or(INVALID)?,
                artifact_id: field("artifact_id")?,
                artifact_hash: field("artifact_hash")?,
                workspace: field("workspace")?,
                reason: field("reason")?,
            })
        })
        .collect()
}

/// Insertion-ordered `(harness, key) -> rows` buckets.
#[derive(Default)]
struct Buckets {
    order: Vec<(String, String)>,
    rows: HashMap<(String, String), Vec<usize>>,
}

impl Buckets {
    fn push(&mut self, key: (String, String), row: usize) {
        if !self.rows.contains_key(&key) {
            self.order.push(key.clone());
        }
        self.rows.entry(key).or_default().push(row);
    }

    /// Rows for one key, or for that key under every harness when `harness` is `*`.
    fn extend(&self, harness: &str, key: &str, out: &mut Vec<usize>) {
        if harness == "*" {
            for bucket in self.order.iter().filter(|(_, value)| value == key) {
                out.extend(&self.rows[bucket]);
            }
        } else if let Some(rows) = self.rows.get(&(harness.to_owned(), key.to_owned())) {
            out.extend(rows);
        }
    }
}

#[derive(Default)]
struct Table {
    rows: Vec<Row>,
    by_artifact: Buckets,
    by_hash: Buckets,
}

impl Table {
    fn index(rows: Vec<Row>) -> Self {
        let mut table = Table::default();
        for (position, row) in rows.iter().enumerate() {
            let harness = cell(row, "harness").unwrap_or_default();
            if let Some(artifact_id) =
                cell(row, "artifact_id").filter(|value| !py_strip(value).is_empty())
            {
                if let Some(exact) = runtime_exact_key(Some(&artifact_id)) {
                    table.by_hash.push((harness.clone(), exact), position);
                }
                table
                    .by_artifact
                    .push((harness.clone(), artifact_id), position);
            }
            if let Some(artifact_hash) =
                cell(row, "artifact_hash").filter(|value| !py_strip(value).is_empty())
            {
                for variant in hash_match_variants(&artifact_hash) {
                    table.by_hash.push((harness.clone(), variant), position);
                }
            }
        }
        table.rows = rows;
        table
    }

    fn hash_candidates(&self, item: &Item, out: &mut Vec<usize>) {
        if let Some(artifact_hash) = item.hash().filter(|value| !value.is_empty()) {
            for variant in hash_match_variants(artifact_hash) {
                self.by_hash.extend(&item.harness, &variant, out);
            }
        }
    }

    fn artifact_candidates(&self, item: &Item, out: &mut Vec<usize>) {
        if item.uses_artifact_buckets() {
            self.by_artifact
                .extend(&item.harness, item.id().unwrap_or(""), out);
        }
    }

    /// The first row with the greatest (exact artifact match, timestamp).
    fn best(
        &self,
        candidates: &[usize],
        artifact_id: Option<&str>,
        timestamp: &str,
    ) -> Option<&Row> {
        let key = |position: usize| {
            let row = &self.rows[position];
            let exact = truthy(artifact_id) && cell(row, "artifact_id").as_deref() == artifact_id;
            (exact, cell(row, timestamp).unwrap_or_default())
        };
        let mut best: Option<(usize, (bool, String))> = None;
        for &position in candidates {
            let candidate = key(position);
            if best
                .as_ref()
                .is_none_or(|(_, current)| candidate > *current)
            {
                best = Some((position, candidate));
            }
        }
        best.map(|(position, _)| &self.rows[position])
    }
}

struct Index {
    receipts: Table,
    inventory: HashMap<(String, String), Row>,
    approvals: Table,
}

fn match_clauses(
    fallback_ids: &[&str],
    families: &[String],
    variants: &[String],
) -> (String, Vec<Value>) {
    let mut clauses = Vec::new();
    let mut params = Vec::new();
    if !fallback_ids.is_empty() {
        clauses.push(format!(
            "artifact_id in ({})",
            placeholders(fallback_ids.len())
        ));
        params.extend(fallback_ids.iter().map(|value| Value::from(*value)));
    }
    for family in families {
        clauses.push("artifact_id like ?".to_owned());
        params.push(Value::from(format!("%:{family}:%")));
    }
    if !variants.is_empty() {
        clauses.push(format!(
            "artifact_hash in ({})",
            placeholders(variants.len())
        ));
        params.extend(variants.iter().map(|value| Value::from(value.as_str())));
    }
    (clauses.join(" or "), params)
}

fn build_index(connection: &Connection, items: &[Item]) -> StoreResult<Index> {
    let harness_set: BTreeSet<&str> = items
        .iter()
        .map(|item| item.harness.as_str())
        .filter(|harness| !harness.is_empty())
        .collect();
    let all_harnesses = harness_set.contains("*");
    let harnesses: Vec<&str> = harness_set
        .into_iter()
        .filter(|harness| *harness != "*")
        .collect();
    let artifact_ids: Vec<&str> = items
        .iter()
        .filter_map(Item::id)
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let fallback_ids: Vec<&str> = items
        .iter()
        .filter(|item| item.uses_artifact_buckets())
        .filter_map(Item::id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let families: Vec<String> = items
        .iter()
        .filter(|item| truthy(item.hash()) && is_runtime_exact_key(item.hash()))
        .filter_map(|item| runtime_exact_family(item.id()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let variants: Vec<String> = items
        .iter()
        .filter_map(Item::hash)
        .filter(|value| !value.is_empty())
        .flat_map(hash_match_variants)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let (harness_sql, harness_params) = if all_harnesses || harnesses.is_empty() {
        (String::new(), Vec::new())
    } else {
        (
            format!("and harness in ({})", placeholders(harnesses.len())),
            harnesses.iter().map(|value| Value::from(*value)).collect(),
        )
    };
    let searchable = !fallback_ids.is_empty() || !variants.is_empty();
    let (clauses, match_params) = match_clauses(&fallback_ids, &families, &variants);
    let params: Vec<Value> = match_params
        .iter()
        .chain(&harness_params)
        .cloned()
        .collect();

    let receipts = if searchable {
        let sql = format!(
            "select {RECEIPT_COLUMNS} from runtime_receipts where ({clauses}) {harness_sql} \
             order by timestamp desc"
        );
        Table::index(query_all(connection, &sql, &params)?)
    } else {
        Table::default()
    };

    let mut inventory = HashMap::new();
    if !harnesses.is_empty() && !artifact_ids.is_empty() {
        let sql = format!(
            "select {INVENTORY_COLUMNS} from artifact_inventory where harness in ({}) and artifact_id in ({})",
            placeholders(harnesses.len()),
            placeholders(artifact_ids.len())
        );
        let inventory_params: Vec<Value> = harnesses
            .iter()
            .chain(&artifact_ids)
            .map(|value| Value::from(*value))
            .collect();
        for row in query_all(connection, &sql, &inventory_params)? {
            let key = (
                cell(&row, "harness").unwrap_or_default(),
                cell(&row, "artifact_id").unwrap_or_default(),
            );
            inventory.insert(key, row);
        }
    }

    let approvals = if searchable {
        let sql = format!(
            "select {APPROVAL_COLUMNS} from approval_requests where status = 'resolved' \
             and ({clauses}) {harness_sql} order by resolved_at desc"
        );
        Table::index(query_all(connection, &sql, &params)?)
    } else {
        Table::default()
    };
    Ok(Index {
        receipts,
        inventory,
        approvals,
    })
}

fn approval_matches(item: &Item, approvals: &Table, candidates: Vec<usize>) -> Vec<usize> {
    if !truthy(item.id()) && !truthy(item.hash()) {
        return Vec::new();
    }
    let variants: HashSet<String> = item
        .hash()
        .filter(|value| !value.is_empty())
        .map(hash_match_variants)
        .unwrap_or_default()
        .into_iter()
        .collect();
    let mut seen = HashSet::new();
    candidates
        .into_iter()
        .filter(|&position| {
            let row = &approvals.rows[position];
            if item.harness != "*" && cell(row, "harness").unwrap_or_default() != item.harness {
                return false;
            }
            let row_id = cell(row, "artifact_id");
            if !artifact_matches_candidate(item.id(), row_id.as_deref()) {
                return false;
            }
            if truthy(item.hash()) {
                let row_hash = cell(row, "artifact_hash").unwrap_or_default();
                if !variants.contains(&row_hash)
                    && runtime_exact_key(row_id.as_deref()).as_deref() != item.hash()
                {
                    return false;
                }
            }
            seen.insert(cell(row, "request_id").unwrap_or_default())
        })
        .collect()
}

fn context_from_rows(
    item: &Item,
    receipt: Option<&Row>,
    inventory: Option<&Row>,
    approval: Option<&Row>,
) -> Value {
    let workspace = item.workspace.as_deref();
    let mut command: Option<String> = None;
    let mut context: Option<String> = None;
    let mut workspace_label: Option<String> = None;
    let mut receipt_id: Option<String> = None;
    let mut scope_path: Option<String> = None;

    if let Some(row) = approval {
        command = approval_command(row);
        let launch_summary = cell(row, "launch_summary");
        if is_human_policy_label(launch_summary.as_deref()) {
            context = launch_summary.map(|value| py_strip(&value).to_owned());
        }
        if let Some(approval_workspace) = cell(row, "workspace") {
            if let Some(path) = normalize_policy_scope_path(Some(&approval_workspace)) {
                scope_path = Some(path);
            }
            workspace_label = workspace_display_label(Some(&approval_workspace), workspace);
        }
    }

    if let Some(row) = receipt {
        receipt_id = cell(row, "receipt_id");
        let (scanner_command, scanner_context) =
            scanner_evidence_fields(cell(row, "scanner_evidence_json").as_deref());
        if truthy(scanner_command.as_deref()) && is_human_policy_label(scanner_command.as_deref()) {
            command = scanner_command;
        }
        if truthy(scanner_context.as_deref()) {
            context = scanner_context;
        }
        let receipt_name = cell(row, "artifact_name");
        if command.is_none() && is_human_policy_label(receipt_name.as_deref()) {
            command = receipt_name.map(|value| sanitize_remembered_command(&value));
        }
        if context.is_none() {
            if let Some(capabilities) = cell(row, "capabilities_summary") {
                let capabilities = py_strip(&capabilities);
                if !capabilities.is_empty() && is_human_policy_label(Some(capabilities)) {
                    context = Some(capabilities.to_owned());
                }
            }
        }
        let source_scope = cell(row, "source_scope");
        let receipt_path = normalize_policy_scope_path(source_scope.as_deref());
        scope_path = if truthy(receipt_path.as_deref()) {
            receipt_path
        } else {
            let provenance_path =
                provenance_workspace_path(cell(row, "provenance_summary").as_deref());
            normalize_policy_scope_path(provenance_path.as_deref())
        };
        workspace_label = workspace_display_label(source_scope.as_deref(), workspace);
    }

    if let Some(row) = inventory {
        let launch_command = cell(row, "launch_command");
        if command.is_none() && is_human_policy_label(launch_command.as_deref()) {
            command = launch_command.map(|value| py_strip(&value).to_owned());
        }
        let inventory_name = cell(row, "artifact_name");
        if context.is_none() && is_human_policy_label(inventory_name.as_deref()) {
            context = inventory_name.map(|value| py_strip(&value).to_owned());
        }
        if workspace_label.is_none() {
            workspace_label =
                workspace_display_label(cell(row, "source_scope").as_deref(), workspace);
        }
    }

    if command.is_none() && !is_generic_policy_reason(item.reason.as_deref()) {
        command = item
            .reason
            .as_deref()
            .map(|value| py_strip(value).to_owned());
    }

    if receipt_id.is_none() && command.is_none() && context.is_none() && scope_path.is_none() {
        return Value::Null;
    }
    let mut payload = Map::new();
    for (key, value) in [
        ("source_receipt_id", receipt_id),
        ("remembered_command", command),
        ("remembered_context", context),
        ("workspace_label", workspace_label),
        ("source_scope_path", scope_path),
    ] {
        if let Some(value) = value {
            payload.insert(key.to_owned(), Value::String(value));
        }
    }
    Value::Object(payload)
}

fn lookup(index: &Index, item: &Item) -> Value {
    let mut receipt_candidates = Vec::new();
    index
        .receipts
        .hash_candidates(item, &mut receipt_candidates);
    index
        .receipts
        .artifact_candidates(item, &mut receipt_candidates);
    let receipt = index
        .receipts
        .best(&receipt_candidates, item.id(), "timestamp");

    let inventory = item
        .id()
        .filter(|value| !py_strip(value).is_empty() && item.harness != "*")
        .and_then(|value| {
            index
                .inventory
                .get(&(item.harness.clone(), value.to_owned()))
        });

    let mut approval_candidates = Vec::new();
    index
        .approvals
        .artifact_candidates(item, &mut approval_candidates);
    index
        .approvals
        .hash_candidates(item, &mut approval_candidates);
    let approval_candidates = approval_matches(item, &index.approvals, approval_candidates);
    let approval = index
        .approvals
        .best(&approval_candidates, item.id(), "resolved_at");

    context_from_rows(item, receipt, inventory, approval)
}

/// `{"items": [{harness, artifact_id?, artifact_hash?, workspace?, reason?}]}`
/// returns one context object or null per item, in order.
pub(crate) fn policy_source_contexts(
    connection: &Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let items = parse_items(args)?;
    if items.is_empty() {
        return Ok(Value::Array(Vec::new()));
    }
    let index = build_index(connection, &items)?;
    Ok(Value::Array(
        items.iter().map(|item| lookup(&index, item)).collect(),
    ))
}
