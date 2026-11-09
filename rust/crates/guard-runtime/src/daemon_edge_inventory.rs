//! `GET /v1/inventory`: the stored artifact inventory, each item carrying its
//! harness contract, and the harnesses with nothing installed yet.

use serde_json::{json, Map, Value};

use super::{NativeReads, ReadConfig};

/// The daemon's `contracts_index`, generated from `HARNESS_CONTRACTS` and
/// `capability_for` in registry order.
const CONTRACT_INDEX: &str = include_str!("../data/harness_contract_index.v1.json");

/// Every `(harness, contract)` in registry order.
pub(super) fn contracts() -> Option<Vec<(String, Value)>> {
    let index: Value = serde_json::from_str(CONTRACT_INDEX).ok()?;
    index
        .get("contracts")?
        .as_array()?
        .iter()
        .map(|row| {
            Some((
                row.get("harness")?.as_str()?.to_owned(),
                row.get("contract")?.clone(),
            ))
        })
        .collect()
}

/// `store.list_inventory()`: every resident page in order. A page the daemon
/// would refuse, or a cursor that does not move, goes to the daemon.
fn inventory(config: &ReadConfig, reads: &NativeReads) -> Option<Vec<Map<String, Value>>> {
    let mut rows = Vec::new();
    let mut cursor: Option<Value> = None;
    loop {
        let mut args = json!({"harness": null});
        if let Some(after) = &cursor {
            args["after"] = after.clone();
        }
        let page = reads.store_call(config, "list_artifact_inventory", args)?;
        for row in page.get("rows")?.as_array()? {
            rows.push(row.as_object()?.clone());
        }
        match page.get("next")? {
            Value::Null => return Some(rows),
            next @ Value::Object(_) if cursor.as_ref() != Some(next) => cursor = Some(next.clone()),
            _ => return None,
        }
    }
}

pub(super) fn list(config: &ReadConfig, reads: &NativeReads) -> Option<(u16, Value)> {
    let contracts = contracts()?;
    let items = inventory(config, reads)?;
    let contract_for = |harness: &str| {
        contracts
            .iter()
            .find(|(name, _)| name == harness)
            .map_or_else(|| json!({}), |(_, contract)| contract.clone())
    };
    let installed: Vec<String> = items
        .iter()
        .map(|item| match item.get("harness") {
            Some(Value::String(harness)) => harness.clone(),
            // `str(item.get("harness", ""))` of anything else never names a
            // registered harness.
            _ => String::new(),
        })
        .collect();
    let enriched: Vec<Value> = items
        .into_iter()
        .zip(&installed)
        .map(|(mut item, harness)| {
            item.insert("contract".to_owned(), contract_for(harness));
            Value::Object(item)
        })
        .collect();
    let available: Vec<Value> = contracts
        .iter()
        .filter(|(harness, _)| !installed.contains(harness))
        .map(|(harness, contract)| {
            json!({"harness": harness, "status": "unknown", "contract": contract})
        })
        .collect();
    Some((200, json!({"items": enriched, "available": available})))
}

#[cfg(test)]
#[path = "daemon_edge_inventory_tests.rs"]
mod tests;
