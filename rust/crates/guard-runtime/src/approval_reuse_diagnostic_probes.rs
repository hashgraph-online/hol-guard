//! Bounded, index-ordered near-match probes for the saved-allow diagnostic.
//!
//! Probes inside one group are disjoint (requested versus wildcard harness,
//! one action each), so each reads at most `LIMIT` rows in index order before a
//! small in-memory merge. Groups concatenate in precedence order until `LIMIT`
//! rows are collected. Every probe names its index so a missing index fails
//! closed instead of degrading to a table scan.

use rusqlite::{types::Value as Sql, Connection};
use serde_json::Value;

use crate::policy_decision_lookup_op::{
    local_once_row_to_json, policy_row_to_json, LOCAL_ONCE_CLAIM_COLUMNS,
    LOCAL_ONCE_LEGACY_AUTHORITY_KIND, POLICY_LOOKUP_COLUMNS,
};

pub(crate) const DIAGNOSTIC_LIMIT: i64 = 32;

/// `GUARD_ACTION_VALUES`, in precedence order.
const ACTIONS: [&str; 6] = [
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
];

struct Probe {
    predicate: String,
    parameters: Vec<Sql>,
    index: &'static str,
}

type Group = Vec<Probe>;

fn text(value: &str) -> Sql {
    Sql::Text(value.to_owned())
}

fn distinct_non_null<'a>(values: &[Option<&'a str>]) -> Vec<&'a str> {
    let mut out: Vec<&str> = Vec::new();
    for value in values.iter().flatten() {
        if !out.contains(value) {
            out.push(value);
        }
    }
    out
}

/// Exclude nullable values without introducing an OR predicate.
fn exclude(
    mut predicate: String,
    parameters: &mut Vec<Sql>,
    column: &str,
    values: &[&str],
) -> String {
    for value in values {
        predicate.push_str(&format!(" and {column} is not ?"));
        parameters.push(text(value));
    }
    predicate
}

fn run_groups(
    connection: &Connection,
    table: &str,
    columns: &str,
    groups: &[Group],
    order_column: &str,
    id_column: &str,
    to_json: fn(&rusqlite::Row<'_>) -> rusqlite::Result<Value>,
) -> rusqlite::Result<Vec<Value>> {
    let mut rows: Vec<Value> = Vec::new();
    for probes in groups {
        let mut group_rows: Vec<Value> = Vec::new();
        for probe in probes {
            let sql = format!(
                "select {columns} from {table} indexed by {} where {} \
                 order by {order_column} desc, {id_column} desc limit ?",
                probe.index, probe.predicate
            );
            let mut parameters = probe.parameters.clone();
            parameters.push(Sql::Integer(DIAGNOSTIC_LIMIT));
            let mut statement = connection.prepare(&sql)?;
            let found = statement
                .query_map(rusqlite::params_from_iter(parameters), to_json)?
                .collect::<rusqlite::Result<Vec<Value>>>()?;
            group_rows.extend(found);
        }
        group_rows.sort_by(|left, right| {
            sort_key(right, order_column, id_column).cmp(&sort_key(left, order_column, id_column))
        });
        let remaining = DIAGNOSTIC_LIMIT as usize - rows.len();
        if remaining == 0 {
            break;
        }
        rows.extend(group_rows.into_iter().take(remaining));
        if rows.len() >= DIAGNOSTIC_LIMIT as usize {
            break;
        }
    }
    Ok(rows)
}

fn sort_key(row: &Value, order_column: &str, id_column: &str) -> (String, i64, String) {
    let order = match &row[order_column] {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    match &row[id_column] {
        Value::Number(number) => (order, number.as_i64().unwrap_or(0), String::new()),
        Value::String(text) => (order, 0, text.clone()),
        _ => (order, 0, String::new()),
    }
}

fn local_groups(
    harness: &str,
    artifact_id: &str,
    artifact_family: Option<&str>,
    artifact_hash: Option<&str>,
) -> Vec<Group> {
    let identities = distinct_non_null(&[Some(artifact_id), artifact_family]);
    let base = "claimed_at is null and action = 'allow' and (authority_kind is null or authority_kind = ?) and harness = ?";
    let mut groups: Vec<Group> = identities
        .iter()
        .map(|identity| {
            vec![Probe {
                predicate: format!("{base} and artifact_id = ?"),
                parameters: vec![
                    text(LOCAL_ONCE_LEGACY_AUTHORITY_KIND),
                    text(harness),
                    text(identity),
                ],
                index: "idx_guard_local_once_diagnostic_artifact",
            }]
        })
        .collect();
    if let Some(hash) = artifact_hash {
        let mut parameters = vec![
            text(LOCAL_ONCE_LEGACY_AUTHORITY_KIND),
            text(harness),
            text(hash),
        ];
        let predicate = exclude(
            format!("{base} and artifact_hash = ?"),
            &mut parameters,
            "artifact_id",
            &identities,
        );
        groups.push(vec![Probe {
            predicate,
            parameters,
            index: "idx_guard_local_once_diagnostic_hash",
        }]);
    }
    groups
}

/// Local near matches in legacy diagnostic precedence order.
pub(crate) fn local_rows(
    connection: &Connection,
    harness: &str,
    artifact_id: &str,
    artifact_family: Option<&str>,
    artifact_hash: Option<&str>,
) -> rusqlite::Result<Vec<Value>> {
    let groups = local_groups(harness, artifact_id, artifact_family, artifact_hash);
    run_groups(
        connection,
        "guard_local_once_approvals",
        LOCAL_ONCE_CLAIM_COLUMNS,
        &groups,
        "created_at",
        "approval_id",
        local_once_row_to_json,
    )
}

fn probe(predicate: &str, parameters: Vec<Sql>, index: &'static str) -> Probe {
    Probe {
        predicate: predicate.to_owned(),
        parameters,
        index,
    }
}

fn artifact_groups(harnesses: &[&str], identities: &[&str]) -> Vec<Group> {
    identities
        .iter()
        .map(|identity| {
            let mut group = Group::new();
            for harness in harnesses {
                for action in ACTIONS {
                    group.push(probe(
                        "action = ? and harness = ? and artifact_id = ?",
                        vec![text(action), text(harness), text(identity)],
                        "idx_policy_decisions_reuse_artifact",
                    ));
                }
            }
            group
        })
        .collect()
}

fn hash_group(harnesses: &[&str], identities: &[&str], hash: &str) -> Group {
    let mut group = Group::new();
    for harness in harnesses {
        for action in ACTIONS {
            let mut parameters = vec![text(action), text(harness), text(hash)];
            let predicate = exclude(
                "action = ? and harness = ? and artifact_hash = ?".to_owned(),
                &mut parameters,
                "artifact_id",
                identities,
            );
            group.push(Probe {
                predicate,
                parameters,
                index: "idx_policy_decisions_reuse_hash",
            });
        }
    }
    group
}

fn broad_group(
    harnesses: &[&str],
    identities: &[&str],
    hash: Option<&str>,
    publisher: Option<&str>,
) -> Group {
    let hashes: Vec<&str> = hash.into_iter().collect();
    let mut group = Group::new();
    for harness in harnesses {
        for (scope, index) in [
            ("harness", "idx_policy_decisions_diagnostic_harness_broad"),
            ("global", "idx_policy_decisions_diagnostic_global_broad"),
        ] {
            let mut parameters = vec![text(harness)];
            let predicate = exclude(
                format!("scope = '{scope}' and action = 'allow' and artifact_id is null and harness = ?"),
                &mut parameters,
                "artifact_hash",
                &hashes,
            );
            group.push(Probe {
                predicate,
                parameters,
                index,
            });
            for action in ACTIONS.iter().filter(|action| **action != "allow") {
                let mut parameters = vec![text(action), text(harness)];
                let predicate = exclude(
                    format!(
                        "scope = '{scope}' and action = ? and harness = ? and artifact_id is null"
                    ),
                    &mut parameters,
                    "artifact_hash",
                    &hashes,
                );
                group.push(Probe {
                    predicate,
                    parameters,
                    index: "idx_policy_decisions_reuse_artifact",
                });
            }
        }
        let Some(publisher) = publisher else { continue };
        let publisher_probe = |action: Option<&str>, index: &'static str| {
            let mut parameters = Vec::new();
            let mut predicate = match action {
                None => {
                    parameters.extend([text(harness), text(publisher)]);
                    "scope = 'publisher' and action = 'allow' and harness = ? and publisher = ?"
                        .to_owned()
                }
                Some(action) => {
                    parameters.extend([text(action), text(harness), text(publisher)]);
                    "scope = 'publisher' and action = ? and harness = ? and publisher = ?"
                        .to_owned()
                }
            };
            predicate = exclude(predicate, &mut parameters, "artifact_id", identities);
            predicate = exclude(predicate, &mut parameters, "artifact_hash", &hashes);
            Probe {
                predicate,
                parameters,
                index,
            }
        };
        group.push(publisher_probe(
            None,
            "idx_policy_decisions_diagnostic_publisher",
        ));
        for action in ACTIONS.iter().filter(|action| **action != "allow") {
            group.push(publisher_probe(
                Some(action),
                "idx_policy_decisions_reuse_publisher",
            ));
        }
    }
    group
}

fn policy_groups(
    harness: &str,
    artifact_id: &str,
    artifact_family: Option<&str>,
    artifact_hash: Option<&str>,
    publisher: Option<&str>,
) -> Vec<Group> {
    let harnesses = distinct_non_null(&[Some(harness), Some("*")]);
    let identities = distinct_non_null(&[Some(artifact_id), artifact_family]);
    let mut groups = artifact_groups(&harnesses, &identities);
    if let Some(hash) = artifact_hash {
        groups.push(hash_group(&harnesses, &identities, hash));
    }
    groups.push(broad_group(
        &harnesses,
        &identities,
        artifact_hash,
        publisher,
    ));
    groups
}

/// Saved-policy near matches through ordered exact probes.
pub(crate) fn policy_rows(
    connection: &Connection,
    harness: &str,
    artifact_id: &str,
    artifact_family: Option<&str>,
    artifact_hash: Option<&str>,
    publisher: Option<&str>,
) -> rusqlite::Result<Vec<Value>> {
    let groups = policy_groups(
        harness,
        artifact_id,
        artifact_family,
        artifact_hash,
        publisher,
    );
    run_groups(
        connection,
        "policy_decisions",
        POLICY_LOOKUP_COLUMNS,
        &groups,
        "updated_at",
        "decision_id",
        policy_row_to_json,
    )
}

#[cfg(test)]
#[path = "approval_reuse_diagnostic_plan_tests.rs"]
mod plan_tests;
