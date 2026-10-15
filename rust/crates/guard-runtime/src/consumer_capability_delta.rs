//! Semantic capability deltas between two normalized capability snapshots.
//!
//! A first-seen artifact is scored against an empty baseline; a known one
//! reports only what it gained or changed. Severities are the evidence the
//! current-action composition scores, so they must not drift.

use std::collections::BTreeSet;

use serde_json::{json, Value};

fn strings(snapshot: &Value, key: &str) -> Vec<String> {
    snapshot
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn flag(snapshot: &Value, key: &str) -> bool {
    snapshot.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn text(snapshot: &Value, key: &str) -> Option<String> {
    snapshot.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn joined(items: &[String]) -> Option<String> {
    (!items.is_empty()).then(|| items.join(", "))
}

fn first_three(items: &[String]) -> String {
    items.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
}

fn delta(
    kind: &str,
    before: Option<String>,
    after: Option<String>,
    severity: i64,
    why: String,
) -> Value {
    json!({
        "delta_type": kind,
        "before": before,
        "after": after,
        "severity": severity,
        "explanation": why,
    })
}

fn gained(before: &[String], after: &[String]) -> Vec<String> {
    let known: BTreeSet<&String> = before.iter().collect();
    let mut added: Vec<String> = after
        .iter()
        .filter(|item| !known.contains(item))
        .cloned()
        .collect();
    added.sort();
    added.dedup();
    added
}

/// Deltas of `after` against `before` (`null` for a first-seen artifact).
pub(crate) fn compute(before: &Value, after: &Value) -> Vec<Value> {
    if before.is_null() {
        return first_seen(after);
    }
    let mut deltas = Vec::new();
    for host in gained(
        &strings(before, "network_hosts"),
        &strings(after, "network_hosts"),
    ) {
        deltas.push(delta(
            "new_network_host",
            None,
            Some(host.clone()),
            8,
            format!("Artifact introduced a new remote host: {host}."),
        ));
    }
    let (before_publisher, after_publisher) = (text(before, "publisher"), text(after, "publisher"));
    if before_publisher != after_publisher && after_publisher.is_some() {
        deltas.push(delta(
            "publisher_changed",
            before_publisher,
            after_publisher,
            7,
            "Artifact publisher changed from the previous snapshot.".to_owned(),
        ));
    }
    let (before_transport, after_transport) = (text(before, "transport"), text(after, "transport"));
    if before_transport != after_transport {
        deltas.push(delta(
            "transport_changed",
            before_transport,
            after_transport,
            6,
            "Artifact transport changed and may alter execution boundaries.".to_owned(),
        ));
    }
    let (before_secrets, after_secrets) = (
        strings(before, "secret_classes"),
        strings(after, "secret_classes"),
    );
    let new_secrets = gained(&before_secrets, &after_secrets);
    if !new_secrets.is_empty() {
        deltas.push(delta(
            "secret_scope_expanded",
            joined(&before_secrets),
            Some(after_secrets.join(", ")),
            9,
            format!(
                "Artifact now references additional secret-bearing classes: {}.",
                new_secrets.join(", ")
            ),
        ));
    }
    let (before_paths, after_paths) = (
        strings(before, "filesystem_paths"),
        strings(after, "filesystem_paths"),
    );
    if !gained(&before_paths, &after_paths).is_empty() {
        deltas.push(delta(
            "filesystem_scope_expanded",
            (!before_paths.is_empty()).then(|| first_three(&before_paths)),
            Some(first_three(&after_paths)),
            5,
            "Artifact expanded filesystem path scope.".to_owned(),
        ));
    }
    if !flag(before, "subprocess_invocation") && flag(after, "subprocess_invocation") {
        deltas.push(delta(
            "subprocess_added",
            Some("false".to_owned()),
            Some("true".to_owned()),
            8,
            "Artifact gained subprocess or shell execution behavior.".to_owned(),
        ));
    }
    let (before_interpreters, after_interpreters) = (
        strings(before, "interpreters"),
        strings(after, "interpreters"),
    );
    if !gained(&before_interpreters, &after_interpreters).is_empty() {
        deltas.push(delta(
            "interpreter_changed",
            joined(&before_interpreters),
            Some(after_interpreters.join(", ")),
            6,
            "Artifact now uses additional interpreters.".to_owned(),
        ));
    }
    let (before_wrappers, after_wrappers) = (
        strings(before, "shell_wrappers"),
        strings(after, "shell_wrappers"),
    );
    let wrapper_set = |items: &[String]| items.iter().cloned().collect::<BTreeSet<String>>();
    if wrapper_set(&before_wrappers) != wrapper_set(&after_wrappers) {
        deltas.push(delta(
            "approval_surface_changed",
            joined(&before_wrappers),
            joined(&after_wrappers),
            6,
            "Artifact shell-wrapper behavior changed and requires review.".to_owned(),
        ));
    }
    deltas
}

fn first_seen(after: &Value) -> Vec<Value> {
    let mut deltas = Vec::new();
    let hosts = strings(after, "network_hosts");
    if !hosts.is_empty() {
        deltas.push(delta(
            "new_network_host",
            None,
            Some(first_three(&hosts)),
            7,
            "First-seen artifact declares remote network hosts.".to_owned(),
        ));
    }
    let secrets = strings(after, "secret_classes");
    if !secrets.is_empty() {
        deltas.push(delta(
            "secret_scope_expanded",
            None,
            Some(secrets.join(", ")),
            8,
            "First-seen artifact references sensitive local secret classes.".to_owned(),
        ));
    }
    if flag(after, "subprocess_invocation") {
        deltas.push(delta(
            "subprocess_added",
            None,
            Some("true".to_owned()),
            7,
            "First-seen artifact includes subprocess or shell execution behavior.".to_owned(),
        ));
    }
    let transport = text(after, "transport");
    if transport.as_deref() != Some("local") {
        deltas.push(delta(
            "transport_changed",
            Some("local".to_owned()),
            transport,
            5,
            "First-seen artifact uses remote or hybrid transport.".to_owned(),
        ));
    }
    if let Some(publisher) = text(after, "publisher").filter(|publisher| !publisher.is_empty()) {
        deltas.push(delta(
            "publisher_changed",
            None,
            Some(publisher),
            4,
            "First-seen artifact declares a publisher identity.".to_owned(),
        ));
    }
    deltas
}
