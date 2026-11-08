//! The receipt's diff summary and runtime event payload, as the Python store
//! writes them.

use guard_contracts::write_json_string;

use super::Plain;

/// `_auto_diff_summary`.
pub(super) fn diff_summary(changed: &[&str]) -> String {
    let sample = changed
        .iter()
        .take(3)
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    let suffix = if changed.len() > 3 { " ..." } else { "" };
    format!("{} change(s): {sample}{suffix}", changed.len())
}

/// The runtime event's payload as `json.dumps` writes it: insertion order,
/// `", "` and `": "` separators, ASCII only.
pub(super) fn event_payload_json(
    plain: &Plain<'_>,
    artifact_id: &str,
    risk_categories: &[&str],
    signals: &[&str],
) -> Option<String> {
    let mut out = vec![b'{'];
    for (name, value) in [
        ("artifact_id", artifact_id),
        ("artifact_hash", plain.artifact_hash),
        ("decision_source", plain.source),
        ("policy_action", plain.policy_action),
    ] {
        key(&mut out, name);
        write_json_string(value, &mut out);
    }
    if !plain.forward {
        key(&mut out, "execution_outcome");
        write_json_string("not-executed", &mut out);
    }
    key(&mut out, "risk_categories");
    list(&mut out, risk_categories);
    key(&mut out, "signals");
    list(&mut out, signals);
    out.push(b'}');
    String::from_utf8(out).ok()
}

fn key(out: &mut Vec<u8>, name: &str) {
    if out.len() > 1 {
        out.extend_from_slice(b", ");
    }
    write_json_string(name, out);
    out.extend_from_slice(b": ");
}

fn list(out: &mut Vec<u8>, items: &[&str]) {
    out.push(b'[');
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.extend_from_slice(b", ");
        }
        write_json_string(item, out);
    }
    out.push(b']');
}
