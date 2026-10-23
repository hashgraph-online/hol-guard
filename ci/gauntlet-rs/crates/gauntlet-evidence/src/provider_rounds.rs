//! Pure classification of already-recorded provider transport rounds. This
//! never retries a request or proves that a provider actually served it.

use serde_json::Value;

fn digest(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|ch| ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch))
    })
}

fn exact_int(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(number)) => number.as_i64(),
        _ => None,
    }
}

/// Match Python `transport.reconcile_rounds` for ordinary typed provider
/// records. Boolean or non-integer delivered-byte counts are refused even
/// where Python's loose `False == 0` comparison would allow them.
pub fn reconcile_provider_rounds(rounds: &[Value]) -> (bool, usize) {
    if rounds.is_empty() || rounds.len() > 50_000 {
        return (false, 0);
    }
    let mut recovered = 0;
    for (index, row) in rounds.iter().enumerate() {
        if !row.is_object() {
            return (false, recovered);
        }
        if row.get("status").and_then(Value::as_str) == Some("completed") {
            if !digest(row.get("request_sha256"))
                || !digest(row.get("response_sha256"))
                || exact_int(row.get("response_bytes")).is_none_or(|value| value <= 0)
                || row
                    .get("response_models")
                    .and_then(Value::as_array)
                    .is_none_or(|models| models.is_empty())
            {
                return (false, recovered);
            }
            continue;
        }
        let Some(status) = exact_int(row.get("http_status")) else {
            return (false, recovered);
        };
        if row.get("status").and_then(Value::as_str) != Some("provider-error")
            || row.get("error_type").and_then(Value::as_str) != Some("HTTPError")
            || exact_int(row.get("delivered_bytes")) != Some(0)
            || !(status == 429 || (500..=599).contains(&status))
        {
            return (false, recovered);
        }
        let Some(request) = row.get("request_sha256").and_then(Value::as_str) else {
            return (false, recovered);
        };
        let mut completed = false;
        for retry in &rounds[index + 1..] {
            if retry.get("request_sha256") != Some(&Value::String(request.to_owned())) {
                break;
            }
            if retry.get("status").and_then(Value::as_str) == Some("completed") {
                completed = true;
                break;
            }
        }
        if !completed {
            return (false, recovered);
        }
        recovered += 1;
    }
    (true, recovered)
}
