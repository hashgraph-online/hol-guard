//! The registry of pending publication inverses, ported from the process-local
//! `_publications` in `codex_publication_inverse`.
//!
//! The resident keeps one entry per grant beside the one-time claims, so the
//! decisions live in one place: an entry whose deadline has passed is purged,
//! a grant already registered is refused, and no more than 128 stay pending.
//! The caller keeps only the object handle for each grant the resident admits,
//! and drops the handles of the grants it reports as purged.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use serde_json::{json, Value};

use super::publication::Call;
use super::{Fault, Step};

const MAX_PENDING: usize = 128;
const INVALID: Fault = Fault::Transition("publication_inverse_publication_invalid");

static PENDING: Mutex<Option<HashMap<String, f64>>> = Mutex::new(None);

/// Purge what expired at `now`, then admit `grant` until `deadline`. Answers
/// the grants purged, in no particular order.
fn register(
    pending: &mut HashMap<String, f64>,
    grant: &str,
    deadline: f64,
    now: f64,
) -> Step<Vec<String>> {
    let expired: Vec<String> = pending
        .iter()
        .filter(|(_, until)| **until <= now)
        .map(|(id, _)| id.clone())
        .collect();
    for id in &expired {
        pending.remove(id);
    }
    if pending.contains_key(grant) {
        return Err(Fault::Transition("publication_inverse_publication_claimed"));
    }
    if pending.len() >= MAX_PENDING {
        return Err(Fault::Transition(
            "publication_inverse_publication_capacity",
        ));
    }
    pending.insert(grant.to_owned(), deadline);
    Ok(expired)
}

fn number(call: &Call<'_>, key: &str) -> Step<f64> {
    call.args
        .get(key)
        .filter(|value| value.is_number())
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
        .ok_or(INVALID)
}

/// `publication_inverse_register`: admit the pending inverse of `grant_id`
/// until `deadline`, given the caller's monotonic `now`. Answers
/// `{"purged": [grant ids]}` whose entries expired.
pub(super) fn register_op(call: &mut Call<'_>) -> Step<Value> {
    let grant = call.text("grant_id").map_err(|_| INVALID)?.to_owned();
    if grant.is_empty() {
        return Err(INVALID);
    }
    let (deadline, now) = (number(call, "deadline")?, number(call, "now")?);
    let mut guard = PENDING.lock().unwrap_or_else(PoisonError::into_inner);
    let purged = register(
        guard.get_or_insert_with(HashMap::new),
        &grant,
        deadline,
        now,
    )?;
    Ok(json!({ "purged": purged }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(result: Step<Vec<String>>, code: &str) -> bool {
        matches!(result, Err(Fault::Transition(found)) if found == code)
    }

    #[test]
    fn a_grant_registers_once_until_its_deadline() {
        let mut pending = HashMap::new();
        assert!(register(&mut pending, "g", 10.0, 1.0).unwrap().is_empty());
        assert!(refused(
            register(&mut pending, "g", 10.0, 9.9),
            "publication_inverse_publication_claimed"
        ));
        // At its deadline the entry is purged, so the grant may register again.
        let purged = register(&mut pending, "g", 20.0, 10.0).unwrap();
        assert_eq!(purged, vec!["g".to_owned()]);
    }

    #[test]
    fn at_most_128_stay_pending_and_expired_ones_make_room() {
        let mut pending = HashMap::new();
        for index in 0..MAX_PENDING {
            let grant = format!("g{index}");
            assert!(register(&mut pending, &grant, 100.0 + index as f64, 0.0).is_ok());
        }
        assert!(refused(
            register(&mut pending, "extra", 500.0, 0.0),
            "publication_inverse_publication_capacity"
        ));
        // g0 and g1 expire at 100.0 and 101.0; the purge frees their room.
        let mut purged = register(&mut pending, "extra", 500.0, 101.5).unwrap();
        purged.sort();
        assert_eq!(purged, vec!["g0".to_owned(), "g1".to_owned()]);
        assert_eq!(pending.len(), MAX_PENDING - 1);
    }

    #[test]
    fn the_op_refuses_a_second_registration_of_a_grant() {
        let ask = |grant: &str| {
            let request = json!({
                "op": "publication_inverse_register",
                "grant_id": grant,
                "deadline": 1.0e12,
                "now": 5.0,
            });
            crate::transition_files::dispatch(&request).expect("a well-formed request")
        };
        let grant = format!("op-test-{}", crate::unique_nanos::unique_nanos());
        assert_eq!(ask(&grant)["value"], json!({"purged": []}));
        let again = ask(&grant);
        assert!(again["error"]
            .to_string()
            .contains("publication_inverse_publication_claimed"));
    }
}
