//! One-time claims on Codex authority repair grants, ported from the
//! process-local registry in `codex_hook_repair`.
//!
//! A grant is claimed before any file is compared, so a failed comparison can
//! never become a forward replay of the same proof. The resident keeps the
//! claims, so a grant claimed by one Guard process cannot be claimed again by
//! another. A claim retires when its grant expires; a resident that restarts
//! forgets its claims, which leaves every pending authorization invalid rather
//! than replayable.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::publication::Call;
use super::{Fault, Step};

const MAX_CLAIMS: usize = 128;
const INVALID: Fault = Fault::Transition("authority_repair_authorization_invalid");

struct Claim {
    subject: String,
    owner_operation_id: String,
    owner_pid: u64,
    deadline: f64,
    retire: Instant,
    publication: Option<f64>,
}

static CLAIMS: Mutex<Option<HashMap<String, Claim>>> = Mutex::new(None);

fn number(call: &Call<'_>, key: &str) -> Step<f64> {
    call.args
        .get(key)
        .filter(|value| !value.is_boolean())
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
        .ok_or(INVALID)
}

fn grant(call: &Call<'_>) -> Step<String> {
    let grant = call.text("grant_id").map_err(|_| INVALID)?;
    if grant.is_empty() {
        return Err(INVALID);
    }
    Ok(grant.to_owned())
}

/// `publication_repair_claim`: claim a grant once, before any comparison.
pub(super) fn claim(call: &mut Call<'_>) -> Step<Value> {
    let grant = grant(call)?;
    let subject = call.text("subject").map_err(|_| INVALID)?.to_owned();
    let owner_operation_id = call
        .text("owner_operation_id")
        .map_err(|_| INVALID)?
        .to_owned();
    let owner_pid = call
        .args
        .get("owner_pid")
        .and_then(Value::as_u64)
        .filter(|pid| *pid > 0)
        .ok_or(INVALID)?;
    let deadline = number(call, "deadline")?;
    let retire_ms = number(call, "retire_ms")?.max(0.0);
    let now = Instant::now();
    let retire = now + Duration::from_secs_f64((retire_ms / 1000.0).min(86_400.0));
    let mut guard = CLAIMS.lock().unwrap_or_else(PoisonError::into_inner);
    let claims = guard.get_or_insert_with(HashMap::new);
    claims.retain(|_, claim| claim.retire > now);
    if claims.contains_key(&grant) {
        return Err(Fault::Transition("authority_repair_authorization_claimed"));
    }
    if claims.len() >= MAX_CLAIMS {
        return Err(Fault::Transition("authority_repair_capacity"));
    }
    claims.insert(
        grant,
        Claim {
            subject,
            owner_operation_id,
            owner_pid,
            deadline,
            retire,
            publication: None,
        },
    );
    Ok(Value::Null)
}

/// `publication_repair_claim_check`: the grant's claim must be the one made
/// for this subject, owner and deadline and, once the caller names it, for
/// the one publication the claim allows. Any other claim, or none, leaves
/// the authorization invalid.
pub(super) fn check(call: &mut Call<'_>) -> Step<Value> {
    let grant = grant(call)?;
    let subject = call.text("subject").map_err(|_| INVALID)?;
    let owner_operation_id = call.text("owner_operation_id").map_err(|_| INVALID)?;
    let owner_pid = call
        .args
        .get("owner_pid")
        .and_then(Value::as_u64)
        .ok_or(INVALID)?;
    let deadline = number(call, "deadline")?;
    let publication = match call.args.get("publication") {
        None | Some(Value::Null) => None,
        Some(_) => Some(number(call, "publication")?),
    };
    let guard = CLAIMS.lock().unwrap_or_else(PoisonError::into_inner);
    let claim = guard
        .as_ref()
        .and_then(|claims| claims.get(&grant))
        .ok_or(INVALID)?;
    if claim.subject != subject
        || claim.owner_operation_id != owner_operation_id
        || claim.owner_pid != owner_pid
        || claim.deadline != deadline
        || publication.is_some_and(|publication| claim.publication != Some(publication))
    {
        return Err(INVALID);
    }
    Ok(Value::Null)
}

/// `publication_repair_publish`: record the one publication a claim allows.
pub(super) fn publish(call: &mut Call<'_>) -> Step<Value> {
    let grant = grant(call)?;
    let publication = number(call, "publication")?;
    let mut guard = CLAIMS.lock().unwrap_or_else(PoisonError::into_inner);
    let claim = guard
        .as_mut()
        .and_then(|claims| claims.get_mut(&grant))
        .ok_or(INVALID)?;
    if claim.publication.is_some() {
        return Err(Fault::Transition("authority_repair_publication_claimed"));
    }
    claim.publication = Some(publication);
    Ok(Value::Null)
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use crate::transition_files::dispatch;

    fn ask(request: serde_json::Value) -> Result<serde_json::Value, String> {
        let answer = dispatch(&request).map_err(|error| format!("{error:?}"))?;
        match answer.get("error") {
            Some(error) => Err(error.to_string()),
            None => Ok(answer["value"].clone()),
        }
    }

    #[test]
    fn a_grant_is_claimed_and_published_once() {
        let grant = format!("grant-{}", crate::unique_nanos::unique_nanos());
        let claim = json!({
            "op": "publication_repair_claim",
            "grant_id": grant,
            "subject": "subject",
            "owner_operation_id": "owner",
            "owner_pid": 7,
            "deadline": 12.5,
            "retire_ms": 60_000,
        });
        assert_eq!(ask(claim.clone()).unwrap(), json!(null));
        assert!(ask(claim)
            .unwrap_err()
            .contains("authority_repair_authorization_claimed"));
        let check = |publication: Value| {
            ask(json!({
                "op": "publication_repair_claim_check",
                "grant_id": grant,
                "subject": "subject",
                "owner_operation_id": "owner",
                "owner_pid": 7,
                "deadline": 12.5,
                "publication": publication,
            }))
        };
        assert_eq!(check(json!(null)).unwrap(), json!(null));
        assert!(check(json!(3.5)).is_err(), "nothing was published yet");
        let publish =
            json!({"op": "publication_repair_publish", "grant_id": grant, "publication": 3.5});
        assert_eq!(ask(publish.clone()).unwrap(), json!(null));
        assert!(ask(publish)
            .unwrap_err()
            .contains("authority_repair_publication_claimed"));
        assert_eq!(check(json!(3.5)).unwrap(), json!(null));
        assert!(check(json!(4.0))
            .unwrap_err()
            .contains("authority_repair_authorization_invalid"));
    }

    #[test]
    fn a_claim_for_another_subject_owner_or_deadline_is_invalid() {
        let grant = format!("grant-{}", crate::unique_nanos::unique_nanos());
        let claim = json!({
            "op": "publication_repair_claim",
            "grant_id": grant,
            "subject": "subject",
            "owner_operation_id": "owner",
            "owner_pid": 7,
            "deadline": 12.5,
            "retire_ms": 60_000,
        });
        ask(claim).unwrap();
        let check = |field: &str, value: Value| {
            let mut request = json!({
                "op": "publication_repair_claim_check",
                "grant_id": grant,
                "subject": "subject",
                "owner_operation_id": "owner",
                "owner_pid": 7,
                "deadline": 12.5,
            });
            request[field] = value;
            ask(request)
        };
        assert!(check("subject", json!("subject")).is_ok());
        for (field, value) in [
            ("subject", json!("other")),
            ("owner_operation_id", json!("other")),
            ("owner_pid", json!(8)),
            ("deadline", json!(13.0)),
        ] {
            let error = check(field, value).unwrap_err();
            assert!(
                error.contains("authority_repair_authorization_invalid"),
                "{field}: {error}"
            );
        }
    }

    #[test]
    fn an_unclaimed_grant_cannot_publish() {
        let unknown = json!({"op": "publication_repair_publish", "grant_id": "never-claimed", "publication": 1.0});
        assert!(ask(unknown)
            .unwrap_err()
            .contains("authority_repair_authorization_invalid"));
    }
}
