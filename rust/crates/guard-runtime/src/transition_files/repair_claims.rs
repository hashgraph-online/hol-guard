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
    // The grant retires at `retirement`; `now` is the caller's clock as it asks.
    let retire_ms = (number(call, "retirement")? - number(call, "now")?).max(0.0) * 1000.0;
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
    // The owner holding the lock now must be the one that was approved; this
    // is its own reason, and it answers before the home or any claim is read.
    let current_id = call.args.get("current_owner_operation_id");
    let current_pid = call.args.get("current_owner_pid");
    if current_id.is_some() || current_pid.is_some() {
        let approved_id = call.args.get("owner_operation_id");
        let approved_pid = call.args.get("owner_pid");
        if current_id != approved_id || current_pid != approved_pid {
            return Err(Fault::Transition("authority_repair_owner_mismatch"));
        }
    }
    // Then the authority home the gate names now must be the approved one.
    let current_home = call.args.get("current_authority_home");
    let approved_home = call.args.get("authority_home");
    if (current_home.is_some() || approved_home.is_some()) && current_home != approved_home {
        return Err(Fault::Transition("approval_authority_mismatch"));
    }
    let grant = grant(call)?;
    let subject = call.text("subject").map_err(|_| INVALID)?;
    // The subject the plan derives now must still be the one approved.
    if call
        .args
        .get("current_subject")
        .is_some_and(|current| current.as_str() != Some(subject))
    {
        return Err(INVALID);
    }
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
            "retirement": 60.0,
            "now": 0.0,
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
            "retirement": 60.0,
            "now": 0.0,
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
            ("current_subject", json!("other")),
        ] {
            let error = check(field, value).unwrap_err();
            assert!(
                error.contains("authority_repair_authorization_invalid"),
                "{field}: {error}"
            );
        }
    }

    #[test]
    fn a_different_lock_owner_is_its_own_mismatch() {
        let grant = format!("grant-{}", crate::unique_nanos::unique_nanos());
        let claim = json!({
            "op": "publication_repair_claim",
            "grant_id": grant,
            "subject": "subject",
            "owner_operation_id": "owner",
            "owner_pid": 7,
            "deadline": 12.5,
            "retirement": 60.0,
            "now": 0.0,
        });
        ask(claim).unwrap();
        let check = |id: Value, pid: Value| {
            ask(json!({
                "op": "publication_repair_claim_check",
                "grant_id": grant,
                "subject": "subject",
                "owner_operation_id": "owner",
                "owner_pid": 7,
                "deadline": 12.5,
                "current_owner_operation_id": id,
                "current_owner_pid": pid,
            }))
        };
        assert!(check(json!("owner"), json!(7)).is_ok());
        for (id, pid) in [(json!("other"), json!(7)), (json!("owner"), json!(8))] {
            let error = check(id, pid).unwrap_err();
            assert!(error.contains("authority_repair_owner_mismatch"), "{error}");
        }
    }

    #[test]
    fn the_owner_is_judged_before_the_authority_home() {
        let grant = format!("grant-{}", crate::unique_nanos::unique_nanos());
        ask(json!({
            "op": "publication_repair_claim",
            "grant_id": grant,
            "subject": "subject",
            "owner_operation_id": "owner",
            "owner_pid": 7,
            "deadline": 12.5,
            "retirement": 60.0,
            "now": 0.0,
        }))
        .unwrap();
        let check = |owner: &str, home: &str| {
            ask(json!({
                "op": "publication_repair_claim_check",
                "grant_id": grant,
                "subject": "subject",
                "owner_operation_id": "owner",
                "owner_pid": 7,
                "deadline": 12.5,
                "current_owner_operation_id": owner,
                "current_owner_pid": 7,
                "authority_home": "/approved",
                "current_authority_home": home,
            }))
        };
        assert!(check("owner", "/approved").is_ok());
        let home = check("owner", "/elsewhere").unwrap_err();
        assert!(home.contains("approval_authority_mismatch"), "{home}");
        let both = check("other", "/elsewhere").unwrap_err();
        assert!(both.contains("authority_repair_owner_mismatch"), "{both}");
    }

    #[test]
    fn an_unclaimed_grant_cannot_publish() {
        let unknown = json!({"op": "publication_repair_publish", "grant_id": "never-claimed", "publication": 1.0});
        assert!(ask(unknown)
            .unwrap_err()
            .contains("authority_repair_authorization_invalid"));
    }
}
