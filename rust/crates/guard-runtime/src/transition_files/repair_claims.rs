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

use serde_json::{json, Value};

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

/// `publication_repair_claimed`: the grant's claim as it was made, or null.
pub(super) fn claimed(call: &mut Call<'_>) -> Step<Value> {
    let grant = grant(call)?;
    let guard = CLAIMS.lock().unwrap_or_else(PoisonError::into_inner);
    Ok(guard
        .as_ref()
        .and_then(|claims| claims.get(&grant))
        .map_or(Value::Null, |claim| {
            json!({
                "subject": claim.subject,
                "owner_operation_id": claim.owner_operation_id,
                "owner_pid": claim.owner_pid,
                "deadline": claim.deadline,
                "publication": claim.publication,
            })
        }))
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
    use serde_json::json;

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
        let claimed =
            || ask(json!({"op": "publication_repair_claimed", "grant_id": grant})).unwrap();
        assert_eq!(claimed()["owner_pid"], json!(7));
        assert_eq!(claimed()["publication"], json!(null));
        let publish =
            json!({"op": "publication_repair_publish", "grant_id": grant, "publication": 3.5});
        assert_eq!(ask(publish.clone()).unwrap(), json!(null));
        assert!(ask(publish)
            .unwrap_err()
            .contains("authority_repair_publication_claimed"));
        assert_eq!(claimed()["publication"], json!(3.5));
    }

    #[test]
    fn an_unclaimed_grant_cannot_publish() {
        let unknown = json!({"op": "publication_repair_publish", "grant_id": "never-claimed", "publication": 1.0});
        assert!(ask(unknown)
            .unwrap_err()
            .contains("authority_repair_authorization_invalid"));
    }
}
