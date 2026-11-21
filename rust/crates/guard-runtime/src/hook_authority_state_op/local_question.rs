use serde::Deserialize;

use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QuestionWrite {
    session_id: String,
    now: String,
    question: String,
    tilde_home: Option<String>,
    artifact_id: String,
    pending_artifact_hash: String,
    pending_id: Option<String>,
    current_generation: Option<i64>,
    integrity_key_b64: Option<String>,
    integrity_key_id: Option<String>,
}

/// Save the answer only if it still matches the pending permission the caller
/// found. Recheck the signed prompt and build the plan inside the write.
pub(crate) fn save_locked_question(
    home: &Path,
    write: QuestionWrite,
    busy: Duration,
) -> Result<Value, &'static str> {
    if write.session_id.is_empty()
        || write.integrity_key_b64.is_none()
        || write.integrity_key_id.is_none()
        || write
            .current_generation
            .is_none_or(|generation| generation < 0)
    {
        return Err(ERROR_INVALID);
    }
    let question = crate::claude_guard_question::project_hook_question(&write.question)
        .ok_or(ERROR_INVALID)?;
    let request = HookAuthorityStateRequestV1 {
        guard_home: home.to_str().ok_or(ERROR_INVALID)?.to_owned(),
        store_path: home
            .join("guard.db")
            .to_str()
            .ok_or(ERROR_INVALID)?
            .to_owned(),
        now: write.now,
        integrity_key_b64: write.integrity_key_b64,
        integrity_key_id: write.integrity_key_id,
        ..Default::default()
    };
    transaction::write(&request, busy, |env| {
        let plan = env.claude_question_settle(
            &write.session_id,
            Some(&question),
            write.tilde_home.as_deref(),
        )?;
        if env.key.is_none()
            || plan["outcome"] != "save"
            || plan["artifact_id"] != write.artifact_id
            || plan["pending_artifact_hash"] != write.pending_artifact_hash
            || plan["pending_id"].as_str() != write.pending_id.as_deref()
        {
            return Err(ERROR_INVALID);
        }
        let Value::Object(mut plan) = plan else {
            return Err(ERROR_INVALID);
        };
        plan.insert(
            "current_generation".to_owned(),
            json!(write.current_generation),
        );
        env.claude_question_save(&write.session_id, &plan)
    })
}
