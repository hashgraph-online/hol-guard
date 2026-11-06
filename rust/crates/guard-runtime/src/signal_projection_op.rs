//! Canonical native persistence projections, never launch permits.
use crate::{
    runner_authority_op::{KindResult, ERR_INVALID},
    signal_projection_approval::approval,
    signal_projection_receipt::{receipt, surfaces},
};
use serde_json::{json, Value};

pub(crate) fn dispatch(kind: &str, args: &Value) -> KindResult {
    if !args.is_object() {
        return Err(ERR_INVALID);
    }
    // A strict flag that is not a boolean is refused, never read as permissive.
    let reject = match &args["reject"] {
        Value::Null => false,
        Value::Bool(reject) => *reject,
        _ => return Err(ERR_INVALID),
    };
    let result = match kind {
        "projection_artifact_surfaces" => {
            let artifact = &args["artifact"];
            guard_command::decisions::authoritative_decision_from_artifact(artifact, false)
                .map_err(|error| error.to_string())
                .and_then(|_| {
                    surfaces(
                        &artifact["policy_action"],
                        &artifact["decision_v2_json"],
                        &artifact["action_envelope_json"],
                        true,
                    )
                })
        }
        "projection_approval" => approval(&args["action"], &args["decision"], reject),
        "projection_receipt" => receipt(&args["action"], &args["envelope"], reject),
        "projection_surfaces" => surfaces(
            &args["action"],
            &args["decision"],
            &args["envelope"],
            reject,
        ),
        "projection_surfaces_batch" => {
            let rows = args["rows"].as_array().ok_or(ERR_INVALID)?;
            if rows.len() > 512 {
                return Err("native_runner_authority_projection_batch_too_large");
            }
            rows.iter()
                .map(|row| surfaces(&row["action"], &row["decision"], &row["envelope"], reject))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array)
        }
        _ => return Err(ERR_INVALID),
    };
    match result {
        Ok(value) => Ok(json!({"status":"ok","value":value})),
        Err(message) if message.len() <= 4096 => {
            Ok(json!({"status":"error","error_type":"ValueError","message":message}))
        }
        Err(_) => Err("native_runner_authority_signal_projection_error_too_large"),
    }
}
