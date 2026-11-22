//! The wire shape of a decide answer.

use super::*;
use serde_json::json;

pub(super) fn encode(answer: Result<Answer, &'static str>) -> Result<Vec<u8>, String> {
    let body = match answer {
        Ok(Answer::Forward { ticket }) => {
            json!({"schema": RESULT_SCHEMA, "outcome": "forward", "ticket": ticket})
        }
        Ok(Answer::Claim { ticket }) => {
            json!({"schema": RESULT_SCHEMA, "outcome": "claim", "ticket": ticket})
        }
        Ok(Answer::Elicit { params }) => {
            json!({"schema": RESULT_SCHEMA, "outcome": "elicit", "params": params})
        }
        Ok(Answer::Evaluate { ticket }) => match ticket {
            Some(ticket) => {
                json!({"schema": RESULT_SCHEMA, "outcome": "evaluate", "ticket": ticket})
            }
            None => json!({"schema": RESULT_SCHEMA, "outcome": "evaluate"}),
        },
        Ok(Answer::Block { message, data }) => json!({
            "schema": RESULT_SCHEMA,
            "outcome": "block",
            "message": message,
            "data": data,
        }),
        Err(reason) => json!({"schema": RESULT_SCHEMA, "outcome": "defer", "reason": reason}),
    };
    serde_json::to_vec(&body).map_err(|_| "mcp_relay_decide_result_encoding_failed".to_owned())
}
