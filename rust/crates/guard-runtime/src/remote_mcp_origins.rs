//! `remote_mcp_origins`: the origin Guard records for each remote MCP server
//! URL a harness config declares, from `guard_command::remote_mcp_origin`.
//!
//! One request carries every URL a discovery pass found, so the answer is a
//! list of the same length: each entry the origin, or `null` when the URL
//! names no remote `http`/`https` server Guard can record.

use serde_json::{json, Value};

use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const MAX_URLS: usize = 16_384;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let urls = args_object(args)?
        .get("urls")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    if urls.len() > MAX_URLS {
        return Err(ERR_INVALID);
    }
    let origins = urls
        .iter()
        .map(|url| {
            url.as_str()
                .map(guard_command::remote_mcp_origin)
                .ok_or(ERR_INVALID)
        })
        .collect::<Result<Vec<Option<String>>, &'static str>>()?;
    Ok(json!({ "origins": origins }))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn each_url_answers_in_order() {
        let answer = dispatch(&json!({
            "urls": [
                "https://user:pw@MCP.Example.Test/v1/a1b2c3d4e5?key=secret",
                "file:///tmp/sock",
                "http://mcp.example.test:8080",
            ]
        }));
        assert_eq!(
            answer,
            Ok(json!({
                "origins": [
                    "https://mcp.example.test/v1/[masked]",
                    null,
                    "http://mcp.example.test:8080",
                ]
            }))
        );
        assert_eq!(
            dispatch(&json!({ "urls": [] })),
            Ok(json!({ "origins": [] }))
        );
    }

    #[test]
    fn malformed_requests_are_invalid() {
        for args in [
            json!([]),
            json!({}),
            json!({ "urls": "https://mcp.example.test" }),
            json!({ "urls": [1] }),
            json!({ "urls": [null] }),
            json!({ "urls": vec![""; MAX_URLS + 1] }),
        ] {
            assert_eq!(dispatch(&args), Err(ERR_INVALID), "{args}");
        }
    }
}
