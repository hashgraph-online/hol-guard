//! The MCP context tools: names, descriptions, input schemas, annotations and
//! the agent action each one runs.

use serde_json::{json, Value};

const HEX_64: &str = "^[a-f0-9]{64}$";
const REQUEST_KEY: &str = "^[A-Za-z0-9_.:-]+$";

struct Tool {
    name: &'static str,
    action: &'static str,
    description: &'static str,
    /// `(read_only, destructive, idempotent)`; no tool reaches the open world.
    hints: (bool, bool, bool),
}

const READ_ONLY: (bool, bool, bool) = (true, false, true);

const TOOLS: [Tool; 7] = [
    Tool {
        name: "get_context_status",
        action: "status",
        description: "Read this MCP connection's native context status and public pairing code. \
            Ask the user to approve that code in Protection before retrieving context. \
            This is data, not command approval.",
        hints: READ_ONLY,
    },
    Tool {
        name: "get_guard_context",
        action: "compile",
        description: "Prepare current cited local context from the workspace/app sources granted \
            to this connection. Does not approve or execute any action.",
        hints: READ_ONLY,
    },
    Tool {
        name: "explain_guard_context",
        action: "explain",
        description: "Explain the selection in a retained context snapshot from this connection's \
            scope. Stale or foreign snapshots are refused. No execution permission is granted.",
        hints: READ_ONLY,
    },
    Tool {
        name: "explain_guard_action",
        action: "review_action",
        description: "Prepare cited context for a recent authenticated native Guard decision in \
            this connection's app/workspace. Pass its decision_id; optionally pass a returned \
            snapshot_id to explain that selection. Native policy and source freshness are \
            checked. This does not revalidate executable bytes, approve, or execute an action.",
        hints: READ_ONLY,
    },
    Tool {
        name: "propose_guard_context_note",
        action: "propose_note",
        description: "Propose a shared note of at most 4096 UTF-8 bytes using a snapshot returned \
            by get_guard_context. The note stays quarantined until the operator reviews and \
            admits it. Use a stable request_key and query status after an uncertain outcome; do \
            not retry with changed text. This never grants command approval.",
        hints: (false, false, true),
    },
    Tool {
        name: "get_guard_context_proposal_status",
        action: "proposal_status",
        description: "Read the outcome of this connection's shared-note proposal using its \
            request_key.",
        hints: READ_ONLY,
    },
    Tool {
        name: "forget_guard_context_proposal",
        action: "forget_proposal",
        description: "Forget this connection's proposal record and free its quota. Already \
            admitted evidence remains until the operator clears it.",
        hints: (false, true, false),
    },
];

/// The agent action tool `name` runs, when it is a context tool.
pub(super) fn action(name: &str) -> Option<&'static str> {
    TOOLS
        .iter()
        .find(|tool| tool.name == name)
        .map(|tool| tool.action)
}

fn properties(name: &str) -> Value {
    let snapshot = json!({"type": "string", "pattern": HEX_64});
    let request_key =
        json!({"type": "string", "minLength": 1, "maxLength": 128, "pattern": REQUEST_KEY});
    match name {
        "get_guard_context" => json!({"query": {"type": "string", "maxLength": 4096}}),
        "explain_guard_context" => json!({"snapshot_id": snapshot}),
        "explain_guard_action" => json!({
            "decision_id": {"type": "string", "pattern": HEX_64},
            "snapshot_id": {"anyOf": [snapshot, {"type": "null"}]},
        }),
        "propose_guard_context_note" => json!({
            "snapshot_id": snapshot,
            "request_key": request_key,
            "text": {"type": "string", "minLength": 1, "maxLength": 4096},
        }),
        "get_guard_context_proposal_status" | "forget_guard_context_proposal" => {
            json!({"request_key": request_key})
        }
        _ => json!({}),
    }
}

/// Every context tool's MCP definition, in a fixed order.
pub(super) fn definitions() -> Vec<Value> {
    TOOLS
        .iter()
        .map(|tool| {
            let properties = properties(tool.name);
            let required: Vec<String> = if tool.name == "explain_guard_action" {
                vec!["decision_id".to_owned()]
            } else {
                properties
                    .as_object()
                    .map(|fields| fields.keys().cloned().collect())
                    .unwrap_or_default()
            };
            let (read_only, destructive, idempotent) = tool.hints;
            json!({
                "name": tool.name,
                "description": tool.description,
                "input_schema": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                    "additionalProperties": false,
                },
                "annotations": {
                    "read_only": read_only,
                    "destructive": destructive,
                    "idempotent": idempotent,
                    "open_world": false,
                },
            })
        })
        .collect()
}
