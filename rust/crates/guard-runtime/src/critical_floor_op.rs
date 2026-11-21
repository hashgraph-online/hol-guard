//! The encoded-payload consumer needs the existing monotonic native floors.

use std::path::Path;

use guard_contracts::{RequestContextCriticalFloorV1, MAX_REQUEST_CONTEXT_PATH_BYTES};
use serde_json::{json, Value};

use crate::request_context_op::Budget;

#[cfg(test)]
#[path = "critical_floor_op_tests.rs"]
mod tests;

pub(crate) fn evaluate(
    body: &RequestContextCriticalFloorV1,
    budget: &Budget,
) -> Result<Value, &'static str> {
    budget.check()?;
    if body.script.trim().is_empty()
        || body.script.len() > guard_command::MAX_COMMAND_BYTES
        || body.script.contains('\0')
    {
        return Err("native_request_context_critical_floor_script_invalid");
    }
    for path in [&body.cwd, &body.home_dir] {
        if path.is_empty()
            || path.len() > MAX_REQUEST_CONTEXT_PATH_BYTES
            || path.contains('\0')
            || !Path::new(path).is_absolute()
        {
            return Err("native_request_context_critical_floor_path_invalid");
        }
    }
    let action = guard_command::critical_floor_action(
        &body.script,
        Path::new(&body.cwd),
        Path::new(&body.home_dir),
    )
    .map_err(|_| "native_request_context_critical_floor_invalid")?;
    budget.check()?;
    Ok(json!({"kind": "critical_floor", "action": action.as_str()}))
}
