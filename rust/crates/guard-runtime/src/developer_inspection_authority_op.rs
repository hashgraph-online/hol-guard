//! One resident admission composes developer Git and direct-tool services.
use crate::codex_tool_output_op::ResidentInspectionHost;
use crate::developer_inspection_host::DeveloperInspectionHost;
use crate::direct_tool_context_op::{admit, Authority};
use crate::request_context_op::Budget;
use crate::runner_authority_op::KindResult;
use guard_command::Ctx;
use guard_contracts::{CodexToolOutputFactsV1, RequestContextDirectFactsV1};
use serde_json::Value;

const INVALID: &str = "native_developer_inspection_request_invalid";
pub(crate) fn dispatch(args: &Value) -> KindResult {
    let facts: CodexToolOutputFactsV1 =
        serde_json::from_value(args["facts"].clone()).map_err(|_| INVALID)?;
    if facts.environment.len() > 128
        || facts.groups.len() > 256
        || [&facts.home, &facts.process_cwd]
            .iter()
            .any(|p| p.len() > 65536 || p.contains('\0'))
        || facts
            .environment
            .iter()
            .any(|(k, v)| k.len() > 256 || v.len() > 65536 || k.contains('\0') || v.contains('\0'))
    {
        return Err(INVALID);
    }
    let direct: RequestContextDirectFactsV1 =
        serde_json::from_value(args["direct_facts"].clone()).map_err(|_| INVALID)?;
    let budget = Budget::bounded_milliseconds(9_000);
    admit(&direct, &budget)?;
    let host = DeveloperInspectionHost {
        base: ResidentInspectionHost { facts: &facts },
        authority: Authority {
            facts: &direct,
            budget: &budget,
        },
    };
    let ctx = Ctx::new(&host, &facts.process_cwd, &facts.home);
    let result = guard_command::developer_inspection_authority::dispatch(
        args["entry"].as_str().ok_or(INVALID)?,
        &args["arguments"],
        &ctx,
    );
    budget.check()?;
    result
}
