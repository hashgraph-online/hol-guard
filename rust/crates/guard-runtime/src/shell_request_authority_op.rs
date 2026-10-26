//! Bound resident adapter for the shared command classifier kernels.

use guard_command::Ctx;
use guard_contracts::CodexToolOutputFactsV1;
use serde_json::Value;

use crate::codex_tool_output_op::ResidentInspectionHost;
use crate::runner_authority_op::KindResult;
use crate::shell_request_inspection_host::ShellInspectionHost;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let entry = args["entry"]
        .as_str()
        .ok_or("native_shell_request_entry_invalid")?;
    let facts: CodexToolOutputFactsV1 = if args["facts"].is_null() {
        if matches!(
            entry,
            "classify_github_shell_capabilities"
                | "_github_pipeline_companion_is_read_only"
                | "_gh_pr_create_uses_safe_static_body_file"
                | "_gh_pr_edit_uses_safe_static_body_file"
        ) {
            return Err("native_shell_request_host_invalid");
        }
        CodexToolOutputFactsV1 {
            process_cwd: "/".to_owned(),
            home: "/".to_owned(),
            account_home: None,
            groups: Vec::new(),
            environment: Default::default(),
            git_executable: None,
        }
    } else {
        serde_json::from_value(args["facts"].clone())
            .map_err(|_| "native_shell_request_host_invalid")?
    };
    if facts.environment.len() > 128
        || facts.groups.len() > 256
        || [&facts.process_cwd, &facts.home]
            .iter()
            .any(|path| path.len() > 65536 || path.contains('\0'))
        || facts.environment.iter().any(|(key, value)| {
            key.len() > 256 || value.len() > 65536 || key.contains('\0') || value.contains('\0')
        })
    {
        return Err("native_shell_request_host_invalid");
    }
    let host = ShellInspectionHost {
        base: ResidentInspectionHost { facts: &facts },
    };
    let context = Ctx::new(&host, &facts.process_cwd, &facts.home);
    guard_command::shell_request_authority::dispatch(entry, &args["arguments"], &context)
}
