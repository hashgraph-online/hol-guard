use super::policy_enforcement_helpers::FloorCause;

/// The package script setting holds lifecycle scripts, not the install. These
/// are the forms `no_script_install_command` proves, which the setting skips.
pub(super) const NO_SCRIPT_INSTALL_ALTERNATIVE: &str =
    "This setting holds package lifecycle scripts. \
An install of the committed lockfile with scripts turned off is not held by it: run \
`bun install --frozen-lockfile --ignore-scripts`, `npm ci --ignore-scripts` or \
`pnpm install --frozen-lockfile --ignore-scripts --ignore-pnpmfile` on its own, choosing the \
manager whose lockfile the project commits (`bun.lock`, `package-lock.json` or `pnpm-lock.yaml`), \
then run tests or builds as separate commands.";

/// The reason code and text for a result the installed policy raised, naming
/// the policy setting that raised it when it is known.
pub(super) fn policy_override_reason(
    action: &str,
    cause: Option<FloorCause>,
    prompt: bool,
) -> (&'static str, String) {
    let (code, outcome) = match action {
        "block" => ("native_policy_block", "blocked this hook action"),
        "sandbox-required" => (
            "native_policy_sandbox_required",
            "requires sandbox enforcement",
        ),
        "require-reapproval" => (
            "native_policy_reapproval_required",
            "requires fresh approval",
        ),
        "review" => ("native_policy_review_required", "requires review"),
        _ => ("native_policy_warning", "raised this action"),
    };
    if prompt && action != "warn" {
        return (code, prompt_stop_reason(cause));
    }
    let Some(cause) = cause else {
        return (
            code,
            format!("HOL Guard {outcome} under the installed native policy."),
        );
    };
    let setting = match cause {
        FloorCause::Default => "default action".to_owned(),
        FloorCause::Harness => "setting for this harness".to_owned(),
        FloorCause::Subprocess => "subprocess setting".to_owned(),
        FloorCause::Network => "new network domain setting".to_owned(),
        FloorCause::Unknown => "rule for unrecognized tool operations".to_owned(),
        FloorCause::ChangedHash => "changed artifact setting".to_owned(),
        FloorCause::UnknownPublisher => "unknown publisher setting".to_owned(),
        FloorCause::Artifact => "rule for this artifact".to_owned(),
        FloorCause::Publisher => "rule for this publisher".to_owned(),
        FloorCause::Risk(risk) => format!("{} setting", risk_label(risk)),
    };
    (
        code,
        format!("HOL Guard {outcome} under the installed policy's {setting}."),
    )
}

fn risk_label(risk: &str) -> &'static str {
    match risk {
        "local_secret_read" => "secret read",
        "credential_exfiltration" => "credential export",
        "data_flow_exfiltration" => "data export",
        "destructive_shell" => "destructive command",
        "encoded_execution" => "encoded execution",
        "network_egress" => "network access",
        "prompt_injection" => "prompt injection",
        "mcp_dangerous_tool" => "unreviewed MCP tool",
        "malicious_skill" => "malicious skill",
        "package_script" => "package script",
        "persistence" => "persistence",
        "guard_bypass" => "Guard bypass",
        "cloud_advisory" => "cloud advisory",
        "encoded_exfiltration" => "encoded export",
        "package_unknown" => "unrecognized package",
        "package_lockfile_drift" => "unpinned dependency",
        "package_direct_source" => "direct package source",
        "package_custom_registry" => "custom package registry",
        "package_install" => "package install",
        "low_trust_artifact" => "low trust score",
        "execution" => "command execution",
        "supply_chain" => "supply chain",
        "policy_bypass" => "policy bypass",
        _ => "risk",
    }
}

/// Prompts never create an approval request, so the text says the prompt was
/// not sent and what to change instead of pointing at an approval inbox.
fn prompt_stop_reason(cause: Option<FloorCause>) -> String {
    let (kind, setting) = match cause {
        Some(FloorCause::Risk(risk)) => (
            match risk {
                "local_secret_read" => "asks to read credentials or other sensitive local data",
                "credential_exfiltration" | "data_flow_exfiltration" | "encoded_exfiltration" => {
                    "asks to send data to an external place"
                }
                "destructive_shell" => "asks to delete or overwrite local files",
                "prompt_injection" => "asks to override trusted instructions",
                "execution" | "encoded_execution" => "asks to run commands or a subprocess",
                "guard_bypass" | "policy_bypass" => "asks to disable Guard protection",
                _ => "matches a guarded request type",
            },
            // Only risk classes the settings command accepts get a setting hint.
            match risk {
                "execution" | "policy_bypass" => None,
                _ => Some(risk),
            },
        ),
        _ => ("matches a guarded request type", None),
    };
    let mut text = format!(
        "HOL Guard did not send this prompt because it {kind}. Nothing is waiting for approval; rephrase that part of the request"
    );
    match setting {
        Some(risk) => text.push_str(&format!(
            ", or change the prompt protection with `hol-guard settings set risk {risk} <action>`."
        )),
        None => text.push('.'),
    }
    text
}
