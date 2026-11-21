//! The `describe` answer: every adapter's static facts, as one document.

use serde_json::{json, Value};

use super::{
    Hook, Install, Spec, COPILOT_HOOK_OPS, ENV_NAMES, ENV_PREFIXES, PASEO_DELEGATES, SPECS,
};

impl Spec {
    fn describe(&self) -> Value {
        json!({
            "harness": self.harness,
            "aliases": self.aliases,
            "executable": self.executable,
            "launcher_name": self.launcher_name,
            "display_name": self.display_name,
            "approval": self.approval_flow(),
            "workspace_aibom": self.workspace_aibom,
            "hook": match self.hook {
                Hook::None => Value::Null,
                Hook::Shell => json!("shell"),
                Hook::Argv => json!("argv"),
            },
            "install": match self.install {
                Install::Shim => "shim",
                Install::Plan => "plan",
                Install::Delegated => "delegated",
            },
            "dynamic": self.dynamic,
            // Hermes signs its manifest, which may create the state key, so it
            // has no rebind preparation; Copilot plans one from what it detected.
            "prepare": match self.harness {
                "hermes" | "cline" => "unavailable",
                "copilot" => "detected",
                // Cursor plans the editor and CLI surfaces in one op.
                "cursor" => "surfaces",
                _ => "plan",
            },
            // Copilot and Cursor name their own launch argv and preview only
            // that one; Cursor picks `cursor-agent` or `cursor agent`.
            "launch_op": if matches!(self.harness, "copilot" | "cursor") {
                "launch_command"
            } else {
                ""
            },
            // Copilot's hook ops refuse to touch a file the runtime did not plan.
            "hook_ownership": if self.harness == "copilot" {
                json!({"message": super::super::copilot::UNANSWERED, "ops": COPILOT_HOOK_OPS})
            } else {
                Value::Null
            },
            // Grok resolves its own trusted executable and retires stale hook
            // commands the CLI's validator names.
            // Cline answers its own doctor warnings, needs the frozen-runtime
            // fact to pick a transport, and runs probes inside its install.
            "warnings_op": self.harness == "cline",
            "frozen_fact": self.frozen_fact(),
            "install_timeout": if self.harness == "cline" { json!(INSTALL_PROBE_TIMEOUT) } else { Value::Null },
            // OpenCode launches through its own runner kind, which renders the
            // inline config overlay and the argv around the caller's arguments.
            "launch_runner": if self.harness == "opencode" { "opencode_launch" } else { "" },
            // Cursor's editor runs Guard's hooks on its own, so a missing
            // `cursor-agent` says nothing about whether Cursor is installed;
            // an uninstall also removes the older `cursor` launcher, and
            // Claude's the `claude-code` one.
            "absence_proves_uninstalled": self.harness != "cursor",
            "legacy_launchers": match self.harness {
                "cursor" => json!(["cursor"]),
                "claude-code" => json!(["claude-code"]),
                _ => json!([]),
            },
            "trusted_launcher": self.harness == "grok",
            // Paseo and the Pi family add to the generic doctor report.
            "diagnostics": matches!(self.harness, "paseo" | "pi" | "omp" | "claude-code" | "hermes"),
            // The Pi family renders an extension that runs this Guard process.
            "extension": self.extension(),
            "delegates": if self.install == Install::Delegated {
                json!(PASEO_DELEGATES)
            } else {
                json!([])
            },
        })
    }
}

/// Cline's install may run the hook canary and `node --check` twice (once
/// per transport) and the hook state once more, each up to 20 seconds.
const INSTALL_PROBE_TIMEOUT: u64 = 90;

pub(crate) fn describe() -> Value {
    json!({
        "adapters": SPECS.iter().map(Spec::describe).collect::<Vec<_>>(),
        "env_names": ENV_NAMES.as_slice(),
        "env_prefixes": ENV_PREFIXES,
    })
}
