//! What each adapter this kind owns is: its names, launcher, approval flow and
//! which generic steps Python runs for it.

use serde_json::{json, Value};

/// How Python installs a harness.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Install {
    /// Only the launcher shim.
    Shim,
    /// The shim plus the file plan `prepare_install` returns.
    Plan,
    /// Paseo: native installs of other adapters, then a receipt.
    Delegated,
}

/// How the bounded hook argv reaches the plan.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hook {
    None,
    /// Joined into one shell command line.
    Shell,
    /// Kept as an argv list.
    Argv,
}

pub(crate) struct Spec {
    pub(crate) harness: &'static str,
    pub(crate) aliases: &'static [&'static str],
    pub(crate) executable: &'static str,
    pub(crate) launcher_name: &'static str,
    pub(crate) display_name: Option<&'static str>,
    pub(crate) tier: &'static str,
    pub(crate) summary: &'static str,
    pub(crate) fallback: &'static str,
    pub(crate) channel: &'static str,
    pub(crate) auto_open: bool,
    pub(crate) workspace_aibom: bool,
    pub(crate) hook: Hook,
    pub(crate) install: Install,
    pub(crate) dynamic: bool,
}

const CENTER: &str = "approval-center";

/// Native harnesses Paseo delegates to, as Python's adapter registry names them.
pub(crate) const PASEO_DELEGATES: [&str; 6] =
    ["claude-code", "codex", "copilot", "opencode", "pi", "omp"];

/// Every variable a request's `env` may carry.
pub(crate) const ENV_NAMES: [&str; 26] = [
    "PATH",
    "PATHEXT",
    "NoDefaultCurrentDirectoryInExePath",
    "KIMI_CODE_HOME",
    "APPDATA",
    "XDG_CONFIG_HOME",
    "PASEO_HOME",
    "GROK_HOME",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "LOCALAPPDATA",
    "ZCODE_HOME",
    "__CFBundleIdentifier",
    "ZCODE_BASE_URL",
    "ZCODE_APP_VERSION",
    "ZCODE_ENV",
    "ZCODE_RUNTIME_ENV",
    "ZCODE_PROCESS_LABEL",
    "ZCODE_RG_BINARY",
    "ZAI_OAUTH_ORIGIN",
    "ZAI_OAUTH_CLIENT_ID",
    "HOL_GUARD_DESKTOP_RUNTIME_OWNER",
    "XDG_DATA_HOME",
    "CLINE_DATA_DIR",
    "CLINE_DIR",
    "CLINE_MCP_SETTINGS_PATH",
];

/// Prefixes of the variables that redirect Paseo's native runtimes.
pub(crate) const ENV_PREFIXES: [&str; 14] = [
    "CLAUDE_CONFIG_DIR",
    "CLAUDE_CODE_DISABLE_HOOKS",
    "CLAUDE_CODE_SIMPLE",
    "CODEX_HOME",
    "COPILOT_HOME",
    "COPILOT_CONFIG_DIR",
    "XDG_CONFIG_HOME",
    "OPENCODE_CONFIG",
    "OPENCODE_DISABLE",
    "PI_CODING_AGENT_DIR",
    "PI_CONFIG_DIR",
    "PI_PROFILE",
    "OMP_AGENT_DIR",
    "OMP_PROFILE",
];

pub(crate) const SPECS: [Spec; 13] = [
    Spec {
        harness: "devin",
        aliases: &["devin", "devin-cli", "cognition-devin"],
        executable: "devin",
        launcher_name: "devin",
        display_name: Some("devin"),
        tier: CENTER,
        summary: "Guard scans Devin config, hooks, skills, and MCP registrations before launch \
                  and routes blocked actions to the local approval center.",
        fallback: "Devin gets preflight approval through Guard until it exposes a richer native \
                   approval surface. Use the Guard approval center when native prompting is \
                   unavailable.",
        channel: "browser",
        auto_open: true,
        workspace_aibom: true,
        hook: Hook::Shell,
        install: Install::Plan,
        dynamic: false,
    },
    Spec {
        harness: "antigravity",
        aliases: &[],
        executable: "antigravity",
        launcher_name: "",
        display_name: None,
        tier: CENTER,
        summary: "Guard scans Antigravity extensions, MCP registrations, and skills before \
                  launch and routes review through the local approval center.",
        fallback: "Use Guard review for new Antigravity artifacts before launch, then hand off \
                   to the local editor normally.",
        channel: "browser",
        auto_open: true,
        workspace_aibom: true,
        hook: Hook::None,
        install: Install::Shim,
        dynamic: false,
    },
    Spec {
        harness: "gemini",
        aliases: &[],
        executable: "gemini",
        launcher_name: "",
        display_name: None,
        tier: CENTER,
        summary: "Guard scans Gemini settings, extensions, hooks, skills, and MCP registrations \
                  before launch and sends blocked changes to the local approval center.",
        fallback: "Gemini gets preflight approval through Guard until it exposes a richer \
                   native approval surface.",
        channel: "browser",
        auto_open: true,
        workspace_aibom: true,
        hook: Hook::None,
        install: Install::Shim,
        dynamic: false,
    },
    Spec {
        harness: "kimi",
        aliases: &["kimi", "kimi-code", "kimi-cli"],
        executable: "kimi",
        launcher_name: "kimi",
        display_name: Some("kimi"),
        tier: CENTER,
        summary: "Guard scans Kimi Code config, hooks, and MCP registrations before launch and \
                  routes blocked changes to the local approval center.",
        fallback: "Kimi Code gets preflight approval through Guard until it exposes a richer \
                   native approval surface.",
        channel: "browser",
        auto_open: true,
        workspace_aibom: true,
        hook: Hook::Shell,
        install: Install::Plan,
        dynamic: false,
    },
    Spec {
        harness: "openclaw",
        aliases: &[],
        executable: "openclaw",
        launcher_name: "",
        display_name: None,
        tier: CENTER,
        summary: "Guard can scan OpenClaw gateway config, channels, skills, and MCP servers \
                  before agent sessions run.",
        fallback: "Connect OpenClaw through the Guard-managed overlay or resolve requests in \
                   the approval center.",
        channel: "native-fallback",
        auto_open: false,
        workspace_aibom: false,
        hook: Hook::Argv,
        install: Install::Plan,
        dynamic: true,
    },
    Spec {
        harness: "paseo",
        aliases: &[],
        executable: "paseo",
        launcher_name: "",
        display_name: None,
        tier: CENTER,
        summary: "Approvals use each provider's native Guard integration on the Paseo daemon \
                  host.",
        fallback: "Check the native provider in Guard on the daemon host; Paseo notifications \
                   do not enforce policy.",
        channel: "browser",
        auto_open: true,
        workspace_aibom: false,
        hook: Hook::None,
        install: Install::Delegated,
        dynamic: true,
    },
    Spec {
        harness: "muse",
        aliases: &["muse", "muse-code"],
        executable: "muse",
        launcher_name: "muse",
        display_name: Some("muse"),
        tier: "native-or-center",
        summary: "Guard scans Muse config, hooks, skills, plugins, and MCP registrations before \
                  launch and routes blocked actions to the local approval center. Approving a \
                  blocked tool call resumes that exact call.",
        fallback: "Muse resumes an approved tool call inside the pending hook. Use the Guard \
                   approval center when native prompting is unavailable.",
        channel: "hook",
        auto_open: false,
        workspace_aibom: true,
        hook: Hook::Shell,
        install: Install::Plan,
        dynamic: false,
    },
    Spec {
        harness: "grok",
        aliases: &["grok-build", "grok-build-cli", "xai-grok"],
        executable: "grok",
        launcher_name: "grok",
        display_name: Some("grok"),
        tier: CENTER,
        summary: "Guard intercepts every Grok tool call, including subagent and MCP tools, \
                  through a catch-all PreToolUse hook and routes blocked actions to the local \
                  approval center.",
        fallback: "Guard screens submitted prompts and intercepts tool calls on PreToolUse. Use \
                   the Guard approval center when a tool call is denied.",
        channel: "browser",
        auto_open: true,
        workspace_aibom: true,
        hook: Hook::Shell,
        install: Install::Plan,
        dynamic: false,
    },
    Spec {
        harness: "zcode",
        aliases: &["zcode", "zai", "z-code", "zai-zcode"],
        executable: "zcode",
        launcher_name: "zcode",
        display_name: Some("zcode"),
        tier: CENTER,
        summary: "Guard scans ZCode config, plugins, hooks, skills, and MCP registrations before \
                  launch and routes blocked actions to the local approval center.",
        fallback: "ZCode gets preflight approval through Guard until it exposes a richer native \
                   approval surface. Use the Guard approval center when native prompting is \
                   unavailable.",
        channel: "browser",
        auto_open: true,
        workspace_aibom: true,
        hook: Hook::Shell,
        install: Install::Plan,
        dynamic: false,
    },
    Spec {
        harness: "pi",
        aliases: &["pi", "pi-agent", "pi-coding-agent"],
        executable: "pi",
        launcher_name: "pi",
        display_name: Some("Pi"),
        tier: CENTER,
        summary: "Guard scans Pi packages, extensions, skills, prompts, and themes before launch \
                  and uses a managed Pi extension to review prompts and tool calls inline.",
        fallback: "Pi keeps the blocked request in Guard and shows the reason inline before you \
                   retry.",
        channel: "native-fallback",
        auto_open: true,
        workspace_aibom: true,
        hook: Hook::None,
        install: Install::Plan,
        dynamic: true,
    },
    Spec {
        harness: "omp",
        aliases: &["omp", "oh-my-pi"],
        executable: "omp",
        launcher_name: "omp",
        display_name: Some("Oh My Pi"),
        tier: CENTER,
        summary: "Guard scans Oh My Pi packages, extensions, skills, prompts, and themes before \
                  launch and uses a managed Oh My Pi extension to review prompts and tool calls \
                  inline.",
        fallback: "Oh My Pi keeps the blocked request in Guard and shows the reason inline before \
                   you retry.",
        channel: "native-fallback",
        auto_open: true,
        workspace_aibom: true,
        hook: Hook::None,
        install: Install::Plan,
        dynamic: true,
    },
    Spec {
        harness: "opencode",
        aliases: &[],
        executable: "opencode",
        launcher_name: "",
        display_name: None,
        tier: "mixed",
        summary: "Guard evaluates OpenCode skills, MCP servers, commands, and plugins before \
                  launch, and the managed runtime overlay keeps managed MCP tools on native ask.",
        fallback: "Use Guard approvals for blocked artifacts and OpenCode's native allow once or \
                   allow session flow for managed MCP tools.",
        channel: "native",
        auto_open: false,
        workspace_aibom: true,
        hook: Hook::None,
        install: Install::Plan,
        dynamic: false,
    },
    Spec {
        harness: "cline",
        aliases: &["cline-cli", "cline-vscode"],
        executable: "cline",
        launcher_name: "cline",
        display_name: None,
        tier: "approval-center",
        summary: "Guard blocks Cline PreToolUse actions synchronously and routes review-required \
                  actions through the local approval center.",
        fallback: "Resolve the Guard request, then retry the exact Cline tool action.",
        channel: "browser",
        auto_open: true,
        workspace_aibom: false,
        hook: Hook::None,
        install: Install::Plan,
        dynamic: false,
    },
];

pub(crate) fn spec(harness: &str) -> Option<&'static Spec> {
    SPECS.iter().find(|spec| spec.harness == harness)
}

impl Spec {
    /// The default approval flow, as `HarnessAdapter.approval_flow` answers it.
    pub(crate) fn approval_flow(&self) -> Value {
        json!({
            "tier": self.tier,
            "summary": self.summary,
            "fallback_hint": self.fallback,
            "prompt_channel": self.channel,
            "auto_open_browser": self.auto_open,
        })
    }

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
            // Grok resolves its own trusted executable and retires stale hook
            // commands the CLI's validator names.
            "trusted_launcher": self.harness == "grok",
            "retired_hooks": self.harness == "grok",
            // Paseo and the Pi family add to the generic doctor report.
            "diagnostics": matches!(self.harness, "paseo" | "pi" | "omp"),
            // The Pi family renders an extension that runs this Guard process.
            "extension": matches!(self.harness, "pi" | "omp"),
            "delegates": if self.install == Install::Delegated {
                json!(PASEO_DELEGATES)
            } else {
                json!([])
            },
        })
    }
}

pub(crate) fn describe() -> Value {
    json!({
        "adapters": SPECS.iter().map(Spec::describe).collect::<Vec<_>>(),
        "env_names": ENV_NAMES,
        "env_prefixes": ENV_PREFIXES,
    })
}
