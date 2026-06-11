export const SUPPORTED_APP_SLUGS = [
  "codex",
  "claude-code",
  "opencode",
  "copilot",
  "cursor",
  "gemini",
  "hermes",
  "openclaw",
  "kimi",
] as const;

export type SupportedAppSlug = (typeof SUPPORTED_APP_SLUGS)[number];

export const SUPPORTED_APPS_BRIEF =
  "Guard works with Codex, Claude Code, OpenCode, Copilot, Cursor, Gemini, Hermes, OpenClaw, and Kimi.";

export const SUPPORTED_APPS_FULL =
  "Guard works with Codex, Claude Code, OpenCode, Copilot, Cursor, Gemini, Hermes, OpenClaw, Kimi, and more. Run your AI app once and Guard will detect it automatically.";

export type AppInstallStatus = "active" | "partial" | "observed" | "not_installed";

export function resolveAppInstallStatus(
  install: { active?: boolean } | undefined,
  hasInventory: boolean,
  hasReceipts: boolean
): AppInstallStatus {
  if (install !== undefined) {
    if (install.active) return "active";
    return "partial";
  }
  if (hasInventory || hasReceipts) return "observed";
  return "not_installed";
}

export const APP_STATUS_LABELS: Record<AppInstallStatus, string> = {
  active: "Active",
  partial: "Partial setup",
  observed: "Observed",
  not_installed: "Not installed",
};

export const APP_STATUS_DESCRIPTIONS: Record<AppInstallStatus, string> = {
  active: "Guard is actively protecting this app.",
  partial: "Guard detected this app but setup is incomplete. Open the app detail to finish.",
  observed: "Guard has seen activity from this app but no managed install is active.",
  not_installed: "This app has not been seen on this machine yet.",
};

export type RiskControlConsequence = {
  key: string;
  example: string;
  impact: string;
};

export const RISK_CONTROL_CONSEQUENCES: Readonly<Record<string, RiskControlConsequence>> = {
  local_secret_read: {
    key: "local_secret_read",
    example: "Reading .env, .npmrc, SSH keys, or cloud credential files",
    impact: "Guard asks before any AI tool opens files that look like credential stores on this machine",
  },
  credential_exfiltration: {
    key: "credential_exfiltration",
    example: "A command that sends API keys or tokens to a remote host",
    impact: "Guard stops credential data from leaving your machine without your review",
  },
  data_flow_exfiltration: {
    key: "data_flow_exfiltration",
    example: "Reading .env then piping the value to curl or a network call in the same session",
    impact: "Guard stops the full secret-to-network route, even when it spans multiple steps",
  },
  destructive_shell: {
    key: "destructive_shell",
    example: "rm -rf, git clean -fdx, or commands that rewrite core config files",
    impact: "Guard pauses irreversible file deletions and overwrites so you can review first",
  },
  encoded_execution: {
    key: "encoded_execution",
    example: "eval(atob(...)) or base64-decoded shell payloads that hide their content",
    impact: "Guard stops scripts that encode their intent so you cannot tell what they do without decoding",
  },
  network_egress: {
    key: "network_egress",
    example: "A request to a host Guard has not seen in this project before",
    impact: "Guard asks before any new external network destination is contacted",
  },
  prompt_injection: {
    key: "prompt_injection",
    example: "A pasted instruction that tells the AI app to ignore Guard or expose secrets",
    impact: "Guard pauses prompt patterns that try to override safety rules",
  },
  mcp_dangerous_tool: {
    key: "mcp_dangerous_tool",
    example: "An MCP server requests a file delete, shell execution, or broad filesystem tool",
    impact: "Guard lets you choose which MCP tools can run without review",
  },
  malicious_skill: {
    key: "malicious_skill",
    example: "A skill from an untrusted source asks to install hooks or run hidden commands",
    impact: "Guard asks before skills can make persistent or privileged changes",
  },
  package_script: {
    key: "package_script",
    example: "npm postinstall, pnpm prepare, or a package lifecycle script runs code",
    impact: "Guard checks supply-chain scripts before they execute locally",
  },
  persistence: {
    key: "persistence",
    example: "A command writes launch agents, shell startup files, or recurring tasks",
    impact: "Guard stops AI apps from adding background persistence without review",
  },
  guard_bypass: {
    key: "guard_bypass",
    example: "A command disables hooks, edits Guard policy, or routes around approvals",
    impact: "Guard blocks attempts to weaken or bypass local protection",
  },
  cloud_advisory: {
    key: "cloud_advisory",
    example: "A team or Cloud advisory marks an action pattern as risky",
    impact: "Guard can apply trusted team guidance when Cloud sync is enabled",
  },
  encoded_exfiltration: {
    key: "encoded_exfiltration",
    example: "A base64 payload decodes a secret and sends it over the network",
    impact: "Guard connects hidden execution and exfiltration into one reviewable risk",
  },
};

export type SettingSearchMatch = {
  key: string;
  label: string;
  description: string;
  section: "risk" | "defaults" | "protection" | "maintenance";
};

const SETTINGS_SEARCH_INDEX: SettingSearchMatch[] = [
  { key: "local_secret_read", label: "Local secrets", description: "Files such as .env, .npmrc, SSH keys, and cloud credentials.", section: "risk" },
  { key: "credential_exfiltration", label: "Credential sharing", description: "Commands or scripts that appear to send keys, tokens, or credentials away.", section: "risk" },
  { key: "data_flow_exfiltration", label: "Secret data flow", description: "Detected source-to-sink route where a local secret reaches a network or external sink.", section: "risk" },
  { key: "destructive_shell", label: "Destructive commands", description: "Shell actions that delete, overwrite, or rewrite local files.", section: "risk" },
  { key: "encoded_execution", label: "Hidden scripts", description: "Encoded, encrypted, or decoded-and-run command payloads.", section: "risk" },
  { key: "network_egress", label: "New network destinations", description: "Outbound connections Guard has not seen in this context.", section: "risk" },
  { key: "prompt_injection", label: "Prompt injection", description: "Instructions that try to override Guard or leak private data.", section: "risk" },
  { key: "mcp_dangerous_tool", label: "Connected tools", description: "Tool calls that can read files, run commands, or reach the network.", section: "risk" },
  { key: "malicious_skill", label: "Skills", description: "Agent skills from unknown or risky sources.", section: "risk" },
  { key: "package_script", label: "Package scripts", description: "Lifecycle scripts such as postinstall, prepare, and prepublish.", section: "risk" },
  { key: "persistence", label: "Persistence", description: "Startup files, launch agents, scheduled jobs, and recurring hooks.", section: "risk" },
  { key: "guard_bypass", label: "Guard bypass", description: "Attempts to disable Guard hooks, policies, or approval flow.", section: "risk" },
  { key: "cloud_advisory", label: "Cloud advisories", description: "Team and Cloud guidance for known risky patterns.", section: "risk" },
  { key: "encoded_exfiltration", label: "Encoded exfiltration", description: "Encoded payloads that hide secret extraction and network transfer.", section: "risk" },
  { key: "default_action", label: "First-time action", description: "What Guard does the first time it sees a new action.", section: "defaults" },
  { key: "unknown_publisher_action", label: "Unknown source", description: "What Guard does when it cannot verify who published a tool or command.", section: "defaults" },
  { key: "changed_hash_action", label: "Changed command", description: "What Guard does when an approved command changes.", section: "defaults" },
  { key: "new_network_domain_action", label: "New website or host", description: "What Guard does when an app contacts a host it has not seen before.", section: "defaults" },
  { key: "subprocess_action", label: "Nested commands", description: "What Guard does when a command starts another command.", section: "defaults" },
  { key: "approval_surface_policy", label: "Where to ask", description: "Where Guard shows approval prompts.", section: "defaults" },
  { key: "security_level", label: "Security level", description: "Overall protection preset: Relaxed, Balanced, Strict, or Custom.", section: "protection" },
  { key: "mode", label: "Protection mode", description: "Prompt, Enforce, or Observe. Controls whether Guard pauses actions.", section: "protection" },
  { key: "approval_wait_timeout", label: "Approval wait timeout", description: "How long Guard waits for you to respond before resuming.", section: "protection" },
  { key: "telemetry", label: "Telemetry", description: "Send anonymized usage data to improve Guard.", section: "protection" },
  { key: "sync", label: "Cloud sync", description: "Sync decisions and rules with Guard Cloud.", section: "protection" },
  { key: "billing", label: "Billing features", description: "Enable billing and subscription features.", section: "protection" },
  { key: "clear_approvals", label: "Clear saved approvals", description: "Remove all stored allow or block decisions. Guard will ask again.", section: "maintenance" },
  { key: "clear_evidence", label: "Clear evidence log", description: "Permanently remove all recorded evidence. Cannot be undone.", section: "maintenance" },
  { key: "export_diagnostics", label: "Export diagnostics", description: "Download a JSON file with local Guard evidence for debugging.", section: "maintenance" },
  { key: "repair_approval_center", label: "Repair approval center", description: "Reset the approval center locator when the link returns an error.", section: "maintenance" },
];

export function filterSettingsBySearch(query: string): SettingSearchMatch[] {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  return SETTINGS_SEARCH_INDEX.filter(
    (item) =>
      item.label.toLowerCase().includes(q) ||
      item.description.toLowerCase().includes(q) ||
      item.key.toLowerCase().includes(q)
  );
}

export function securityLevelLabel(level: "relaxed" | "gentle" | "balanced" | "strict" | "custom"): string {
  switch (level) {
    case "relaxed":
      return "Relaxed";
    case "gentle":
      return "Relaxed";
    case "balanced":
      return "Balanced";
    case "strict":
      return "Strict";
    case "custom":
      return "Custom";
  }
}
