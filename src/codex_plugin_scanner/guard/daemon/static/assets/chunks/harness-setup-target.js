const CONNECTABLE_HARNESS_ALIASES = /* @__PURE__ */ new Set([
  "codex",
  "claude-code",
  "claude",
  "copilot",
  "cursor",
  "cline",
  "cline-cli",
  "cline-vscode",
  "antigravity",
  "gemini",
  "grok",
  "grok-build",
  "grok-build-cli",
  "xai-grok",
  "hermes",
  "kimi",
  "kimi-code",
  "kimi-cli",
  "pi",
  "pi-agent",
  "pi-coding-agent",
  "omp",
  "oh-my-pi",
  "openclaw",
  "opencode",
  "zcode",
  "zai",
  "z-code",
  "zai-zcode"
]);
const PACKAGE_FIREWALL_SOURCES = /* @__PURE__ */ new Set([
  "package-firewall",
  "brew",
  "bun",
  "bunx",
  "bundle",
  "cargo",
  "composer",
  "go",
  "gradle",
  "mvn",
  "npm",
  "npx",
  "pip",
  "pip3",
  "pipenv",
  "pipx",
  "pnpm",
  "poetry",
  "uv",
  "uvx",
  "yarn"
]);
function appSetupTarget(harness) {
  const normalized = typeof harness === "string" ? harness.trim().toLowerCase() : "";
  if (CONNECTABLE_HARNESS_ALIASES.has(normalized)) return "harness";
  if (PACKAGE_FIREWALL_SOURCES.has(normalized)) return "package-firewall";
  if (normalized === "guard-cli" || normalized === "hol-guard") return "guard-settings";
  return "activity-only";
}
function isConnectableAppHarness(harness) {
  return appSetupTarget(harness) === "harness";
}
export {
  appSetupTarget as a,
  isConnectableAppHarness as i
};
