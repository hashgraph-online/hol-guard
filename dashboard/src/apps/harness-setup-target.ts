// Keep this positive allowlist aligned with the daemon adapter registry. Runtime
// receipts also use the `harness` field for package managers and Guard's own
// operational evidence sources; those values must never be offered the
// state-changing AI-app install flow.
const CONNECTABLE_HARNESS_ALIASES = new Set([
  "codex",
  "claude-code",
  "claude",
  "copilot",
  "cursor",
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
  "zai-zcode",
]);

// These names mirror the package-shim managers in guard/shims.py. They have a
// dedicated, approval-gated Package Firewall mutation API.
const PACKAGE_FIREWALL_SOURCES = new Set([
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
  "yarn",
]);

export type AppSetupTarget = "harness" | "package-firewall" | "guard-settings" | "activity-only";

export function appSetupTarget(harness: string | null | undefined): AppSetupTarget {
  const normalized = typeof harness === "string" ? harness.trim().toLowerCase() : "";
  if (CONNECTABLE_HARNESS_ALIASES.has(normalized)) return "harness";
  if (PACKAGE_FIREWALL_SOURCES.has(normalized)) return "package-firewall";
  if (normalized === "guard-cli" || normalized === "hol-guard") return "guard-settings";
  return "activity-only";
}

export function isConnectableAppHarness(harness: string | null | undefined): harness is string {
  return appSetupTarget(harness) === "harness";
}
