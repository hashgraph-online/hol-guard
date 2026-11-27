import type { ProviderEffect, ProviderState } from "./provider-integrations-api";

/** What each capability checks, in the words a person reads before connecting. */
const CAPABILITIES: Record<string, { label: string; checks: string }> = {
  "browser.origin-reputation": {
    label: "Site reputation",
    checks: "Whether a website is known for phishing, malware or scams before an agent acts on it.",
  },
  "browser.script-integrity": {
    label: "Script integrity",
    checks: "Whether scripts loaded on a page match known-bad or tampered versions.",
  },
  "browser.page-data-risk": {
    label: "Page data risk",
    checks: "Whether a page asks for data it should not, such as credentials on a look-alike site.",
  },
  "browser.download-reputation": {
    label: "Download reputation",
    checks: "Whether a file an agent downloads is known to be harmful.",
  },
  "browser.site-policy": {
    label: "Site policy",
    checks: "Whether your organization allows agents to use a website.",
  },
};

/** What each shareable fact sends, so "What leaves this device" never shows a raw code alone. */
const FACTS: Record<string, string> = {
  "target.origin": "The website's address without a path, such as https://shop.example",
  "target.site_group": "The registrable domain the website belongs to",
  "target.path_prefix": "The first part of the page path",
  "action.verb": "The kind of action, such as navigate or submit",
  "action.intent": "A short label for what the agent is trying to do",
  "page.script_hashes": "Fingerprints of the scripts on the page, never their contents",
  "download.sha256": "The fingerprint of a downloaded file, never the file",
  "guard.version": "The HOL Guard version",
};

const STATES: Record<ProviderState, string> = {
  not_connected: "Not connected",
  connected: "Connected",
  key_invalid: "Key rejected",
  disabled: "Turned off",
};

const EFFECTS: Record<ProviderEffect, string> = {
  observe: "Record findings only",
  tighten: "Ask before risky actions",
  enforce: "Block dangerous sites",
};

const SURFACES: Record<string, string> = {
  browser: "Browser",
};

export function capabilityLabel(capability: string): string {
  return CAPABILITIES[capability]?.label ?? capability;
}

export function capabilityChecks(capability: string): string | null {
  return CAPABILITIES[capability]?.checks ?? null;
}

/** Facts a provider may only receive after the person turns them on (PRD 6.4). */
const OPT_IN_ONLY_FACTS: ReadonlySet<string> = new Set(["target.path_prefix"]);

export function factIsOptIn(fact: string): boolean {
  return OPT_IN_ONLY_FACTS.has(fact);
}

export function factDescription(fact: string): string {
  return FACTS[fact] ?? fact;
}

export function providerStateLabel(state: ProviderState): string {
  return STATES[state];
}

export function effectLabel(effect: ProviderEffect): string {
  return EFFECTS[effect];
}

export function surfaceLabel(surface: string): string {
  return SURFACES[surface] ?? surface;
}

export function providerErrorMessage(code: string): string {
  switch (code) {
    case "provider_not_found":
      return "Guard does not ship this provider.";
    case "provider_capability_unavailable":
      return "Provider integrations are turned off on this device.";
    case "provider_managed_policy_unavailable":
      return "Guard could not read your organization's policy, so integrations are paused.";
    default:
      return "Guard could not load provider integrations.";
  }
}
