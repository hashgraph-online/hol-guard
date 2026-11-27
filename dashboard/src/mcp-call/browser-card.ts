import type {
  GuardBrowserCardV1,
  GuardBrowserProfileLineV1,
  GuardBrowserSurfaceV1,
  GuardBrowserVerbV1,
} from "../guard-types";
import { parseProviderFindings } from "../browser-call/browser-provider-finding-model";
import type { McpCallBody } from "./composio-calls";
import { THOUGHT_CAPTION } from "./composio-calls";
import type { McpFact } from "./mcp-call-types";
import type { McpEffectKind } from "./mcp-effects";
import { codeOf, textOf } from "./mcp-input";

/**
 * A browser review drawn from Core's native card (`BrowserCardV1`). Core built
 * the card from the browser driver profile that lists the tool, so nothing
 * here reads meaning from a tool or server name. A call without a card is
 * shown as an ordinary MCP tool, never as a guessed browser step.
 */

const VERBS: Record<GuardBrowserVerbV1, { title: string; effect: McpEffectKind }> = {
  navigate: { title: "Open a web page", effect: "act-as-you" },
  read: { title: "Read the page", effect: "read" },
  click: { title: "Click on the page", effect: "act-as-you" },
  type: { title: "Type on the page", effect: "act-as-you" },
  key: { title: "Press a key", effect: "act-as-you" },
  select: { title: "Choose an option", effect: "act-as-you" },
  scroll: { title: "Move around the page", effect: "act-as-you" },
  screenshot: { title: "Take a picture of the page", effect: "read" },
  upload: { title: "Upload a file to a website", effect: "send" },
  download: { title: "Download a file", effect: "write" },
  evaluate: { title: "Run code on the page", effect: "run-code" },
  cookie_read: { title: "Read the site's cookies", effect: "read" },
  cookie_write: { title: "Change the site's cookies", effect: "act-as-you" },
  storage_read: { title: "Read the site's stored data", effect: "read" },
  storage_write: { title: "Change the site's stored data", effect: "act-as-you" },
  intercept: { title: "Watch or change network traffic", effect: "act-as-you" },
  permission: { title: "Change site permissions", effect: "act-as-you" },
  tab_control: { title: "Manage browser tabs", effect: "act-as-you" },
  attach: { title: "Attach to a browser", effect: "act-as-you" },
  other: { title: "Control the browser", effect: "unknown" },
};

const PROFILES: Record<GuardBrowserProfileLineV1, string> = {
  shared: "Your own browser profile",
  dedicated: "A separate automation profile",
  isolated: "A throwaway browser",
  "remote-debugging": "A browser attached over remote debugging",
  unknown: "A browser Guard could not identify",
};

const SURFACES: Record<GuardBrowserSurfaceV1, string> = {
  cookies: "Cookies",
  storage: "Site storage",
  auth_headers: "Sign-in headers",
  cdp: "Browser debugging protocol",
  script_eval: "Runs page code",
  upload: "File upload",
  download: "File download",
  clipboard: "Clipboard",
  network_intercept: "Network traffic",
  password_field: "Password field",
};

const INPUT_NOUNS = { text: "text", key: "keys", file: "file path", script: "code" } as const;
const CODE_KEYS = ["function", "script", "expression", "code", "text"];
const BASIS = "Read from Guard's browser driver profile for this tool.";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

function lengthOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : null;
}

/** The card Core attached, or null when the value is not a well-formed card. */
export function parseBrowserCard(value: unknown): GuardBrowserCardV1 | null {
  if (!isRecord(value) || typeof value.headline !== "string" || value.headline.trim().length === 0) return null;
  const verb = value.verb;
  if (typeof verb !== "string" || !(verb in VERBS)) return null;
  const profile = value.profile_line;
  if (typeof profile !== "string" || !(profile in PROFILES)) return null;
  const site = isRecord(value.site) ? value.site : {};
  const detail = isRecord(value.detail) ? value.detail : {};
  const inputKind = detail.input_kind;
  const chips = Array.isArray(value.risk_chips)
    ? value.risk_chips.filter((chip): chip is GuardBrowserSurfaceV1 => typeof chip === "string" && Object.hasOwn(SURFACES, chip))
    : [];
  return {
    headline: value.headline.trim(),
    verb: verb as GuardBrowserVerbV1,
    site: {
      origin: stringOrNull(site.origin),
      first_visit_in_task: site.first_visit_in_task === true,
      left_granted_site: site.left_granted_site === true,
    },
    profile_line: profile as GuardBrowserProfileLineV1,
    detail: {
      element_preview: stringOrNull(detail.element_preview),
      input_kind: typeof inputKind === "string" && inputKind in INPUT_NOUNS ? (inputKind as keyof typeof INPUT_NOUNS) : null,
      input_length: lengthOrNull(detail.input_length),
      input_masked: detail.input_masked === true,
    },
    risk_chips: [...new Set(chips)],
    provider_findings: parseProviderFindings(value.provider_findings),
    choices: Array.isArray(value.choices) ? value.choices.filter((choice): choice is string => typeof choice === "string") : [],
    steps: [],
  };
}

export function browserSurfaceLabel(surface: GuardBrowserSurfaceV1): string {
  return SURFACES[surface];
}

export function browserProfileLabel(profile: GuardBrowserProfileLineV1): string {
  return PROFILES[profile];
}

/** What the input is, never what it says: the card has no typed text. */
export function browserInputSummary(card: GuardBrowserCardV1): string | null {
  const { input_kind: kind, input_length: length, input_masked: masked } = card.detail;
  if (kind === null) return null;
  const size = length === null ? null : `${length} ${length === 1 ? "character" : "characters"}`;
  if (masked) return size === null ? "Hidden" : `Hidden · ${size}`;
  return size === null ? INPUT_NOUNS[kind] : `${size} of ${INPUT_NOUNS[kind]}`;
}

function fact(label: string, value: string | null, key: string, kind: McpFact["kind"] = "text"): McpFact[] {
  return value !== null && value.length > 0 ? [{ label, value, key, kind }] : [];
}

/** The site without its scheme, as the card names it. */
export function browserSiteLabel(origin: string | null): string | null {
  if (origin === null) return null;
  const host = origin.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/\/+$/, "");
  return host.length > 0 ? host : null;
}

export function explainBrowserCard(
  card: GuardBrowserCardV1,
  context: { connector: string; input: Record<string, unknown> | null },
): McpCallBody {
  const { title, effect } = VERBS[card.verb];
  const { input } = context;
  const facts = [
    ...fact("Web page", card.site.origin, "browser_site", "url"),
    ...fact("On", card.detail.element_preview, "browser_element"),
    ...fact(card.detail.input_kind === "script" ? "Code" : "What it types", browserInputSummary(card), "browser_input"),
    ...fact("Browser", PROFILES[card.profile_line], "browser_profile"),
    ...fact("Touches", card.risk_chips.map((chip) => SURFACES[chip]).join(", "), "browser_surfaces"),
  ];
  const codeKey = card.verb === "evaluate" && input !== null && card.detail.input_masked !== true
    ? (CODE_KEYS.find((key) => typeof input[key] === "string" && (input[key] as string).trim().length > 0) ?? null)
    : null;
  const code = codeKey !== null ? codeOf(input?.[codeKey]) : null;
  const thought = textOf(input?.thought, 300);
  const site = browserSiteLabel(card.site.origin);
  const rowTitle = card.verb === "navigate" && site !== null ? `Open ${site}` : title;
  return {
    headline: card.headline,
    title,
    aside: null,
    effect,
    effectBasis: BASIS,
    facts,
    steps: [],
    quotes: thought !== null ? { caption: THOUGHT_CAPTION, items: [thought] } : null,
    code: code !== null ? { label: "Code", text: code } : null,
    queueTitle: `${context.connector} · ${rowTitle}`,
    queueDetail: card.verb === "navigate" ? null : (facts[0]?.value ?? null),
  };
}
