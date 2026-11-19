import { firstActionWordIndex, nameWords } from "./mcp-effects";

const SERVICE_NAMES = new Map<string, string>([
  ["composio", "Composio"],
  ["gmail", "Gmail"],
  ["googlecalendar", "Google Calendar"],
  ["googledrive", "Google Drive"],
  ["googledocs", "Google Docs"],
  ["googlesheets", "Google Sheets"],
  ["googleslides", "Google Slides"],
  ["googlemeet", "Google Meet"],
  ["googletasks", "Google Tasks"],
  ["github", "GitHub"],
  ["gitlab", "GitLab"],
  ["slack", "Slack"],
  ["discord", "Discord"],
  ["notion", "Notion"],
  ["linear", "Linear"],
  ["jira", "Jira"],
  ["asana", "Asana"],
  ["trello", "Trello"],
  ["airtable", "Airtable"],
  ["hubspot", "HubSpot"],
  ["salesforce", "Salesforce"],
  ["stripe", "Stripe"],
  ["shopify", "Shopify"],
  ["youtube", "YouTube"],
  ["linkedin", "LinkedIn"],
  ["twitter", "X (Twitter)"],
  ["reddit", "Reddit"],
  ["facebook", "Facebook"],
  ["instagram", "Instagram"],
  ["dropbox", "Dropbox"],
  ["outlook", "Outlook"],
  ["zoom", "Zoom"],
  ["figma", "Figma"],
  ["sentry", "Sentry"],
  ["posthog", "PostHog"],
  ["supabase", "Supabase"],
  ["vercel", "Vercel"],
  ["cloudflare", "Cloudflare"],
  ["openai", "OpenAI"],
  ["perplexity", "Perplexity"],
  ["firecrawl", "Firecrawl"],
  ["context7", "Context7"],
  ["playwright", "Playwright browser"],
  ["puppeteer", "Puppeteer browser"],
  ["claudebrowser", "Claude's browser"],
  ["claudeinchrome", "Chrome"],
  ["chromedevtools", "Chrome"],
  ["computeruse", "Computer control"],
  ["filesystem", "Files"],
  ["postgres", "Postgres"],
  ["sqlite", "SQLite"],
  ["brave", "Brave Search"],
  ["bravesearch", "Brave Search"],
  ["exa", "Exa"],
  ["tavily", "Tavily"],
]);

/** A readable name for a service or connector key such as `googlecalendar` or `bing_webmaster_tools`. */
export function serviceDisplayName(key: string): string {
  const known = SERVICE_NAMES.get(key.trim().toLowerCase().replace(/[\s_-]+/g, ""));
  if (known !== undefined) return known;
  const words = nameWords(key);
  if (words.length === 0) return key.trim();
  return words.map(capitalize).join(" ");
}

export function capitalize(word: string): string {
  return word.length === 0 ? word : `${word[0].toUpperCase()}${word.slice(1)}`;
}

/** `search_issues` becomes `Search issues`. */
export function sentenceCase(identifier: string): string {
  const words = nameWords(identifier);
  if (words.length === 0) return identifier.trim();
  return capitalize(words.join(" "));
}

/**
 * Splits a Composio tool slug such as `GMAIL_SEND_EMAIL` into the app it acts
 * in and the action it takes. The app is every word before the first action
 * word, so `BING_WEBMASTER_TOOLS_GET_SITES` reads as Bing Webmaster Tools.
 */
export function splitToolSlug(slug: string): { app: string | null; action: string } {
  const words = nameWords(slug);
  const split = firstActionWordIndex(words);
  if (split <= 0) {
    return { app: null, action: sentenceCase(slug) };
  }
  const action = words.slice(split);
  action[0] = PLAIN_VERBS.get(action[0]) ?? action[0];
  return {
    app: serviceDisplayName(words.slice(0, split).join("_")),
    action: capitalize(action.join(" ")),
  };
}

// API verbs people do not say. `GMAIL_FETCH_EMAILS` reads as "Get emails".
const PLAIN_VERBS = new Map([
  ["fetch", "get"],
  ["retrieve", "get"],
]);

/**
 * A tool's name as a short action, without the service's own name in front:
 * `brave_web_search` on Brave Search is `Web search`, not `Brave web search`.
 */
export function toolTitle(service: string, tool: string): string {
  const serviceWords = new Set(nameWords(service));
  const words = nameWords(tool);
  let start = 0;
  while (start < words.length - 1 && serviceWords.has(words[start])) start += 1;
  return start === 0 ? sentenceCase(tool) : capitalize(words.slice(start).join(" "));
}

export type McpServerRef = { server: string; tool: string };

const NAME_PART = /^[a-zA-Z0-9_.:-]{1,120}$/;

/** `mcp__server__tool`, including Codex's `mcp__codex_apps__connector__tool`. */
export function parseNamespacedMcpName(raw: string | null | undefined): McpServerRef | null {
  if (!raw || raw.length > 256 || !raw.startsWith("mcp__")) return null;
  const parts = raw.slice(5).split("__");
  if (parts.length < 2 || parts.some((part) => !NAME_PART.test(part))) return null;
  const codexApp = parts[0] === "codex_apps" && parts.length > 2;
  return { server: codexApp ? parts[1] : parts[0], tool: parts.slice(codexApp ? 2 : 1).join("__") };
}

export function isPlainNamePart(value: string | null | undefined): value is string {
  return typeof value === "string" && NAME_PART.test(value);
}

/** Drops a leading `<server>_` from a tool name: `COMPOSIO_SEARCH_TOOLS` on `composio` is `SEARCH_TOOLS`. */
export function shortToolName(server: string, tool: string): string {
  const prefix = `${server.toLowerCase()}_`;
  return tool.toLowerCase().startsWith(prefix) && tool.length > prefix.length ? tool.slice(prefix.length) : tool;
}
