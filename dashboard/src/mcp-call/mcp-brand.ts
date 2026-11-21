import type { IconType } from "react-icons";
import { FaLinkedin, FaMicrosoft } from "react-icons/fa";
import {
  HiMiniBookOpen,
  HiMiniCircleStack,
  HiMiniCommandLine,
  HiMiniComputerDesktop,
  HiMiniFolder,
  HiMiniGlobeAlt,
  HiMiniLightBulb,
  HiMiniMagnifyingGlass,
} from "react-icons/hi2";
import {
  SiAirtable,
  SiAsana,
  SiBitbucket,
  SiBox,
  SiBrave,
  SiCalendly,
  SiCanva,
  SiClaude,
  SiClickup,
  SiCloudflare,
  SiConfluence,
  SiDatadog,
  SiDiscord,
  SiDocker,
  SiDropbox,
  SiFacebook,
  SiFigma,
  SiFirebase,
  SiGithub,
  SiGitlab,
  SiGmail,
  SiGoogle,
  SiGooglecalendar,
  SiGooglechrome,
  SiGooglecloud,
  SiGoogledocs,
  SiGoogledrive,
  SiGooglemaps,
  SiGooglemeet,
  SiGooglesheets,
  SiGoogleslides,
  SiGoogletasks,
  SiHubspot,
  SiHuggingface,
  SiInstagram,
  SiIntercom,
  SiJira,
  SiKubernetes,
  SiLinear,
  SiLoom,
  SiMailchimp,
  SiMiro,
  SiMongodb,
  SiNetlify,
  SiNotion,
  SiObsidian,
  SiOpenai,
  SiPaypal,
  SiPerplexity,
  SiPosthog,
  SiPostgresql,
  SiReddit,
  SiRedis,
  SiSalesforce,
  SiSentry,
  SiShopify,
  SiSlack,
  SiSpotify,
  SiSqlite,
  SiStripe,
  SiSupabase,
  SiTelegram,
  SiTodoist,
  SiTrello,
  SiTwilio,
  SiVercel,
  SiWhatsapp,
  SiWordpress,
  SiX,
  SiYoutube,
  SiZendesk,
  SiZoom,
} from "react-icons/si";
import type { McpCallExplanation } from "./mcp-call-types";
import { unique } from "./mcp-input";

/**
 * The mark a review shows for an MCP app: the service's own logo when people
 * know it on sight, else an icon for what kind of tool it is (a browser, your
 * files, a search). `color` is a hex brand colour without `#`, dark enough to
 * read on its own light tint.
 */
export type McpBrand = { label: string; icon: IconType; color: string };

const GUARD_BLUE = "5599fe";

function brand(label: string, icon: IconType, color: string): McpBrand {
  return { label, icon, color };
}

const BRANDS: Record<string, McpBrand> = {
  gmail: brand("Gmail", SiGmail, "ea4335"),
  googlecalendar: brand("Google Calendar", SiGooglecalendar, "4285f4"),
  googledrive: brand("Google Drive", SiGoogledrive, "1a73e8"),
  googledocs: brand("Google Docs", SiGoogledocs, "4285f4"),
  googlesheets: brand("Google Sheets", SiGooglesheets, "188038"),
  googleslides: brand("Google Slides", SiGoogleslides, "e37400"),
  googlemeet: brand("Google Meet", SiGooglemeet, "00897b"),
  googletasks: brand("Google Tasks", SiGoogletasks, "2684fc"),
  googlemaps: brand("Google Maps", SiGooglemaps, "34a853"),
  googlecloud: brand("Google Cloud", SiGooglecloud, "4285f4"),
  google: brand("Google", SiGoogle, "4285f4"),
  github: brand("GitHub", SiGithub, "181717"),
  gitlab: brand("GitLab", SiGitlab, "e24329"),
  bitbucket: brand("Bitbucket", SiBitbucket, "0052cc"),
  slack: brand("Slack", SiSlack, "4a154b"),
  discord: brand("Discord", SiDiscord, "5865f2"),
  telegram: brand("Telegram", SiTelegram, "26a5e4"),
  whatsapp: brand("WhatsApp", SiWhatsapp, "1da851"),
  notion: brand("Notion", SiNotion, "000000"),
  linear: brand("Linear", SiLinear, "5e6ad2"),
  jira: brand("Jira", SiJira, "0052cc"),
  confluence: brand("Confluence", SiConfluence, "172b4d"),
  asana: brand("Asana", SiAsana, "e8384f"),
  trello: brand("Trello", SiTrello, "0052cc"),
  airtable: brand("Airtable", SiAirtable, "1a8fd6"),
  clickup: brand("ClickUp", SiClickup, "7b68ee"),
  todoist: brand("Todoist", SiTodoist, "e44332"),
  miro: brand("Miro", SiMiro, "050038"),
  canva: brand("Canva", SiCanva, "00a3ad"),
  figma: brand("Figma", SiFigma, "f24e1e"),
  loom: brand("Loom", SiLoom, "625df5"),
  zoom: brand("Zoom", SiZoom, "0b5cff"),
  calendly: brand("Calendly", SiCalendly, "006bff"),
  hubspot: brand("HubSpot", SiHubspot, "ff5c35"),
  salesforce: brand("Salesforce", SiSalesforce, "00a1e0"),
  zendesk: brand("Zendesk", SiZendesk, "03363d"),
  intercom: brand("Intercom", SiIntercom, "1f8ded"),
  mailchimp: brand("Mailchimp", SiMailchimp, "241c15"),
  twilio: brand("Twilio", SiTwilio, "f22f46"),
  stripe: brand("Stripe", SiStripe, "635bff"),
  paypal: brand("PayPal", SiPaypal, "002991"),
  shopify: brand("Shopify", SiShopify, "5e8e3e"),
  wordpress: brand("WordPress", SiWordpress, "21759b"),
  youtube: brand("YouTube", SiYoutube, "ff0000"),
  x: brand("X", SiX, "000000"),
  reddit: brand("Reddit", SiReddit, "ff4500"),
  facebook: brand("Facebook", SiFacebook, "0866ff"),
  instagram: brand("Instagram", SiInstagram, "e4405f"),
  linkedin: brand("LinkedIn", FaLinkedin, "0a66c2"),
  spotify: brand("Spotify", SiSpotify, "1aa34a"),
  dropbox: brand("Dropbox", SiDropbox, "0061ff"),
  box: brand("Box", SiBox, "0061d5"),
  outlook: brand("Outlook", FaMicrosoft, "0078d4"),
  microsoft: brand("Microsoft", FaMicrosoft, "0078d4"),
  obsidian: brand("Obsidian", SiObsidian, "7c3aed"),
  sentry: brand("Sentry", SiSentry, "362d59"),
  posthog: brand("PostHog", SiPosthog, "f54e00"),
  datadog: brand("Datadog", SiDatadog, "632ca6"),
  supabase: brand("Supabase", SiSupabase, "249361"),
  firebase: brand("Firebase", SiFirebase, "dd2c00"),
  vercel: brand("Vercel", SiVercel, "000000"),
  netlify: brand("Netlify", SiNetlify, "00a39b"),
  cloudflare: brand("Cloudflare", SiCloudflare, "f38020"),
  docker: brand("Docker", SiDocker, "2496ed"),
  kubernetes: brand("Kubernetes", SiKubernetes, "326ce5"),
  postgres: brand("Postgres", SiPostgresql, "4169e1"),
  sqlite: brand("SQLite", SiSqlite, "003b57"),
  mongodb: brand("MongoDB", SiMongodb, "47a248"),
  redis: brand("Redis", SiRedis, "dc382d"),
  openai: brand("OpenAI", SiOpenai, "000000"),
  claude: brand("Claude", SiClaude, "d97757"),
  perplexity: brand("Perplexity", SiPerplexity, "1a99a8"),
  huggingface: brand("Hugging Face", SiHuggingface, "c98a00"),
  brave: brand("Brave Search", SiBrave, "fb542b"),
  chrome: brand("Chrome", SiGooglechrome, "4285f4"),
};

// Other names people and servers use for the same service.
const ALIASES: Record<string, string> = {
  twitter: "x",
  xtwitter: "x",
  postgresql: "postgres",
  pg: "postgres",
  bravesearch: "brave",
  googlechrome: "chrome",
  claudeinchrome: "chrome",
  chromedevtools: "chrome",
  microsoftoutlook: "outlook",
  office365: "microsoft",
  googlegmail: "gmail",
  googlecal: "googlecalendar",
  gdrive: "googledrive",
  gcal: "googlecalendar",
};

/** What a tool is for, when its service is not one Guard has a logo for. Checked in order. */
const KINDS: { words: string[]; brand: McpBrand }[] = [
  {
    words: ["browser", "playwright", "puppeteer", "selenium", "webdriver", "stagehand"],
    brand: brand("Browser", HiMiniGlobeAlt, GUARD_BLUE),
  },
  { words: ["computeruse", "computer", "desktop", "screen"], brand: brand("Your computer", HiMiniComputerDesktop, "3f4174") },
  { words: ["filesystem", "files", "file", "fs"], brand: brand("Files", HiMiniFolder, "b7791f") },
  { words: ["search", "exa", "tavily", "serp", "bing"], brand: brand("Search", HiMiniMagnifyingGlass, GUARD_BLUE) },
  { words: ["database", "mysql", "sql", "db"], brand: brand("Database", HiMiniCircleStack, "3f4174") },
  { words: ["memory", "knowledge", "notes"], brand: brand("Memory", HiMiniLightBulb, "b7791f") },
  { words: ["fetch", "web", "http", "crawl", "scrape", "firecrawl"], brand: brand("Web", HiMiniGlobeAlt, GUARD_BLUE) },
  { words: ["shell", "terminal", "bash", "command", "exec"], brand: brand("Terminal", HiMiniCommandLine, "3f4174") },
  { words: ["docs", "context7", "documentation"], brand: brand("Docs", HiMiniBookOpen, GUARD_BLUE) },
];

const MAKER_SLUGS = new Set(["google", "claude", "microsoft", "openai"]);

// Words server names wrap around the service, as in `mcp-server-github` or `slack_mcp`.
const WRAPPER_WORDS = new Set(["mcp", "server", "official", "the"]);

function wordsOf(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((word) => word.length > 0 && !WRAPPER_WORDS.has(word));
}

/** Long kind words may sit inside a joined name (`websearch`); shorter ones must be a word of their own (`fs`, not `docsfs`). */
function namesKind(words: string[], key: string, kindWord: string): boolean {
  return kindWord.length >= 6 ? key.includes(kindWord) : words.includes(kindWord);
}

/**
 * The mark for a service, from its display name (`Google Calendar`) or its
 * server key (`mcp-server-github`, `Claude_Browser`). Null when neither the
 * service nor its kind is known, so the caller shows its first letter.
 */
export function mcpBrandFor(name: string): McpBrand | null {
  const words = wordsOf(name);
  const key = words.join("");
  if (key.length === 0) return null;
  const known = BRANDS[ALIASES[key] ?? key];
  if (known !== undefined) return known;
  // `googlecalendar_v2` and `slackbot` still name the service they start with. A maker's
  // name alone does not: `claude_browser` is a browser and `google_search` a search.
  for (const [slug, entry] of Object.entries(BRANDS)) {
    if (slug.length >= 4 && !MAKER_SLUGS.has(slug) && key.startsWith(slug)) return entry;
  }
  if (key.includes("chrome")) return BRANDS.chrome;
  for (const kind of KINDS) {
    if (kind.words.some((word) => namesKind(words, key, word))) return kind.brand;
  }
  return key.startsWith("google") ? BRANDS.google : null;
}

/**
 * Where the call acts: the one app its actions name when there is just one
 * (Gmail through Composio), else the connector it goes through. Actions
 * left out of the card may name other apps, so then it is the connector.
 */
export function actingApp(explanation: McpCallExplanation): string {
  if ((explanation.hiddenSteps ?? 0) > 0) return explanation.connector;
  const apps = unique(explanation.steps.map((step) => step.app).filter((app): app is string => app !== null));
  return apps.length === 1 ? apps[0] : explanation.connector;
}

/** The name whose mark stands for the call: the app for a built-in tool, else the app it acts in. */
export function mcpMarkName(explanation: McpCallExplanation): string {
  return explanation.builtIn === true ? (explanation.requester ?? actingApp(explanation)) : actingApp(explanation);
}
