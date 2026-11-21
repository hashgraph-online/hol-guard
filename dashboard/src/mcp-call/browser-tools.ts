import type { McpCallBody } from "./composio-calls";
import { THOUGHT_CAPTION } from "./composio-calls";
import type { McpFact } from "./mcp-call-types";
import type { McpEffectKind } from "./mcp-effects";
import { codeOf, scalarFacts, textOf } from "./mcp-input";
import { linkParts } from "./mcp-values";

/**
 * Tools that drive a browser or the screen: Claude's built-in browser, Claude
 * in Chrome, Playwright, Puppeteer and computer-use servers. Their names
 * (`navigate`, `computer`, `left_click`) mean nothing to most people, and
 * what matters is that the agent acts in a place where the user may be signed
 * in. Each known action gets a plain title; an unknown one returns null and
 * reads like any other tool.
 *
 * Like every effect on the card, this is read from the names, not checked.
 */
type Surface = "page" | "screen";

type BrowserAction = {
  /** Card heading. */
  title: string;
  /** Finishes "Codex wants to …" before the place. */
  phrase: string;
  effect: McpEffectKind;
};

const BROWSER_WORDS = ["browser", "playwright", "puppeteer", "chrome", "selenium", "webdriver", "stagehand"];
const SCREEN_WORDS = ["computeruse", "computer", "desktop"];

const AGENT_TEXT_KEYS = ["thought", "use_case"];
// Fields that point the tool at a spot or a tab. They mean nothing on their own, so they stay in the exact input.
const POINTER_KEYS = ["tabid", "tab_id", "coordinate", "coordinates", "start_coordinate", "ref", "element_ref", "uid", "node_id"];

function surfaceOf(server: string): Surface | null {
  const key = server.toLowerCase().replace(/[^a-z0-9]/g, "");
  if (BROWSER_WORDS.some((word) => key.includes(word))) return "page";
  if (SCREEN_WORDS.some((word) => key.includes(word))) return "screen";
  return null;
}

function action(title: string, phrase: string, effect: McpEffectKind): BrowserAction {
  return { title, phrase, effect };
}

function actionFor(name: string, surface: Surface): BrowserAction | null {
  const on = surface === "page" ? "the page" : "the screen";
  const word = name.toLowerCase().replace(/^(browser|page|mouse|computer)_/, "");
  switch (word) {
    case "navigate":
    case "navigate_page":
    case "goto":
    case "go_to":
    case "open":
    case "open_url":
    case "open_page":
    case "new_page":
    case "new_tab":
    case "tab_new":
    case "tabs_create":
    case "tabs_create_mcp":
    case "preview_start":
      return action("Open a web page", "open a web page", "act-as-you");
    case "navigate_back":
    case "go_back":
    case "back":
      return action("Go back a page", "go back a page", "act-as-you");
    case "click":
    case "left_click":
    case "right_click":
    case "middle_click":
    case "double_click":
    case "triple_click":
    case "tap":
      return action(`Click on ${on}`, `click on ${on}`, "act-as-you");
    case "left_click_drag":
    case "drag":
    case "drag_and_drop":
      return action(`Drag on ${on}`, `drag something on ${on}`, "act-as-you");
    case "type":
    case "type_text":
    case "fill":
    case "fill_form":
    case "form_input":
    case "input_text":
    case "select_option":
      return action(`Type on ${on}`, `type on ${on}`, "act-as-you");
    case "key":
    case "press":
    case "press_key":
    case "keyboard":
      return action("Press a key", `press a key on ${on}`, "act-as-you");
    case "scroll":
    case "scroll_to":
    case "hover":
    case "mouse_move":
      return action(`Move around ${on}`, `move around ${on}`, "act-as-you");
    case "screenshot":
    case "take_screenshot":
    case "zoom":
      return action(surface === "page" ? "Take a picture of the page" : "Take a picture of your screen", "take a screenshot", "read");
    case "snapshot":
    case "read_page":
    case "get_page_text":
    case "get_text":
    case "get_content":
    case "extract":
      return action("Read the page", "read the page", "read");
    case "find":
    case "find_element":
      return action("Find something on the page", "find something on the page", "read");
    case "tabs_context":
    case "tabs_context_mcp":
    case "tabs":
    case "list_tabs":
    case "tab_list":
      return action("See which tabs are open", "see which tabs are open", "read");
    case "read_console_messages":
    case "console_messages":
      return action("Read the page's developer messages", "read the page's developer messages", "read");
    case "read_network_requests":
    case "network_requests":
      return action("See what the page loaded", "see what the page loaded", "read");
    case "wait":
    case "wait_for":
      return action("Wait for the page", "wait for the page", "read");
    case "resize_window":
    case "resize":
      return action("Resize the window", "resize the window", "act-as-you");
    case "close":
    case "close_tab":
    case "tab_close":
    case "tabs_close":
      return action("Close a tab", "close a tab", "act-as-you");
    case "file_upload":
    case "upload_file":
    case "upload_image":
      return action("Upload a file to a website", "upload a file to a website", "send");
    case "evaluate":
    case "javascript":
    case "javascript_tool":
    case "execute_script":
    case "run_script":
      return action("Run code on the page", "run code on the page", "run-code");
    case "open_application":
    case "open_app":
      return action("Open an app", "open an app on your computer", "act-as-you");
    default:
      return null;
  }
}

function fact(label: string, value: string | null, key: string, kind: McpFact["kind"] = "text"): McpFact[] {
  return value !== null && value.length > 0 ? [{ label, value, key, kind }] : [];
}

function firstKey(input: Record<string, unknown> | null, keys: string[]): string | null {
  if (input === null) return null;
  return keys.find((key) => typeof input[key] === "string" && (input[key] as string).trim().length > 0) ?? null;
}

const URL_KEYS = ["url", "href", "link"];
const TEXT_KEYS = ["text", "value", "values"];
const KEY_KEYS = ["key", "keys"];
const TARGET_KEYS = ["element", "description", "target", "selector"];
const QUERY_KEYS = ["query"];
const CODE_KEYS = ["function", "script", "expression", "code"];

/** The fields a person needs to judge the step, in their words. The rest stay in the exact input. */
function browserFacts(input: Record<string, unknown> | null, act: BrowserAction): { facts: McpFact[]; used: string[] } {
  const urlKey = firstKey(input, URL_KEYS);
  const textKey = act.effect === "run-code" ? null : firstKey(input, TEXT_KEYS);
  const keyKey = firstKey(input, KEY_KEYS);
  const targetKey = firstKey(input, TARGET_KEYS);
  const queryKey = firstKey(input, QUERY_KEYS);
  const facts = [
    ...(urlKey !== null ? fact("Web page", textOf(input?.[urlKey]), urlKey, "url") : []),
    ...(targetKey !== null ? fact("On", textOf(input?.[targetKey], 160), targetKey) : []),
    ...(textKey !== null ? fact("What it types", textOf(input?.[textKey]), textKey, "long") : []),
    ...(keyKey !== null ? fact("Key", textOf(input?.[keyKey], 60), keyKey) : []),
    ...(queryKey !== null ? fact("Looking for", textOf(input?.[queryKey], 160), queryKey) : []),
  ];
  return { facts, used: [urlKey, textKey, keyKey, targetKey, queryKey].filter((key): key is string => key !== null) };
}

/** A web address's host, for the headline, so "open a web page" becomes "open shop.example.com". */
function hostOf(facts: McpFact[]): string | null {
  const url = facts.find((item) => item.kind === "url")?.value;
  return url !== undefined ? (linkParts(url)?.host ?? null) : null;
}

export function explainBrowserTool(
  server: string,
  shortTool: string,
  context: { harness: string; connector: string; input: Record<string, unknown> | null },
): McpCallBody | null {
  const surface = surfaceOf(server);
  if (surface === null) return null;
  const { harness, connector, input } = context;
  // A single `computer` tool carries the real step in its `action` field.
  const stepName = shortTool.toLowerCase() === "computer" ? (textOf(input?.action, 40) ?? "") : shortTool;
  const act = actionFor(stepName, surface);
  if (act === null) return null;
  const { facts: named, used } = browserFacts(input, act);
  const codeKey = act.effect === "run-code" ? firstKey(input, [...CODE_KEYS, "text"]) : null;
  const code = codeKey !== null ? codeOf(input?.[codeKey]) : null;
  const skip = [...AGENT_TEXT_KEYS, ...used, ...(codeKey !== null ? [codeKey] : []), "action", ...POINTER_KEYS];
  const { facts: rest } = scalarFacts(input, { skip, max: Math.max(0, 6 - named.length) });
  const facts = [...named, ...rest];
  const host = act.title === "Open a web page" ? hostOf(facts) : null;
  const phrase = host !== null ? `open ${host}` : act.phrase;
  const thought = textOf(input?.thought, 300);
  return {
    headline: `${harness} wants to ${phrase} in ${connector}`,
    title: act.title,
    aside: null,
    effect: act.effect,
    effectBasis: "Read from the tool's name. Guard has not checked what it does.",
    facts,
    steps: [],
    quotes: thought !== null ? { caption: THOUGHT_CAPTION, items: [thought] } : null,
    code: code !== null ? { label: "Code", text: code } : null,
    queueTitle: `${connector} · ${host !== null ? `Open ${host}` : act.title}`,
    queueDetail: host === null ? (facts[0]?.value ?? null) : null,
  };
}
