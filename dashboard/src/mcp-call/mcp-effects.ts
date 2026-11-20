/**
 * What an MCP tool most likely does to the world, read from the words in its
 * name. This is a reading of the name, not a check of the tool: the card says
 * so, never calls a tool "safe", and leaves a name it cannot read as unknown.
 *
 * A name that carries a change word is never called a read, so
 * `search_and_delete` is a delete and `get_or_create_user` is a change.
 */
export type McpEffectKind =
  | "in-app"
  | "read"
  | "write"
  | "send"
  | "delete"
  | "run-code"
  | "connect"
  | "act-as-you"
  | "unknown";

export type McpEffectCopy = {
  /** Short pill text. */
  label: string;
  /** What the tool name suggests, one plain sentence. */
  meaning: string;
};

export const MCP_EFFECT_COPY: Record<McpEffectKind, McpEffectCopy> = {
  // Only a built-in agent-app tool gets this; no name is read as in-app on its own.
  "in-app": { label: "Only in the app", meaning: "It changes what the agent app shows you and nothing else." },
  read: { label: "Looks things up", meaning: "The name suggests it reads or searches and does not change anything." },
  write: { label: "Makes changes", meaning: "The name suggests it creates or changes something." },
  send: { label: "Sends something", meaning: "The name suggests it sends or posts something to other people or services." },
  delete: { label: "Deletes things", meaning: "The name suggests it removes or deletes something." },
  "run-code": { label: "Runs code", meaning: "The name suggests it runs code or a command." },
  connect: { label: "Changes connections", meaning: "The name suggests it connects or changes a linked account." },
  // Only a browser or screen-control tool gets this; no name is read as acting as you on its own.
  "act-as-you": { label: "Acts as you", meaning: "It clicks, types or opens pages as if it were you." },
  unknown: { label: "Effect unclear", meaning: "The name does not say what it does." },
};

const DELETE_WORDS = new Set([
  "delete", "remove", "destroy", "drop", "purge", "erase", "revoke", "uninstall", "trash", "clear", "wipe", "truncate", "disconnect",
]);
const SEND_WORDS = new Set([
  "send", "post", "publish", "reply", "forward", "share", "invite", "tweet", "broadcast", "notify", "dm", "submit",
]);
const RUN_WORDS = new Set([
  "run", "execute", "exec", "bash", "shell", "workbench", "eval", "script", "invoke", "spawn",
]);
const CONNECT_WORDS = new Set(["connect", "connection", "connections", "authorize", "authenticate", "login", "oauth", "unlink"]);
const WRITE_WORDS = new Set([
  "create", "update", "edit", "write", "add", "insert", "set", "modify", "patch", "upload", "move", "rename", "archive",
  "mark", "import", "append", "save", "put", "merge", "commit", "push", "pay", "transfer",
  "purchase", "approve", "enable", "disable", "install", "deploy", "assign", "close", "reopen", "restore", "sync",
  "copy", "duplicate", "unarchive", "unstar", "follow", "unfollow", "subscribe", "unsubscribe", "reset", "refresh",
  "start", "stop", "cancel", "unpin", "untag", "upsert", "attach", "detach", "register", "change", "replace",
  "make", "generate",
]);
const READ_WORDS = new Set([
  "get", "list", "search", "find", "fetch", "read", "query", "lookup", "view", "show", "check", "describe", "count",
  "retrieve", "browse", "download", "inspect", "preview", "explore", "discover", "resolve", "summarize", "analyze",
  "export", "scan", "stat", "status", "info", "schema", "schemas", "catalog", "load", "poll",
]);
// Words that are a noun as often as a verb (`get_label`, `list_orders`). They
// count as a change only when no read word comes before them.
const NOUN_OR_VERB = new Map<string, McpEffectKind>([
  ["comment", "send"],
  ["label", "write"],
  ["tag", "write"],
  ["star", "write"],
  ["pin", "write"],
  ["order", "write"],
  ["schedule", "write"],
  ["book", "write"],
  ["link", "connect"],
  ["react", "send"],
  ["build", "write"],
  ["fork", "write"],
  ["new", "write"],
  ["watch", "write"],
]);

/** Lower-case words of an identifier such as `GMAIL_SEND_EMAIL` or `createIssue`. */
export function nameWords(identifier: string): string[] {
  return identifier
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((word) => word.length > 0);
}

export function classifyMcpEffect(identifier: string): McpEffectKind {
  const words = nameWords(identifier);
  const firstRead = words.findIndex((word) => READ_WORDS.has(word));
  const ambiguous: McpEffectKind[] = [];
  words.forEach((word, index) => {
    const kind = NOUN_OR_VERB.get(word);
    if (kind !== undefined && (firstRead === -1 || index < firstRead)) ambiguous.push(kind);
  });
  const has = (kind: McpEffectKind, set: Set<string>) => ambiguous.includes(kind) || words.some((word) => set.has(word));
  // Strongest first, so a name that mixes a read word with a change word is
  // never presented as a read.
  if (has("delete", DELETE_WORDS)) return "delete";
  if (has("run-code", RUN_WORDS)) return "run-code";
  if (has("send", SEND_WORDS)) return "send";
  if (has("connect", CONNECT_WORDS)) return "connect";
  if (has("write", WRITE_WORDS)) return "write";
  if (firstRead !== -1) return "read";
  return "unknown";
}

const SEVERITY: Record<McpEffectKind, number> = {
  "in-app": 0,
  read: 1,
  unknown: 2,
  connect: 3,
  write: 4,
  "act-as-you": 5,
  send: 6,
  "run-code": 7,
  delete: 8,
};

/** The effect a group of actions has as a whole: the most serious one in it. */
export function worstMcpEffect(effects: McpEffectKind[]): McpEffectKind {
  if (effects.length === 0) return "unknown";
  let worst = effects[0];
  for (const effect of effects) {
    if (SEVERITY[effect] > SEVERITY[worst]) worst = effect;
  }
  return worst;
}

/** The first word of `identifier` that names an action, used to split a slug into app and action. */
export function firstActionWordIndex(words: string[]): number {
  return words.findIndex(
    (word) =>
      DELETE_WORDS.has(word) ||
      SEND_WORDS.has(word) ||
      RUN_WORDS.has(word) ||
      CONNECT_WORDS.has(word) ||
      WRITE_WORDS.has(word) ||
      READ_WORDS.has(word) ||
      NOUN_OR_VERB.has(word),
  );
}
