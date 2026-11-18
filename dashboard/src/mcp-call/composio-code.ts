import type { McpStep } from "./mcp-call-types";
import { classifyMcpEffect } from "./mcp-effects";
import { scalarFacts } from "./mcp-input";
import { splitToolSlug } from "./mcp-services";

/**
 * Code sent to Composio's workspace usually calls Composio actions by name:
 * `run_composio_tool('GMAIL_FETCH_EMAILS', {'query': 'riverside', ...})`.
 * Those names say what the code is for in words people know, so the card can
 * show "Get emails in Gmail" instead of asking them to read Python.
 *
 * This reads the text only. It finds the action names and the plain values
 * written next to them; it does not run or fully parse the code, and code can
 * do more than the actions it names. The card says so and keeps the code one
 * click away.
 *
 * The agent writes this code, so nothing it can hide counts: a call inside a
 * comment or a string is not a call, and a value is shown only when the whole
 * value is one plain literal. Anything else is counted as unreadable, and the
 * card says so instead of guessing.
 */
export type ComposioCodeReading = {
  /** Every call whose action name is written out, in order. */
  steps: McpStep[];
  /**
   * Places the code reaches actions in a way Guard cannot name: an action
   * name built at run time, a call function passed around under another
   * name, or code run from text (`exec`, `eval`).
   */
  unreadable: number;
};

const CALL_NAMES = "run_composio_tool|execute_action|tools\\.execute";
// The action name counts only when the whole first argument is that one string.
const CALL = new RegExp(
  `\\b(?:${CALL_NAMES})\\s*\\(\\s*(?:(["'])([A-Za-z][A-Za-z0-9_]{2,119})\\1(?=\\s*[,)]))?`,
  "g",
);
// The call function named without calling it, so it is handed to something else.
const PASSED_AROUND = new RegExp(`\\b(?:${CALL_NAMES})\\b(?!\\s*\\()`, "g");
const RUNS_TEXT = /\b(?:exec|eval|compile|__import__)\s*\(/g;
// `'key':` or `key=` (not `==`).
const KEY = /(["'])([A-Za-z_][A-Za-z0-9_]{0,59})\1\s*:|\b([A-Za-z_][A-Za-z0-9_]{0,59})\s*=(?!=)/g;
// One plain literal that is the whole value: the next thing is a comma or a closing bracket.
const LITERAL =
  /\s*(?:(["'])((?:\\.|(?!\1)[^\\\n]){0,400})\1|(-?\d+(?:\.\d+)?)(?![\w.])|(True|False|None|true|false|null)\b)(?=\s*[,})\]])/y;
const ARG_REACH = 1200;

export function readComposioCode(code: string): ComposioCodeReading {
  const { scan, quoted } = maskPython(code);
  const steps: McpStep[] = [];
  let unreadable = 0;
  for (const match of scan.matchAll(CALL)) {
    const at = match.index ?? 0;
    if (quoted[at] === 1) continue;
    const slug = match[2];
    if (slug === undefined) {
      unreadable += 1;
      continue;
    }
    const start = at + match[0].length;
    const { args, unknown } = literalArguments(scan, quoted, start, callEnd(scan, quoted, start));
    const tool = slug.toUpperCase();
    const { app, action } = splitToolSlug(tool);
    const { facts, hidden } = scalarFacts(args, { max: 4, tool });
    steps.push({
      id: `code-${steps.length}-${slug}`,
      app,
      action,
      effect: classifyMcpEffect(slug),
      details: facts,
      hiddenDetails: hidden + unknown,
    });
  }
  unreadable += countOutsideStrings(scan, quoted, PASSED_AROUND, true) + countOutsideStrings(scan, quoted, RUNS_TEXT, false);
  return { steps, unreadable };
}

/** Matches outside strings. A plain import of the call function is not passing it around. */
function countOutsideStrings(scan: string, quoted: Uint8Array, pattern: RegExp, skipImports: boolean): number {
  let count = 0;
  for (const match of scan.matchAll(pattern)) {
    const at = match.index ?? 0;
    if (quoted[at] === 1) continue;
    if (skipImports && plainImport(scan, at, at + match[0].length)) continue;
    count += 1;
  }
  return count;
}

// `from composio import a, run_composio_tool` or `import run_composio_tool`, with nothing else on the line.
const IMPORT_BEFORE = /^\s*(?:from\s+[\w.]+\s+)?import\s+(?:[\w.]+\s*,\s*)*$/;
// The name is not renamed (`as send`): the line ends, or another plain name follows.
const IMPORT_AFTER = /^\s*(?:,\s*[\w.]+\s*)*$/;

/** Only a one-statement import line that keeps the name as it is. `as send` or `; send = ...` still counts. */
function plainImport(scan: string, start: number, end: number): boolean {
  const lineStart = scan.lastIndexOf("\n", start) + 1;
  const lineEnd = scan.indexOf("\n", end);
  const before = scan.slice(lineStart, start);
  const after = scan.slice(end, lineEnd === -1 ? scan.length : lineEnd);
  return IMPORT_BEFORE.test(before) && IMPORT_AFTER.test(after);
}

/**
 * Python text with every `#` comment blanked to spaces (offsets kept), and a
 * map of which characters sit inside a string literal. A string's opening
 * quote is left unmarked so a quoted key can still start there.
 */
export function maskPython(code: string): { scan: string; quoted: Uint8Array } {
  const quoted = new Uint8Array(code.length);
  const out: string[] = [];
  let at = 0;
  while (at < code.length) {
    const char = code[at];
    if (char === "#") {
      while (at < code.length && code[at] !== "\n") {
        out.push(" ");
        at += 1;
      }
      continue;
    }
    if (char !== "'" && char !== '"') {
      out.push(char);
      at += 1;
      continue;
    }
    const delimiter = code.startsWith(char.repeat(3), at) ? char.repeat(3) : char;
    out.push(delimiter);
    at += delimiter.length;
    while (at < code.length) {
      if (code.startsWith(delimiter, at)) {
        quoted.fill(1, at, at + delimiter.length);
        out.push(delimiter);
        at += delimiter.length;
        break;
      }
      // A one-line string the code never closed ends at the line break.
      if (delimiter.length === 1 && code[at] === "\n") break;
      const width = code[at] === "\\" && at + 1 < code.length ? 2 : 1;
      quoted.fill(1, at, at + width);
      out.push(code.slice(at, at + width));
      at += width;
    }
  }
  return { scan: out.join(""), quoted };
}

/** Where the call's parentheses close, so values written after the call are not read as its inputs. */
function callEnd(scan: string, quoted: Uint8Array, start: number): number {
  const limit = Math.min(scan.length, start + ARG_REACH);
  let depth = 1;
  for (let at = start; at < limit; at += 1) {
    if (quoted[at] === 1) continue;
    if (scan[at] === "(") depth += 1;
    else if (scan[at] === ")") {
      depth -= 1;
      if (depth === 0) return at;
    }
  }
  return limit;
}

/**
 * The plain values written beside an action name. A value built from more
 * than one piece (`'a' + domain`, a variable, an f-string) is not shown, since
 * what runs could differ from any piece of it; it is counted instead. Yes/no
 * switches are settings, not something a person judges, so they stay in the code.
 */
function literalArguments(
  scan: string,
  quoted: Uint8Array,
  from: number,
  to: number,
): { args: Record<string, unknown>; unknown: number } {
  const text = scan.slice(0, to);
  const args: Record<string, unknown> = {};
  let unknown = 0;
  KEY.lastIndex = from;
  for (let match = KEY.exec(text); match !== null; match = KEY.exec(text)) {
    const key = match[2] ?? match[3];
    if (key === undefined || quoted[match.index] === 1 || key in args) continue;
    LITERAL.lastIndex = match.index + match[0].length;
    const value = LITERAL.exec(text);
    if (value === null) unknown += 1;
    else if (value[2] !== undefined) args[key] = value[2].replace(/\\(["'\\])/g, "$1");
    else if (value[3] !== undefined) args[key] = Number(value[3]);
  }
  return { args, unknown };
}
