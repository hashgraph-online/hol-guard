/**
 * The subset of Markdown that Guard's release notes are written in, parsed
 * into a typed tree.
 *
 * hol.org publishes release notes as the Markdown a maintainer wrote, so the
 * archive has to render headings, lists, links and code to be readable at all.
 * It does that without a Markdown library and without ever producing HTML: the
 * parser emits data, the renderer emits React elements, and nothing in the
 * path can turn upstream bytes into markup. Anything this grammar does not
 * recognise survives as its own literal text rather than disappearing.
 *
 * The daemon has already bounded the response, but these notes are still the
 * one place where another origin's prose reaches the screen, so the parser
 * scans characters instead of backtracking through regular expressions and
 * stops at the limits below rather than trusting the input to be small.
 */

const MAX_SOURCE_CHARS = 64_000;
const MAX_BLOCKS = 1_000;
const MAX_LIST_ITEMS = 500;
const MAX_INLINE_NODES = 400;
const MAX_HREF_CHARS = 2_000;
/** Lists nest one level. Deeper bullets flatten into their parent. */
const MAX_LIST_DEPTH = 2;

export type ReleaseInline =
  | { kind: "text"; text: string }
  | { kind: "code"; text: string }
  | { kind: "break" }
  | { kind: "strong"; children: ReleaseInline[] }
  | { kind: "emphasis"; children: ReleaseInline[] }
  | { kind: "link"; href: string; children: ReleaseInline[] };

export type ReleaseListItem = {
  children: ReleaseInline[];
  items: ReleaseListItem[];
};

export type ReleaseBlock =
  | { kind: "heading"; level: 1 | 2 | 3; children: ReleaseInline[] }
  | { kind: "paragraph"; children: ReleaseInline[] }
  | { kind: "quote"; children: ReleaseInline[] }
  | { kind: "list"; ordered: boolean; items: ReleaseListItem[] }
  | { kind: "code"; language: string | null; text: string }
  | { kind: "rule" };

/**
 * Only a web link survives as a link. `javascript:`, `data:` and every other
 * scheme keeps its text and loses its href, so a reader still sees what was
 * written and cannot click it.
 */
export function safeHref(raw: string): string | null {
  const href = raw.trim();
  if (!href || href.length > MAX_HREF_CHARS) return null;
  if (/[\u0000-\u001f\u007f\s]/.test(href)) return null;
  const lower = href.toLowerCase();
  if (!lower.startsWith("https://") && !lower.startsWith("http://")) return null;
  return href;
}

function pushText(nodes: ReleaseInline[], text: string): void {
  if (!text) return;
  const last = nodes[nodes.length - 1];
  if (last && last.kind === "text") {
    last.text += text;
    return;
  }
  nodes.push({ kind: "text", text });
}

/** How far a run of `marker` extends from `start`, capped at `max`. */
function runLength(source: string, start: number, marker: string, max: number): number {
  let length = 0;
  while (length < max && source[start + length] === marker) length += 1;
  return length;
}

/**
 * How far failed lookaheads may scan before every remaining marker is treated
 * as literal text. A closer that is never found costs a scan of the rest of
 * the line, and an input of nothing but openers would pay that for each one,
 * so the budget keeps a hostile note linear instead of quadratic.
 */
type ScanBudget = { left: number };

function scanBudgetFor(source: string): ScanBudget {
  return { left: source.length * 4 + 1_000 };
}

/** `indexOf` that charges what it scanned and gives up once the budget is spent. */
function findWithin(source: string, token: string, from: number, budget: ScanBudget): number {
  if (budget.left <= 0) return -1;
  const found = source.indexOf(token, from);
  const scanned = (found === -1 ? source.length : found + token.length) - from;
  budget.left -= Math.max(scanned, 1);
  return budget.left < 0 ? -1 : found;
}

const WORD_CHARACTER = /[\p{L}\p{N}]/u;

function isWordCharacter(source: string, position: number): boolean {
  if (position < 0 || position >= source.length) return false;
  return WORD_CHARACTER.test(source[position]);
}

/**
 * Where an underscore run may open or close emphasis. CommonMark does not let
 * `_` do either inside a word, so `HOL_GUARD_HOME` and `guard_daemon` keep
 * every underscore a maintainer typed instead of italicising the middle.
 */
function underscoreOpens(source: string, start: number): boolean {
  return !isWordCharacter(source, start - 1);
}

function underscoreCloses(source: string, end: number): boolean {
  return !isWordCharacter(source, end);
}

/**
 * Inline Markdown, scanned left to right. An opener with no closer is not a
 * marker at all: it stays in the text exactly as written.
 */
function parseInline(source: string, depth = 0, budget: ScanBudget = scanBudgetFor(source)): ReleaseInline[] {
  const nodes: ReleaseInline[] = [];
  let index = 0;
  let plain = "";
  const flush = () => {
    pushText(nodes, plain);
    plain = "";
  };
  while (index < source.length) {
    if (nodes.length >= MAX_INLINE_NODES) {
      plain += source.slice(index);
      break;
    }
    const char = source[index];

    if (char === "\n") {
      flush();
      nodes.push({ kind: "break" });
      index += 1;
      continue;
    }

    if (char === "\\" && index + 1 < source.length && /[\\`*_[\]()#>~]/.test(source[index + 1])) {
      plain += source[index + 1];
      index += 2;
      continue;
    }

    if (char === "`") {
      const fence = runLength(source, index, "`", 3);
      const close = findWithin(source, "`".repeat(fence), index + fence, budget);
      if (close !== -1) {
        flush();
        nodes.push({ kind: "code", text: source.slice(index + fence, close).trim() });
        index = close + fence;
        continue;
      }
    }

    if (char === "[" && depth < 3) {
      const link = readLink(source, index, depth, budget);
      if (link) {
        flush();
        nodes.push(link.node);
        index = link.next;
        continue;
      }
    }

    if ((char === "*" || char === "_") && depth < 3) {
      const marker = runLength(source, index, char, 2);
      const token = char.repeat(marker);
      // An underscore inside a word belongs to the word, so skip past any
      // closer that would italicise the middle of an identifier.
      let close = -1;
      if (char !== "_" || underscoreOpens(source, index)) {
        let from = index + marker;
        while (from < source.length) {
          const candidate = findWithin(source, token, from, budget);
          if (candidate === -1) break;
          if (char !== "_" || underscoreCloses(source, candidate + marker)) {
            close = candidate;
            break;
          }
          from = candidate + marker;
        }
      }
      // `**` with nothing between it is literal, not empty emphasis.
      if (close !== -1 && close > index + marker) {
        const inner = source.slice(index + marker, close);
        flush();
        nodes.push(
          marker === 2
            ? { kind: "strong", children: parseInline(inner, depth + 1, budget) }
            : { kind: "emphasis", children: parseInline(inner, depth + 1, budget) },
        );
        index = close + marker;
        continue;
      }
    }

    if (char === "h" && source.startsWith("http", index)) {
      const bare = readBareUrl(source, index, budget);
      if (bare) {
        flush();
        nodes.push(bare.node);
        index = bare.next;
        continue;
      }
    }

    plain += char;
    index += 1;
  }
  flush();
  return nodes;
}

/** `[label](href)`, with one level of balanced parentheses in the href so a
 * GitHub compare link does not end at its own bracket. */
function readLink(
  source: string,
  start: number,
  depth: number,
  budget: ScanBudget,
): { node: ReleaseInline; next: number } | null {
  if (budget.left <= 0) return null;
  let cursor = start + 1;
  let open = 1;
  while (cursor < source.length && open > 0) {
    budget.left -= 1;
    if (budget.left < 0) return null;
    const char = source[cursor];
    if (char === "\\") {
      cursor += 2;
      continue;
    }
    if (char === "[") open += 1;
    if (char === "]") open -= 1;
    cursor += 1;
  }
  if (open !== 0 || source[cursor] !== "(") return null;
  const labelEnd = cursor - 1;
  let hrefCursor = cursor + 1;
  let parens = 1;
  while (hrefCursor < source.length && parens > 0) {
    budget.left -= 1;
    if (budget.left < 0) return null;
    const char = source[hrefCursor];
    if (char === "(") parens += 1;
    if (char === ")") parens -= 1;
    if (parens === 0) break;
    hrefCursor += 1;
  }
  if (parens !== 0) return null;
  const label = source.slice(start + 1, labelEnd);
  const href = safeHref(source.slice(cursor + 1, hrefCursor));
  const children = parseInline(label, depth + 1, budget);
  return {
    node: href ? { kind: "link", href, children } : { kind: "emphasis", children },
    next: hrefCursor + 1,
  };
}

/** A URL written on its own, not inside brackets. Trailing sentence
 * punctuation belongs to the sentence, not to the link. */
function readBareUrl(
  source: string,
  start: number,
  budget: ScanBudget,
): { node: ReleaseInline; next: number } | null {
  if (budget.left <= 0) return null;
  let end = start;
  while (end < source.length && !/[\s<>"'`)\]]/.test(source[end])) end += 1;
  budget.left -= end - start;
  while (end > start && /[.,;:!?]/.test(source[end - 1])) end -= 1;
  const href = safeHref(source.slice(start, end));
  if (!href) return null;
  return { node: { kind: "link", href, children: [{ kind: "text", text: href }] }, next: end };
}

/**
 * Whether this line starts a block of its own rather than continuing the text
 * above it. A heading or a fence written straight under a paragraph or a
 * bullet is still its own block, and never part of what came before.
 */
function startsBlock(line: string): boolean {
  return (
    /^(#{1,6})\s+/.test(line) ||
    /^\s*(?:`{3,}|~{3,})/.test(line) ||
    /^\s*>\s?/.test(line) ||
    /^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/.test(line)
  );
}

function listMarker(line: string): { ordered: boolean; indent: number; text: string } | null {
  const match = /^(\s*)(?:([-*+])|(\d{1,3})[.)])\s+(.*)$/.exec(line);
  if (!match) return null;
  return { ordered: match[3] !== undefined, indent: match[1].length, text: match[4] };
}

/**
 * Parse one release's notes. A single newline inside a paragraph is a line
 * break, the way the release pages these notes come from render it.
 */
export function parseReleaseMarkdown(source: string): ReleaseBlock[] {
  const text = source.length > MAX_SOURCE_CHARS ? source.slice(0, MAX_SOURCE_CHARS) : source;
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  const blocks: ReleaseBlock[] = [];
  let index = 0;

  const atLimit = () => blocks.length >= MAX_BLOCKS;

  while (index < lines.length && !atLimit()) {
    const line = lines[index];
    if (!line.trim()) {
      index += 1;
      continue;
    }

    const fence = /^\s*(`{3,}|~{3,})\s*([A-Za-z0-9_+-]{0,20})\s*$/.exec(line);
    if (fence) {
      const token = fence[1][0].repeat(3);
      const body: string[] = [];
      index += 1;
      while (index < lines.length && !lines[index].trimStart().startsWith(token)) {
        body.push(lines[index]);
        index += 1;
      }
      if (index < lines.length) index += 1;
      blocks.push({ kind: "code", language: fence[2] || null, text: body.join("\n") });
      continue;
    }

    if (/^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
      blocks.push({ kind: "rule" });
      index += 1;
      continue;
    }

    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      // Three visible ranks is all this panel has room for, and the headings
      // sit under the panel's own, so the document outline stays in order.
      const level = Math.min(3, heading[1].length) as 1 | 2 | 3;
      blocks.push({ kind: "heading", level, children: parseInline(heading[2].trim()) });
      index += 1;
      continue;
    }

    if (/^\s*>\s?/.test(line)) {
      const quoted: string[] = [];
      while (index < lines.length && /^\s*>\s?/.test(lines[index])) {
        quoted.push(lines[index].replace(/^\s*>\s?/, ""));
        index += 1;
      }
      blocks.push({ kind: "quote", children: parseInline(quoted.join("\n").trim()) });
      continue;
    }

    const marker = listMarker(line);
    if (marker) {
      const result = readList(lines, index);
      blocks.push(result.block);
      index = result.next;
      continue;
    }

    // The opening line is always consumed, even when it looks like a block
    // start the stricter matchers above rejected — a fence with an info string
    // this grammar does not take, say. Without that the parser would stand
    // still on the line and emit empty paragraphs for the rest of the notes.
    const paragraph: string[] = [lines[index].trim()];
    index += 1;
    while (
      index < lines.length &&
      lines[index].trim() &&
      !listMarker(lines[index]) &&
      !startsBlock(lines[index])
    ) {
      paragraph.push(lines[index].trim());
      index += 1;
    }
    blocks.push({ kind: "paragraph", children: parseInline(paragraph.join("\n")) });
  }

  return blocks;
}

function readList(lines: string[], start: number, depth = 0): { block: ReleaseBlock; next: number } {
  const first = listMarker(lines[start]);
  const ordered = first ? first.ordered : false;
  const baseIndent = first ? first.indent : 0;
  const items: ReleaseListItem[] = [];
  let index = start;

  while (index < lines.length && items.length < MAX_LIST_ITEMS) {
    const line = lines[index];
    if (!line.trim()) {
      // A blank line ends the list unless another bullet follows it.
      const next = lines[index + 1];
      if (!next || !listMarker(next)) break;
      index += 1;
      continue;
    }
    const marker = listMarker(line);
    if (!marker || marker.indent < baseIndent || marker.ordered !== ordered) break;

    if (marker.indent > baseIndent) {
      const parent = items[items.length - 1];
      const nested = readList(lines, index, depth + 1);
      if (parent && nested.block.kind === "list") {
        // Deeper than the panel renders: the bullets join their grandparent.
        parent.items.push(...nested.block.items);
        if (parent.items.length > MAX_LIST_ITEMS) parent.items.length = MAX_LIST_ITEMS;
      } else if (nested.block.kind === "list") {
        items.push(...nested.block.items);
        if (items.length > MAX_LIST_ITEMS) items.length = MAX_LIST_ITEMS;
      }
      index = nested.next;
      continue;
    }

    const lead: string[] = [marker.text];
    index += 1;
    // A wrapped bullet continues on an indented line that starts no new item.
    while (
      index < lines.length &&
      lines[index].trim() &&
      !listMarker(lines[index]) &&
      !startsBlock(lines[index])
    ) {
      lead.push(lines[index].trim());
      index += 1;
    }
    items.push({ children: parseInline(lead.join("\n")), items: [] });
  }

  // Past the depth this panel renders, a bullet and everything under it sit at
  // the same level: indentation stops growing rather than running off-screen.
  if (depth + 1 >= MAX_LIST_DEPTH) {
    const flattened: ReleaseListItem[] = [];
    const collect = (source: readonly ReleaseListItem[]): void => {
      for (const item of source) {
        if (flattened.length >= MAX_LIST_ITEMS) return;
        flattened.push({ children: item.children, items: [] });
        collect(item.items);
      }
    };
    collect(items);
    return { block: { kind: "list", ordered, items: flattened }, next: index };
  }
  return { block: { kind: "list", ordered, items }, next: index };
}

/** Plain text for a summary line, with the markup removed rather than shown. */
export function releaseMarkdownToText(source: string): string {
  const flatten = (nodes: readonly ReleaseInline[]): string =>
    nodes
      .map((node) => {
        switch (node.kind) {
          case "text":
          case "code":
            return node.text;
          case "break":
            return " ";
          default:
            return flatten(node.children);
        }
      })
      .join("");
  return parseReleaseMarkdown(source)
    .map((block) => {
      switch (block.kind) {
        case "heading":
        case "paragraph":
        case "quote":
          return flatten(block.children);
        case "list":
          return block.items.map((item) => flatten(item.children)).join(" ");
        case "code":
          return block.text;
        case "rule":
          return "";
      }
    })
    .filter(Boolean)
    .join(" ")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * The same grammar over a single run of text, for the places that render one
 * line inside a list item rather than a document.
 */
export function parseReleaseInline(source: string): ReleaseInline[] {
  return parseInline(source.slice(0, MAX_SOURCE_CHARS).replace(/\r\n?/g, "\n").trim());
}
