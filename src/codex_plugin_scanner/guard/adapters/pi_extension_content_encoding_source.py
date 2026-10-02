"""Generated Pi content-review helper source."""

# ruff: noqa: E501

from __future__ import annotations

CONTENT_ENCODING_HELPERS_SOURCE = r"""type OutputDigest = {
  sha256: string | null;
  chars: number;
  textForExcerpt: string;
  excerptTruncated: boolean;
  traversalTruncated: boolean;
};

function legacyDigestOutputText(value: unknown): OutputDigest {
  const hash = createHash('sha256');
  let chars = 0;
  let textForExcerpt = '';
  let excerptTruncated = false;
  let traversalTruncated = false;
  const seen = new WeakSet<object>();
  function update(text: string): void {
    hash.update(text, 'utf8');
    chars += text.length;
    if (textForExcerpt.length < GUARD_TEXT_LIMIT_CHARS) {
      const remaining = GUARD_TEXT_LIMIT_CHARS - textForExcerpt.length;
      if (text.length <= remaining) {
        textForExcerpt += text;
      } else {
        textForExcerpt += text.slice(0, remaining);
        excerptTruncated = true;
      }
    }
    if (chars > GUARD_SOURCE_REF_MAX_OUTPUT_CHARS) {
      traversalTruncated = true;
    }
  }
  function traverse(val: unknown, depth: number): void {
    if (traversalTruncated) return;
    if (typeof val === 'string') { update(val); return; }
    if (val === undefined || val === null) return;
    if (typeof val === 'number' || typeof val === 'boolean') return;
    if (typeof val === 'bigint') { update(val.toString()); return; }
    if (typeof val !== 'object') { traversalTruncated = true; return; }
    const obj = val as object;
    if (seen.has(obj)) { traversalTruncated = true; return; }
    if (depth > GUARD_MAX_DEPTH) { traversalTruncated = true; return; }
    seen.add(obj);
    if (Array.isArray(val)) {
      if (val.length > GUARD_CONTENT_ITEM_LIMIT) { traversalTruncated = true; return; }
      for (const item of val) { if (traversalTruncated) return; traverse(item, depth + 1); }
      return;
    }
    const record = val as Record<string, unknown>;
    // Match collectOutputText: only extract text from {type: "text", text: ...}
    // objects, not from metadata keys like "type".
    if (record.type === 'text' && typeof record.text === 'string') {
      update(record.text);
      return;
    }
    let keyCount = 0;
    for (const key of OUTPUT_TEXT_KEYS) {
      if (!(key in record)) continue;
      if (keyCount >= GUARD_OBJECT_KEY_LIMIT) { traversalTruncated = true; return; }
      keyCount++;
      if (traversalTruncated) return;
      traverse(record[key], depth + 1);
    }
  }
  try {
    traverse(value, 0);
  } catch {
    traversalTruncated = true;
  }
  return {
    sha256: traversalTruncated ? null : hash.digest('hex'),
    chars,
    textForExcerpt,
    excerptTruncated,
    traversalTruncated,
  };
}

function structuredOutputJsonForPostToolUse(value: unknown, deadlineAt?: number): string | null {
  let nodeCount = 0;
  let keyCount = 0;
  const seen = new WeakSet<object>();
  const deadlineExceeded = (): boolean => deadlineAt !== undefined && Date.now() >= deadlineAt;
  const checkDeadline = (): void => {
    if (deadlineExceeded()) throw new Error('structured output deadline exceeded');
  };
  function hasUnpairedSurrogate(text: string): boolean {
    checkDeadline();
    for (let index = 0; index < text.length; index += 1) {
      if ((index & 0x3ff) === 0) checkDeadline();
      const code = text.charCodeAt(index);
      if (code >= 0xd800 && code <= 0xdbff) {
        const next = text.charCodeAt(index + 1);
        if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
        index += 1;
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        return true;
      }
    }
    return false;
  }
  function canonicalize(item: unknown, depth: number): unknown {
    checkDeadline();
    nodeCount += 1;
    if (nodeCount > GUARD_STRUCTURED_MAX_NODES || depth > GUARD_STRUCTURED_MAX_DEPTH) {
      throw new Error('structured output bounds exceeded');
    }
    if (typeof item === 'string') {
      if (hasUnpairedSurrogate(item)) throw new Error('structured output unicode is invalid');
      if (item.length > GUARD_STRUCTURED_MAX_BYTES || Buffer.byteLength(item, 'utf8') > GUARD_STRUCTURED_MAX_BYTES) {
        throw new Error('structured output string bounds exceeded');
      }
      checkDeadline();
      return item;
    }
    if (item === null || typeof item === 'boolean') return item;
    if (typeof item === 'number') {
      if (!Number.isFinite(item) || !Number.isSafeInteger(item)) {
        throw new Error('structured output number is unsupported');
      }
      return item;
    }
    if (typeof item !== 'object' || Array.isArray(item)) {
      throw new Error('structured output value is unsupported');
    }
    const record = item as Record<string, unknown>;
    const prototype = Object.getPrototypeOf(record);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error('structured output object prototype is unsupported');
    }
    if (Object.getOwnPropertySymbols(record).length > 0) {
      throw new Error('structured output symbols are unsupported');
    }
    if (seen.has(record)) throw new Error('structured output cycle');
    seen.add(record);
    try {
      const keys = Object.keys(record);
      keyCount += keys.length;
      if (keyCount > GUARD_STRUCTURED_MAX_FIELDS) {
        throw new Error('structured output field bounds exceeded');
      }
      let keyBytes = 0;
      for (const key of keys) {
        checkDeadline();
        if (hasUnpairedSurrogate(key)) throw new Error('structured output key unicode is invalid');
        keyBytes += Buffer.byteLength(key, 'utf8');
        if (keyBytes > GUARD_STRUCTURED_MAX_BYTES) throw new Error('structured output key bounds exceeded');
      }
      checkDeadline();
      keys.sort();
      checkDeadline();
      const normalized = Object.create(null) as Record<string, unknown>;
      for (const key of keys) {
        normalized[key] = canonicalize(record[key], depth + 1);
      }
      checkDeadline();
      return normalized;
    } finally {
      seen.delete(record);
    }
  }
  function canonicalStringify(item: unknown): string {
    checkDeadline();
    if (item === null || typeof item !== 'object') {
      const serialized = JSON.stringify(item);
      if (typeof serialized !== 'string') throw new Error('structured output value is unsupported');
      return serialized;
    }
    if (Array.isArray(item)) {
      return `[${item.map((entry) => canonicalStringify(entry)).join(',')}]`;
    }
    const record = item as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    const entries: string[] = [];
    for (const key of keys) {
      checkDeadline();
      entries.push(`${JSON.stringify(key)}:${canonicalStringify(record[key])}`);
    }
    return `{${entries.join(',')}}`;
  }
  try {
    // The host contract is ToolResultEvent.content: an array of content
    // blocks.  This adapter intentionally accepts one closed text envelope
    // carrying a canonical JSON object.  Every wrapper key is checked, so an
    // image, a second block, or unknown metadata is withheld instead of being
    // silently dropped before the model-visible receiver proof.
    if (!Array.isArray(value) || value.length !== 1) return null;
    const block = value[0];
    if (block === null || typeof block !== 'object' || Array.isArray(block)) return null;
    const blockRecord = block as Record<string, unknown>;
    const blockPrototype = Object.getPrototypeOf(blockRecord);
    if (blockPrototype !== Object.prototype && blockPrototype !== null) return null;
    // Host object symbol/key enumeration is a native operation that this
    // adapter cannot preempt. Unknown metadata remains fail-closed; the
    // checks below validate the complete ordinary-object shape after that
    // host input boundary and do not claim to bound malicious proxies.
    if (Object.getOwnPropertySymbols(blockRecord).length > 0) return null;
    checkDeadline();
    const blockKeys = Object.keys(blockRecord);
    if (blockKeys.length !== 2) return null;
    let blockKeyBytes = 0;
    for (const key of blockKeys) {
      checkDeadline();
      if (hasUnpairedSurrogate(key)) return null;
      blockKeyBytes += Buffer.byteLength(key, 'utf8');
      if (blockKeyBytes > GUARD_STRUCTURED_MAX_BYTES) return null;
    }
    checkDeadline();
    blockKeys.sort();
    checkDeadline();
    if (blockKeys[0] !== 'text' || blockKeys[1] !== 'type') return null;
    if (blockRecord.type !== 'text' || typeof blockRecord.text !== 'string') return null;
    const structuredText = blockRecord.text;
    if (structuredText.length > GUARD_STRUCTURED_MAX_BYTES) return null;
    checkDeadline();
    if (Buffer.byteLength(structuredText, 'utf8') > GUARD_STRUCTURED_MAX_BYTES) return null;
    checkDeadline();
    const parsed = JSON.parse(structuredText) as unknown;
    checkDeadline();
    const normalized = canonicalize(parsed, 0);
    checkDeadline();
    const serialized = canonicalStringify(normalized);
    checkDeadline();
    if (typeof serialized !== 'string' || serialized !== structuredText || serialized.includes('\\')) return null;
    if (Buffer.byteLength(serialized, 'utf8') > GUARD_STRUCTURED_MAX_BYTES) return null;
    checkDeadline();
    return serialized;
  } catch {
    return null;
  }
}

function sourcePathFromToolInput(toolInput: Record<string, unknown>): string | null {
  for (const key of ['file_path', 'filePath', 'path', 'file', 'filename']) {
    const value = toolInput[key];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return null;
}

function isVirtualSourcePath(path: string): boolean {
  if (/^[A-Za-z]:[\\/]/.test(path)) return false;
  return /^[A-Za-z][A-Za-z0-9+.-]*:/.test(path);
}

function sourceFileRefForPostToolUse(
  event: Record<string, unknown>,
  toolInput: Record<string, unknown>,
  digest: OutputDigest,
): { version: number; kind: string; path: string; tool_input_path: string; output_sha256: string; output_chars: number } | null {
  const toolName = typeof event.toolName === 'string' ? event.toolName : '';
  if (!GUARD_SOURCE_REF_ALLOWED_TOOL_NAMES.has(toolName)) return null;
  if (!digest.sha256 || digest.traversalTruncated) return null;
  if (digest.chars > GUARD_SOURCE_REF_MAX_OUTPUT_CHARS) return null;
  const path = sourcePathFromToolInput(toolInput);
  // The daemon independently resolves, validates, and re-reads this path
  // before it can return the original output. Absolute paths are common in
  // Pi Read calls and must retain that provenance rather than fall back to
  // context-free output scanning.
  if (!path || isVirtualSourcePath(path)) return null;
  return {
    version: 1,
    kind: 'source_file',
    path,
    tool_input_path: path,
    output_sha256: digest.sha256,
    output_chars: digest.chars,
  };
}

type BoundedValue = { value: unknown; truncated: boolean };
const OUTPUT_TEXT_KEYS = ["stdout", "stderr", "output", "content", "result", "message", "text"] as const;

function truncateText(value: string, limit = GUARD_TEXT_LIMIT_CHARS): string {
  if (value.length <= limit) return value;
  return `${value.slice(0, Math.max(limit, 0))}\n...[truncated by HOL Guard]...`;
}

function legacyBoundValue(value: unknown, depth = 0, seen = new WeakSet<object>()): BoundedValue {
  if (typeof value === 'string') {
    if (value.length <= GUARD_TEXT_LIMIT_CHARS) {
      return { value, truncated: false };
    }
    return { value: truncateText(value), truncated: true };
  }
  if (value === undefined) return { value: undefined, truncated: false };
  if (typeof value === 'bigint') return { value: value.toString(), truncated: false };
  if (
    value === null ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return { value, truncated: false };
  }
  if (typeof value !== 'object') {
    return { value: String(value), truncated: true };
  }
  const objectValue = value as object;
  if (seen.has(objectValue)) {
    return { value: '[cycle omitted by HOL Guard]', truncated: true };
  }
  if (depth > GUARD_MAX_DEPTH) {
    return { value: '[deep object omitted by HOL Guard]', truncated: true };
  }
  seen.add(objectValue);
  try {
    if (Array.isArray(value)) {
      const truncated = value.length > GUARD_CONTENT_ITEM_LIMIT;
      const items = value.slice(0, GUARD_CONTENT_ITEM_LIMIT);
      const nextItems: unknown[] = [];
      let childTruncated = truncated;
      for (const item of items) {
        const next = legacyBoundValue(item, depth + 1, seen);
        nextItems.push(next.value);
        childTruncated = childTruncated || next.truncated;
      }
      return { value: nextItems, truncated: childTruncated };
    }
    const record = value as Record<string, unknown>;
    const nextRecord: Record<string, unknown> = {};
    let truncated = false;
    let keyCount = 0;
    for (const key in record) {
      if (!Object.prototype.hasOwnProperty.call(record, key)) continue;
      if (keyCount >= GUARD_OBJECT_KEY_LIMIT) {
        truncated = true;
        break;
      }
      keyCount += 1;
      const entryValue = record[key];
      const next = legacyBoundValue(entryValue, depth + 1, seen);
      nextRecord[key] = next.value;
      truncated = truncated || next.truncated;
    }
    return { value: nextRecord, truncated };
  } finally {
    seen.delete(objectValue);
  }
}

"""
