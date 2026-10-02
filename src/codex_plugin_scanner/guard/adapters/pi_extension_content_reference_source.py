"""Generated Pi content-review helper source."""

# ruff: noqa: E501

from __future__ import annotations

CONTENT_REFERENCE_HELPERS_SOURCE = r"""function appendBoundedText(accumulator: { text: string; truncated: boolean }, value: string): void {
  if (accumulator.truncated || value.length === 0) return;
  const prefix = accumulator.text ? "\n" : "";
  const available = GUARD_TEXT_LIMIT_CHARS - accumulator.text.length - prefix.length;
  if (available <= 0) {
    accumulator.truncated = true;
    return;
  }
  if (value.length > available) {
    accumulator.text += `${prefix}${value.slice(0, available)}`;
    accumulator.truncated = true;
    return;
  }
  accumulator.text += `${prefix}${value}`;
}

function collectOutputText(
  value: unknown,
  accumulator: { text: string; truncated: boolean; itemCount: number },
  depth = 0,
  seen = new WeakSet<object>(),
): void {
  if (accumulator.truncated) return;
  if (typeof value === 'string') {
    appendBoundedText(accumulator, value);
    return;
  }
  if (typeof value === 'bigint') {
    appendBoundedText(accumulator, value.toString());
    return;
  }
  if (
    value === undefined ||
    value === null ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return;
  }
  if (typeof value !== 'object') {
    accumulator.truncated = true;
    return;
  }
  const objectValue = value as object;
  if (seen.has(objectValue) || depth > GUARD_MAX_DEPTH) {
    accumulator.truncated = true;
    return;
  }
  seen.add(objectValue);
  try {
    if (Array.isArray(value)) {
      const arrayItems = value as unknown[];
      for (const item of arrayItems) {
        if (accumulator.itemCount >= GUARD_CONTENT_ITEM_LIMIT) {
          accumulator.truncated = true;
          break;
        }
        accumulator.itemCount += 1;
        collectOutputText(item, accumulator, depth + 1, seen);
        if (accumulator.truncated) break;
      }
      if (arrayItems.length > GUARD_CONTENT_ITEM_LIMIT) accumulator.truncated = true;
      return;
    }
    const record = value as Record<string, unknown>;
    if (record.type === 'text' && typeof record.text === 'string') {
      appendBoundedText(accumulator, record.text);
      return;
    }
    for (const key of OUTPUT_TEXT_KEYS) {
      if (!(key in record)) continue;
      collectOutputText(record[key], accumulator, depth + 1, seen);
      if (accumulator.truncated) break;
    }
  } finally {
    seen.delete(objectValue);
  }
}

function legacyBoundedOutputText(value: unknown): BoundedValue {
  const accumulator = { text: '', truncated: false, itemCount: 0 };
  collectOutputText(value, accumulator);
  return { value: accumulator.text, truncated: accumulator.truncated };
}

function toolCallIdKey(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function base64Url(value: Buffer): string {
  return value.toString('base64url');
}

function encryptedPayload(serializedPayload: string) {
  const key = randomBytes(32);
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const ciphertext = Buffer.concat([
    cipher.update(serializedPayload, 'utf8'),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  return { ciphertext, key: base64Url(key), nonce: base64Url(nonce) };
}

function referencedPayload(payload: Record<string, unknown>, serializedPayload: string) {
  const directory = mkdtempSync(join(tmpdir(), 'hol-guard-hook-payload-'));
  try { chmodSync(directory, 0o700); } catch {}
  const path = join(directory, 'payload.json');
  const encrypted = encryptedPayload(serializedPayload);
  writeFileSync(path, encrypted.ciphertext, { mode: 0o600 });
  const sha256 = createHash('sha256').update(encrypted.ciphertext).digest('hex');
  const referencePayload: Record<string, unknown> = {
    hook_event_name: payload.hook_event_name,
    config_path: payload.config_path,
    tool_name: payload.tool_name,
    is_error: payload.is_error,
    ...(typeof payload.structured_output_json === 'string'
      ? { structured_output_json: payload.structured_output_json }
      : {}),
    guard_payload_ref: {
      version: 1,
      path,
      sha256,
      encoding: 'json',
      encryption: 'aes-256-gcm',
      key: encrypted.key,
      nonce: encrypted.nonce,
      serialized_chars: serializedPayload.length,
    },
  };
  return {
    payload: referencePayload,
    cleanup: () => { try { rmSync(directory, { recursive: true, force: true }); } catch {} },
  };
}

/* HOL Guard bounded preprocessing begins */
type TraversalBudget = {
  deadlineAt?: number;
  nodes: number;
  exhausted: boolean;
  maxNodes?: number;
};
type BoundedCodePointPrefix = { text: string; chars: number; complete: boolean };

const GUARD_PREPROCESS_MAX_NODES = 256;
// The native reference resolver caps ciphertext at 5 MiB; AES-GCM appends a 16-byte tag.
const GUARD_MAX_REFERENCE_JSON_BYTES = 5 * 1024 * 1024 - 16;
// Shape preflight has a separate finite cap from display traversal limits. It
// remains large enough for ordinary reference payloads while bounding a
// helper call that does not receive a deadline.
const GUARD_MAX_REFERENCE_JSON_NODES = 100_000;

function createTraversalBudget(deadlineAt?: number): TraversalBudget {
  return { deadlineAt, nodes: 0, exhausted: false };
}

function traversalBudgetReady(budget: TraversalBudget): boolean {
  if (budget.exhausted) return false;
  if (budget.deadlineAt !== undefined && Date.now() >= budget.deadlineAt) {
    budget.exhausted = true;
    return false;
  }
  return true;
}

function consumeTraversalNode(budget: TraversalBudget): boolean {
  if (!traversalBudgetReady(budget)) return false;
  budget.nodes += 1;
  if (budget.nodes > (budget.maxNodes ?? GUARD_PREPROCESS_MAX_NODES)) {
    budget.exhausted = true;
    return false;
  }
  return true;
}

function boundedCodePointPrefix(
  value: string,
  limit: number,
  budget: TraversalBudget,
  limitKind: 'code_points' | 'code_units' = 'code_points',
): BoundedCodePointPrefix {
  const max = Math.max(limit, 0);
  let index = 0;
  let chars = 0;
  while (index < value.length && (limitKind === 'code_units' ? index : chars) < max) {
    if ((chars & 0x3ff) === 0 && !traversalBudgetReady(budget)) {
      return { text: value.slice(0, index), chars, complete: false };
    }
    const code = value.charCodeAt(index);
    let width = 1;
    if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) width = 2;
    }
    if (limitKind === 'code_units' && index + width > max) break;
    index += width;
    chars += 1;
  }
  if (!traversalBudgetReady(budget)) {
    return { text: value.slice(0, index), chars, complete: false };
  }
  return { text: value.slice(0, index), chars, complete: index >= value.length };
}

function appendSafeExcerpt(
  accumulator: { text: string; truncated: boolean },
  value: string,
  budget: TraversalBudget,
): void {
  if (accumulator.truncated || value.length === 0) return;
  if (!traversalBudgetReady(budget)) {
    accumulator.truncated = true;
    return;
  }
  const prefix = accumulator.text ? "\n" : "";
  const available = GUARD_TEXT_LIMIT_CHARS - accumulator.text.length - prefix.length;
  if (available <= 0) {
    accumulator.truncated = true;
    return;
  }
  if (value.length <= available) {
    accumulator.text += `${prefix}${value}`;
    return;
  }
  const bounded = boundedCodePointPrefix(value, available, budget, 'code_units');
  accumulator.text += `${prefix}${bounded.text}`;
  accumulator.truncated = true;
}

function safeTruncateText(
  value: string,
  limit = GUARD_TEXT_LIMIT_CHARS,
  budget: TraversalBudget = createTraversalBudget(),
): string {
  if (value.length <= limit && traversalBudgetReady(budget)) return value;
  const bounded = boundedCodePointPrefix(value, limit, budget, 'code_units');
  return `${bounded.text}\n...[truncated by HOL Guard]...`;
}

function digestOutputText(
  value: unknown,
  deadlineAt?: number,
  budget = createTraversalBudget(deadlineAt),
): OutputDigest {
  const hash = createHash('sha256');
  let chars = 0;
  let textForExcerpt = '';
  let excerptTruncated = false;
  let traversalTruncated = false;
  const seen = new WeakSet<object>();
  const excerpt = { text: '', truncated: false };
  const refuse = (): void => {
    traversalTruncated = true;
  };
  function update(text: string): void {
    if (traversalTruncated || !traversalBudgetReady(budget)) {
      refuse();
      return;
    }
    // Reject before hashing or counting an uncapped string.  Only the small
    // excerpt prefix is inspected, so a hostile single string cannot force a
    // full code-point array or an unbounded hash operation.
    if (text.length > GUARD_SOURCE_REF_MAX_OUTPUT_CHARS) {
      appendSafeExcerpt(excerpt, text, budget);
      excerptTruncated = true;
      refuse();
      return;
    }
    const bounded = boundedCodePointPrefix(text, GUARD_SOURCE_REF_MAX_OUTPUT_CHARS, budget);
    if (!bounded.complete) {
      appendSafeExcerpt(excerpt, bounded.text, budget);
      excerptTruncated = true;
      refuse();
      return;
    }
    if (!traversalBudgetReady(budget)) {
      refuse();
      return;
    }
    hash.update(text, 'utf8');
    chars += bounded.chars;
    appendSafeExcerpt(excerpt, text, budget);
    if (excerpt.truncated) excerptTruncated = true;
    if (!traversalBudgetReady(budget)) refuse();
  }
  function traverse(val: unknown, depth: number): void {
    if (traversalTruncated || !consumeTraversalNode(budget)) {
      refuse();
      return;
    }
    if (typeof val === 'string') { update(val); return; }
    if (val === undefined || val === null) return;
    if (typeof val === 'number' || typeof val === 'boolean') return;
    if (typeof val === 'bigint') { update(val.toString()); return; }
    if (typeof val !== 'object') { refuse(); return; }
    const obj = val as object;
    if (seen.has(obj) || depth > GUARD_MAX_DEPTH) { refuse(); return; }
    seen.add(obj);
    try {
      if (Array.isArray(val)) {
        if (val.length > GUARD_CONTENT_ITEM_LIMIT) { refuse(); return; }
        for (const item of val) {
          if (traversalTruncated) return;
          traverse(item, depth + 1);
        }
        return;
      }
      const record = val as Record<string, unknown>;
      if (record.type === 'text' && typeof record.text === 'string') {
        update(record.text);
        return;
      }
      let keyCount = 0;
      for (const key of OUTPUT_TEXT_KEYS) {
        if (!(key in record)) continue;
        if (keyCount >= GUARD_OBJECT_KEY_LIMIT) { refuse(); return; }
        keyCount += 1;
        traverse(record[key], depth + 1);
        if (traversalTruncated) return;
      }
    } finally {
      seen.delete(obj);
    }
  }
  try {
    traverse(value, 0);
  } catch {
    refuse();
  }
  textForExcerpt = excerpt.text;
  excerptTruncated = excerptTruncated || excerpt.truncated;
  return {
    sha256: traversalTruncated ? null : hash.digest('hex'),
    chars,
    textForExcerpt,
    excerptTruncated,
    traversalTruncated,
  };
}

"""
