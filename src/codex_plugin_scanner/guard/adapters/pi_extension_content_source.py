"""Generated Pi managed extension content-review helper source."""

# ruff: noqa: E501

from __future__ import annotations

CONTENT_REVIEW_HELPERS_SOURCE = r"""type OutputDigest = {
  sha256: string | null;
  chars: number;
  textForExcerpt: string;
  excerptTruncated: boolean;
  traversalTruncated: boolean;
};

function digestOutputText(value: unknown): OutputDigest {
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

function sourcePathFromToolInput(toolInput: Record<string, unknown>): string | null {
  for (const key of ['file_path', 'filePath', 'path', 'file', 'filename']) {
    const value = toolInput[key];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return null;
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
  if (!path) return null;
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

function boundValue(value: unknown, depth = 0, seen = new WeakSet<object>()): BoundedValue {
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
        const next = boundValue(item, depth + 1, seen);
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
      const next = boundValue(entryValue, depth + 1, seen);
      nextRecord[key] = next.value;
      truncated = truncated || next.truncated;
    }
    return { value: nextRecord, truncated };
  } finally {
    seen.delete(objectValue);
  }
}

function appendBoundedText(accumulator: { text: string; truncated: boolean }, value: string): void {
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

function boundedOutputText(value: unknown): BoundedValue {
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

"""
