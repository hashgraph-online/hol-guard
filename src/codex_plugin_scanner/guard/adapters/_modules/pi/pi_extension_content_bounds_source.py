"""Generated Pi content-review helper source."""

from __future__ import annotations

CONTENT_BOUNDING_HELPERS_SOURCE = r"""function boundValue(
  value: unknown,
  depth = 0,
  seen = new WeakSet<object>(),
  budget = createTraversalBudget(),
): BoundedValue {
  if (!consumeTraversalNode(budget)) {
    return { value: '[content omitted by HOL Guard]', truncated: true };
  }
  if (typeof value === 'string') {
    if (value.length <= GUARD_TEXT_LIMIT_CHARS && traversalBudgetReady(budget)) {
      return { value, truncated: false };
    }
    return { value: safeTruncateText(value, GUARD_TEXT_LIMIT_CHARS, budget), truncated: true };
  }
  if (value === undefined) return { value: undefined, truncated: false };
  if (typeof value === 'bigint') {
    const text = value.toString();
    return {
      value: safeTruncateText(text, GUARD_TEXT_LIMIT_CHARS, budget),
      truncated: text.length > GUARD_TEXT_LIMIT_CHARS,
    };
  }
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
      const itemLimit = Math.min(value.length, GUARD_CONTENT_ITEM_LIMIT);
      const nextItems: unknown[] = [];
      let truncated = value.length > GUARD_CONTENT_ITEM_LIMIT;
      for (let index = 0; index < itemLimit; index += 1) {
        const next = boundValue(value[index], depth + 1, seen, budget);
        nextItems.push(next.value);
        truncated = truncated || next.truncated;
        if (!traversalBudgetReady(budget)) {
          truncated = true;
          break;
        }
      }
      return { value: nextItems, truncated };
    }
    const record = value as Record<string, unknown>;
    const nextRecord: Record<string, unknown> = {};
    let truncated = false;
    let keyCount = 0;
    for (const key in record) {
      if (!Object.prototype.hasOwnProperty.call(record, key)) continue;
      if (keyCount >= GUARD_OBJECT_KEY_LIMIT || !traversalBudgetReady(budget)) {
        truncated = true;
        break;
      }
      keyCount += 1;
      const next = boundValue(record[key], depth + 1, seen, budget);
      nextRecord[key] = next.value;
      truncated = truncated || next.truncated;
    }
    return { value: nextRecord, truncated };
  } finally {
    seen.delete(objectValue);
  }
}

function safeCollectOutputText(
  value: unknown,
  accumulator: { text: string; truncated: boolean; itemCount: number },
  depth: number,
  seen: WeakSet<object>,
  budget: TraversalBudget,
): void {
  if (accumulator.truncated || !consumeTraversalNode(budget)) {
    accumulator.truncated = true;
    return;
  }
  if (typeof value === 'string') {
    appendSafeExcerpt(accumulator, value, budget);
    return;
  }
  if (typeof value === 'bigint') {
    appendSafeExcerpt(accumulator, value.toString(), budget);
    return;
  }
  if (
    value === undefined ||
    value === null ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) return;
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
      const itemLimit = Math.min(value.length, GUARD_CONTENT_ITEM_LIMIT);
      for (let index = 0; index < itemLimit; index += 1) {
        if (accumulator.itemCount >= GUARD_CONTENT_ITEM_LIMIT) {
          accumulator.truncated = true;
          break;
        }
        accumulator.itemCount += 1;
        safeCollectOutputText(value[index], accumulator, depth + 1, seen, budget);
        if (accumulator.truncated) break;
      }
      if (value.length > GUARD_CONTENT_ITEM_LIMIT) accumulator.truncated = true;
      return;
    }
    const record = value as Record<string, unknown>;
    if (record.type === 'text' && typeof record.text === 'string') {
      appendSafeExcerpt(accumulator, record.text, budget);
      return;
    }
    for (const key of OUTPUT_TEXT_KEYS) {
      if (!(key in record)) continue;
      safeCollectOutputText(record[key], accumulator, depth + 1, seen, budget);
      if (accumulator.truncated) break;
    }
  } finally {
    seen.delete(objectValue);
  }
}

function boundedOutputText(
  value: unknown,
  deadlineAt?: number,
  budget = createTraversalBudget(deadlineAt),
): BoundedValue {
  const accumulator = { text: '', truncated: false, itemCount: 0 };
  safeCollectOutputText(value, accumulator, 0, new WeakSet<object>(), budget);
  return { value: accumulator.text, truncated: accumulator.truncated || budget.exhausted };
}

function boundedResponseText(
  response: Response,
  maxChars: number,
  deadlineAt?: number,
): Promise<string | null> {
  return (async (): Promise<string | null> => {
    const body = response.body;
    const reader = body && typeof body.getReader === 'function' ? body.getReader() : null;
    if (!reader) return null;
    const decoder = new TextDecoder();
    let text = '';
    try {
      for (;;) {
        if (deadlineAt !== undefined && Date.now() >= deadlineAt) {
          try { await reader.cancel(); } catch {}
          return null;
        }
        const next = await reader.read();
        if (deadlineAt !== undefined && Date.now() >= deadlineAt) {
          try { await reader.cancel(); } catch {}
          return null;
        }
        if (next.done) {
          const tail = decoder.decode();
          if (text.length + tail.length > maxChars) return null;
          text += tail;
          return text;
        }
        const chunk = next.value as Uint8Array;
        const remaining = maxChars - text.length;
        // UTF-8 needs at most four bytes per code point plus a small
        // incomplete-sequence allowance. Reject before decoding an oversized
        // stream chunk so a hostile daemon body is not materialized first.
        if (remaining < 0 || chunk.byteLength > remaining * 4 + 4) {
          try { await reader.cancel(); } catch {}
          return null;
        }
        const decoded = decoder.decode(chunk, { stream: true });
        if (text.length + decoded.length > maxChars) {
          try { await reader.cancel(); } catch {}
          return null;
        }
        text += decoded;
      }
    } catch {
      return null;
    } finally {
      try { reader.releaseLock(); } catch {}
    }
  })();
}

function boundedJsonStringSize(value: string, budget: TraversalBudget): number | null {
  if (!traversalBudgetReady(budget)) return null;
  if (value.length + 2 > GUARD_MAX_REFERENCE_JSON_BYTES) return null;
  let size = 2;
  for (let index = 0; index < value.length; index += 1) {
    if ((index & 0x3ff) === 0 && !traversalBudgetReady(budget)) return null;
    const code = value.charCodeAt(index);
    if (code === 0x22 || code === 0x5c) {
      size += 2;
    } else if (code < 0x20) {
      if ([8, 9, 10, 12, 13].includes(code)) {
        size += 2;
      } else {
        size += 6;
      }
    } else if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        size += 4;
        index += 1;
      } else {
        size += 6;
      }
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      size += 6;
    } else {
      if (code < 0x80) {
        size += 1;
      } else if (code < 0x800) {
        size += 2;
      } else {
        size += 3;
      }
    }
    if (size > GUARD_MAX_REFERENCE_JSON_BYTES) return null;
  }
  return size;
}

function hasCallableSerializationHook(value: object): boolean {
  try {
    let owner: object | null = value;
    while (owner !== null) {
      const descriptor = Object.getOwnPropertyDescriptor(owner, 'toJSON');
      if (descriptor) {
        if (!Object.prototype.hasOwnProperty.call(descriptor, 'value')) return true;
        if (typeof descriptor.value === 'function') return true;
      }
      owner = Object.getPrototypeOf(owner);
    }
    return false;
  } catch {
    return true;
  }
}

// The preflight proves only ordinary JSON-like data. Reflection of arbitrary
// objects can execute proxy traps, so this does not claim universal detection
// or boundedness for custom JavaScript objects.
function safeEnumerableDataKeys(record: Record<string, unknown>): string[] | null {
  try {
    const prototype = Object.getPrototypeOf(record);
    if (prototype !== Object.prototype && prototype !== null) return null;
    if (hasCallableSerializationHook(record)) return null;
    const keys = Object.keys(record);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(record, key);
      if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) return null;
    }
    return keys;
  } catch {
    return null;
  }
}

function boundedJsonSize(
  value: unknown,
  budget: TraversalBudget,
  depth: number,
  seen: WeakSet<object>,
  inArray: boolean,
): number | null {
  if (!consumeTraversalNode(budget) || depth > GUARD_MAX_DEPTH) return null;
  if (value === null) return 4;
  if (typeof value === 'string') return boundedJsonStringSize(value, budget);
  if (typeof value === 'boolean') return value ? 4 : 5;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return 4;
    try {
      const serialized = JSON.stringify(value);
      return typeof serialized === 'string' ? serialized.length : 4;
    } catch {
      return null;
    }
  }
  if (value === undefined || typeof value === 'function' || typeof value === 'symbol') {
    return inArray ? 4 : 0;
  }
  if (typeof value === 'bigint' || typeof value !== 'object') return null;
  const objectValue = value as object;
  if (seen.has(objectValue)) return null;
  seen.add(objectValue);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype || hasCallableSerializationHook(value)) return null;
      const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
      if (
        !lengthDescriptor
        || !Object.prototype.hasOwnProperty.call(lengthDescriptor, 'value')
        || !Number.isSafeInteger(lengthDescriptor.value)
        // Every dense element uses at least one byte, plus comma separators.
        || lengthDescriptor.value > Math.floor((GUARD_MAX_REFERENCE_JSON_BYTES - 1) / 2)
      ) return null;
      const length = lengthDescriptor.value;
      let size = 2;
      for (let index = 0; index < length; index += 1) {
        if (!traversalBudgetReady(budget)) return null;
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) return null;
        const child = boundedJsonSize(descriptor.value, budget, depth + 1, seen, true);
        if (child === null) return null;
        if (index > 0) size += 1;
        size += child;
        if (size > GUARD_MAX_REFERENCE_JSON_BYTES) return null;
      }
      return size;
    }
    const record = value as Record<string, unknown>;
    const keys = safeEnumerableDataKeys(record);
    if (keys === null) return null;
    let size = 2;
    let included = 0;
    for (const key of keys) {
      if (!traversalBudgetReady(budget)) return null;
      const child = boundedJsonSize(record[key], budget, depth + 1, seen, false);
      if (child === null) return null;
      if (child === 0) continue;
      const keySize = boundedJsonStringSize(key, budget);
      if (keySize === null) return null;
      if (included > 0) size += 1;
      size += keySize + 1 + child;
      included += 1;
      if (size > GUARD_MAX_REFERENCE_JSON_BYTES) return null;
    }
    return size;
  } catch {
    return null;
  } finally {
    seen.delete(objectValue);
  }
}

function payloadWithinSerializedBudget(payload: Record<string, unknown>, deadlineAt?: number): boolean {
  const budget = createTraversalBudget(deadlineAt);
  // Shape traversal may exceed the ordinary excerpt budget, but never the
  // same native reference byte budget used by the final serialized payload.
  budget.maxNodes = GUARD_MAX_REFERENCE_JSON_NODES;
  try {
    const size = boundedJsonSize(payload, budget, 0, new WeakSet<object>(), false);
    return size !== null && size <= GUARD_MAX_REFERENCE_JSON_BYTES && traversalBudgetReady(budget);
  } catch {
    return false;
  }
}

/* HOL Guard bounded preprocessing ends */

"""
