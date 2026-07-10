import { addReadIds, removeReadId, createRequestReadState, REQUEST_READ_STATE_KEY } from "./request-read-state";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function makeStorage(initial: Record<string, string> = {}): Storage {
  const store = new Map<string, string>(Object.entries(initial));
  return {
    getItem(key: string): string | null {
      return store.get(key) ?? null;
    },
    setItem(key: string, value: string): void {
      store.set(key, value);
    },
    removeItem(key: string): void {
      store.delete(key);
    },
    clear(): void {
      store.clear();
    },
    get length(): number {
      return store.size;
    },
    key(index: number): string | null {
      return Array.from(store.keys())[index] ?? null;
    },
  } as Storage;
}

// addReadIds marks ids as read and moves them to the front.
assert(
  JSON.stringify(addReadIds(["a", "b"], ["c"])) === JSON.stringify(["c", "a", "b"]),
  "T-RRS-01: addReadIds prepends newly-read ids"
);

assert(
  JSON.stringify(addReadIds(["a", "b"], ["b"])) === JSON.stringify(["b", "a"]),
  "T-RRS-02: addReadIds reorders existing ids to the front"
);

assert(
  JSON.stringify(addReadIds(["a", "b"], ["a", "b"])) === JSON.stringify(["a", "b"]),
  "T-RRS-03: addReadIds preserves order when ids already at front"
);

assert(
  JSON.stringify(addReadIds(["a", "b"], ["c", "c", "c"])) === JSON.stringify(["c", "a", "b"]),
  "T-RRS-03b: addReadIds deduplicates repeated input ids"
);

assert(
  addReadIds(new Array(500).fill(0).map((_, i) => `id-${i}`), ["new"]).length === 500,
  "T-RRS-04: addReadIds respects the limit"
);

assert(
  !addReadIds(new Array(500).fill(0).map((_, i) => `id-${i}`), ["new"]).includes("id-499"),
  "T-RRS-05: addReadIds evicts the oldest id at the limit"
);

// removeReadId unmarks an id.
assert(
  JSON.stringify(removeReadId(["a", "b", "c"], "b")) === JSON.stringify(["a", "c"]),
  "T-RRS-06: removeReadId removes the target id"
);

assert(
  JSON.stringify(removeReadId(["a", "b"], "c")) === JSON.stringify(["a", "b"]),
  "T-RRS-07: removeReadId is a no-op for unknown ids"
);

// createRequestReadState reads and writes through storage.
const storage = makeStorage({ [REQUEST_READ_STATE_KEY]: JSON.stringify({ ids: ["old-1"] }) });
const state = createRequestReadState(storage);

assert(state.isRead("old-1"), "T-RRS-08: state reflects persisted read ids");
assert(!state.isRead("new-1"), "T-RRS-09: unknown ids are unread");

state.markRead("new-1");
assert(state.isRead("new-1"), "T-RRS-10: markRead makes an id read");
assert(
  JSON.parse(storage.getItem(REQUEST_READ_STATE_KEY)!).ids[0] === "new-1",
  "T-RRS-11: markRead persists the id to storage"
);

state.markUnread("old-1");
assert(!state.isRead("old-1"), "T-RRS-12: markUnread makes an id unread");
assert(
  !JSON.parse(storage.getItem(REQUEST_READ_STATE_KEY)!).ids.includes("old-1"),
  "T-RRS-13: markUnread persists the removal"
);

state.markAllRead(["batch-1", "batch-2"]);
assert(state.isRead("batch-1") && state.isRead("batch-2"), "T-RRS-14: markAllRead marks every id");

// Graceful handling of corrupt storage.
const corruptStorage = makeStorage({ [REQUEST_READ_STATE_KEY]: "not-json" });
const corruptState = createRequestReadState(corruptStorage);
assert(!corruptState.isRead("x"), "T-RRS-15: corrupt storage is treated as empty");
corruptState.markRead("x");
assert(corruptState.isRead("x"), "T-RRS-16: state recovers and writes valid JSON after corrupt storage");

console.log("request-read-state tests passed");
