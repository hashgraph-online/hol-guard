import {
  fetchReadState,
  postReadStateMarkRead,
  postReadStateMarkUnread,
  postReadStateMarkAllRead,
  type GuardReadStatePayload,
} from "./guard-api";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

async function testReadStateApiExports(): Promise<void> {
  assert(typeof fetchReadState === "function", "fetchReadState should be a function");
  assert(typeof postReadStateMarkRead === "function", "postReadStateMarkRead should be a function");
  assert(typeof postReadStateMarkUnread === "function", "postReadStateMarkUnread should be a function");
  assert(typeof postReadStateMarkAllRead === "function", "postReadStateMarkAllRead should be a function");

  const mockPayload: GuardReadStatePayload = { ids: ["req-1", "req-2"] };
  assert(mockPayload.ids.length === 2, "GuardReadStatePayload should have ids array");
}

async function main(): Promise<void> {
  await testReadStateApiExports();
  console.log("✓ request-read-state API exports verified");
}

void main().catch((error) => {
  console.error(error);
  process.exit(1);
});
