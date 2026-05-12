import { paginate, totalPages, hasMore } from "./evidence-pagination";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`FAIL: ${message}`);
}

const items = Array.from({ length: 120 }, (_, i) => i + 1);

// paginate
const page0 = paginate(items, 0, 50);
assert(page0.length === 50, "paginate: page 0 returns 50");
assert(page0[0] === 1 && page0[49] === 50, "paginate: page 0 values");

const page1 = paginate(items, 1, 50);
assert(page1.length === 100, "paginate: page 1 returns cumulative 100");
assert(page1[99] === 100, "paginate: page 1 last value is 100");

const page2 = paginate(items, 2, 50);
assert(page2.length === 120, "paginate: page 2 returns all 120");

const page3 = paginate(items, 3, 50);
assert(page3.length === 120, "paginate: page 3 returns 120 (capped)");

const emptyPage = paginate([], 0, 50);
assert(emptyPage.length === 0, "paginate: empty input");

const smallPage = paginate([1, 2, 3], 0, 10);
assert(smallPage.length === 3, "paginate: fewer items than pageSize");

// totalPages
assert(totalPages(0, 50) === 0, "totalPages: 0 items");
assert(totalPages(50, 50) === 1, "totalPages: exact fit");
assert(totalPages(51, 50) === 2, "totalPages: one over");
assert(totalPages(100, 50) === 2, "totalPages: exact two pages");
assert(totalPages(101, 50) === 3, "totalPages: three pages");
assert(totalPages(1, 1) === 1, "totalPages: 1 item 1 pageSize");
assert(totalPages(10, 0) === 0, "totalPages: zero pageSize returns 0");

// hasMore
assert(hasMore(0, 50, 120) === true, "hasMore: page 0, 120 total");
assert(hasMore(1, 50, 120) === true, "hasMore: page 1, 120 total");
assert(hasMore(2, 50, 120) === false, "hasMore: page 2, 120 total - no more");
assert(hasMore(0, 50, 50) === false, "hasMore: exactly 50 on first page");
assert(hasMore(0, 50, 0) === false, "hasMore: empty list");
assert(hasMore(0, 50, 51) === true, "hasMore: 51 items, 50 per page");

console.log("evidence-pagination.test.ts: all tests passed");
