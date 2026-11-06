import { readFileSync } from "node:fs";
import { resolve } from "node:path";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const source = readFileSync(
  resolve(import.meta.dirname, "components/section-shell.tsx"),
  "utf8",
);

assert(
  !source.includes("opacity-0"),
  "about sections must not hide copy before intersection observer fires",
);
assert(
  source.includes('typeof IntersectionObserver === "undefined"'),
  "about sections stay visible when IntersectionObserver is unavailable",
);

console.log("about-section-shell.test.ts: all assertions passed");
