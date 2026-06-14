import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const here = dirname(fileURLToPath(import.meta.url));
const reviewSource = readFileSync(join(here, "approval-center-layout.tsx"), "utf8");

assert(!reviewSource.includes("PolicyCloudExceptionsTab"), "review layout must not mount cloud exceptions tab");
assert(!reviewSource.includes("policy-cloud-exception"), "review layout must not import cloud exception modules");
assert(reviewSource.includes("Review"), "review layout remains the review surface");

console.log("policy-review-scope.test.ts: all assertions passed");
