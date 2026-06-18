import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const here = dirname(fileURLToPath(import.meta.url));
const bundleCardSource = readFileSync(join(here, "policy-guard-cloud-bundle-card.tsx"), "utf8");
const rememberedTabSource = readFileSync(join(here, "policy-remembered-rules-tab.tsx"), "utf8");
const activeModeSource = readFileSync(join(here, "policy-active-mode-card.tsx"), "utf8");

assert(bundleCardSource.includes("CloudBundleHeader"), "bundle card uses header row for cloud action");
assert(bundleCardSource.includes("sm:flex-row"), "bundle stats use responsive flex row");
assert(!bundleCardSource.includes("grid-cols-3"), "bundle card avoids equal-thirds grid");
assert(!bundleCardSource.includes("Latest sync needs attention"), "bundle card drops legacy wrapped subtitle copy");
assert(bundleCardSource.includes("cloudBundleCopy.detail"), "attention state uses detail alert");
assert(bundleCardSource.includes("self-start"), "bundle card does not stretch with siblings");
assert(rememberedTabSource.includes("lg:items-start"), "summary row avoids equal-height stretch");
assert(rememberedTabSource.includes("1.55fr"), "bundle card gets wider column than active mode");
assert(activeModeSource.includes("line-clamp-3"), "active mode description clamps instead of stretching card");

console.log("policy-remembered-rules-summary.test.ts: all assertions passed");
