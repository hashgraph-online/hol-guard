import {
  ABOUT_PATH_CARDS,
  ABOUT_TRUST_CONTRACT_CLAIMS,
  ABOUT_DATA_BOUNDARY_ROWS,
  ABOUT_STANDARDS_NODES,
} from "./about-content";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

// Hierarchy: affiliate is tertiary, not primary or secondary
const affiliateCard = ABOUT_PATH_CARDS.find((c) => c.id === "affiliate_starter_kit");
assert(affiliateCard !== undefined, "affiliate card exists");
assert(affiliateCard!.priority === "tertiary", "affiliate priority is tertiary");

// Hero does not link to affiliate
assert(
  !ABOUT_PATH_CARDS.some((c) => c.priority === "primary" && c.id === "affiliate_starter_kit"),
  "affiliate is not primary"
);

// Trust contract has 4 claims
assert(ABOUT_TRUST_CONTRACT_CLAIMS.length === 4, "trust contract has 4 claims");

// Data boundary has 4 rows
assert(ABOUT_DATA_BOUNDARY_ROWS.length === 4, "data boundary has 4 rows");

// Standards map has 6 nodes
assert(ABOUT_STANDARDS_NODES.length === 6, "standards map has 6 nodes");

// No local path or sensitive token patterns in content strings
const allStrings = [
  ...ABOUT_PATH_CARDS.flatMap((c) => [c.title, c.description, c.ctaLabel]),
  ...ABOUT_TRUST_CONTRACT_CLAIMS.flatMap((c) => [c.title, c.body]),
  ...ABOUT_DATA_BOUNDARY_ROWS.flatMap((r) => [r.label, r.localDefault, r.optionalSync, r.neverFromAbout]),
  ...ABOUT_STANDARDS_NODES.flatMap((n) => [n.label, n.body]),
].join(" ");

const forbiddenPatterns = [
  "/Users/",
  "/home/",
  "/var/folders/",
  "guard-token",
  "guardDaemon",
  "workspace=",
  "device=",
  "install=",
  "user=",
  "127.0.0.1",
  "localhost",
  ".local",
];

for (const pattern of forbiddenPatterns) {
  assert(
    !allStrings.includes(pattern),
    `content does not contain forbidden pattern: ${pattern}`
  );
}

console.log("about-design.test.ts: all assertions passed");
