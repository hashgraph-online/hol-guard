import { assertSafeAboutExternalUrl, validateAboutExternalLinkOrThrow, AboutExternalLinkError } from "./about-external-links";
import type { AboutLinkId } from "./about-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

// Allowed links - correct linkId + href pairs
assert(
  assertSafeAboutExternalUrl("hol_partners", "https://hol.org/guard/partners").hostname === "hol.org",
  "hol.org partners is allowed with correct linkId"
);
assert(
  assertSafeAboutExternalUrl("hol_affiliates", "https://hol.org/guard/affiliates").hostname === "hol.org",
  "hol.org affiliates is allowed with correct linkId"
);
assert(
  assertSafeAboutExternalUrl("hol_guard_source", "https://github.com/hashgraph-online/hol-guard").hostname === "github.com",
  "github.com source is allowed with correct linkId"
);
assert(
  assertSafeAboutExternalUrl("standards_sdk_github", "https://github.com/hashgraph-online/standards-sdk").hostname === "github.com",
  "github.com standards-sdk is allowed with correct linkId"
);
assert(
  assertSafeAboutExternalUrl("guard_docs", "https://hol.org/guard/docs").hostname === "hol.org",
  "hol.org guard docs is allowed"
);

// Path prefix mismatch
let threw = false;
try {
  assertSafeAboutExternalUrl("hol_affiliates", "https://hol.org/guard/pricing");
} catch (e) {
  threw = true;
  assert(e instanceof AboutExternalLinkError, "path mismatch throws AboutExternalLinkError");
}
assert(threw, "affiliates linkId with wrong path is rejected");

// Wrong repo for source linkId
threw = false;
try {
  assertSafeAboutExternalUrl("hol_guard_source", "https://github.com/other/repo");
} catch (e) {
  threw = true;
}
assert(threw, "github.com/other/repo is rejected for hol_guard_source");

// Must use HTTPS
threw = false;
try {
  assertSafeAboutExternalUrl("hol_partners", "http://hol.org/guard/partners");
} catch (e) {
  threw = true;
  assert(e instanceof AboutExternalLinkError, "http throws AboutExternalLinkError");
}
assert(threw, "http is rejected");

// Must not contain credentials
threw = false;
try {
  assertSafeAboutExternalUrl("hol_partners", "https://user:pass@hol.org/guard/partners");
} catch (e) {
  threw = true;
}
assert(threw, "credentials are rejected");

// Must not point to localhost
threw = false;
try {
  assertSafeAboutExternalUrl("hol_partners", "https://localhost:3000/guard/partners");
} catch (e) {
  threw = true;
}
assert(threw, "localhost is rejected");

threw = false;
try {
  assertSafeAboutExternalUrl("hol_partners", "https://127.0.0.1:3000/guard/partners");
} catch (e) {
  threw = true;
}
assert(threw, "127.0.0.1 is rejected");

// Must not have forbidden params
threw = false;
try {
  assertSafeAboutExternalUrl("hol_partners", "https://hol.org/guard/partners?guard-token=abc");
} catch (e) {
  threw = true;
}
assert(threw, "guard-token param is rejected");

threw = false;
try {
  assertSafeAboutExternalUrl("hol_partners", "https://hol.org/guard/partners?workspace=test");
} catch (e) {
  threw = true;
}
assert(threw, "workspace param is rejected");

// Referral param rejected
threw = false;
try {
  assertSafeAboutExternalUrl("hol_affiliates", "https://hol.org/guard/affiliates?ref=abc123");
} catch (e) {
  threw = true;
}
assert(threw, "ref param is rejected");

// Private IP ranges
threw = false;
try {
  assertSafeAboutExternalUrl("hol_partners", "https://10.0.0.1/guard/partners");
} catch (e) {
  threw = true;
}
assert(threw, "10.x.x.x is rejected");

threw = false;
try {
  assertSafeAboutExternalUrl("hol_partners", "https://192.168.1.1/guard/partners");
} catch (e) {
  threw = true;
}
assert(threw, "192.168.x.x is rejected");

threw = false;
try {
  assertSafeAboutExternalUrl("hol_partners", "https://172.16.0.1/guard/partners");
} catch (e) {
  threw = true;
}
assert(threw, "172.16.x.x is rejected");

threw = false;
try {
  assertSafeAboutExternalUrl("hol_partners", "https://172.31.255.255/guard/partners");
} catch (e) {
  threw = true;
}
assert(threw, "172.31.x.x is rejected");

// 172.15 should be allowed (outside 172.16/12)
let allowed = false;
try {
  assertSafeAboutExternalUrl("hol_partners", "https://172.15.0.1/guard/partners");
  allowed = true;
} catch {
  allowed = false;
}
assert(!allowed, "172.15.x.x is outside RFC1918 and should be rejected by host mismatch, not private range");

// Returns correct rel and target
const result = assertSafeAboutExternalUrl("hol_partners", "https://hol.org/guard/partners");
assert(result.rel === "noopener noreferrer", "rel is noopener noreferrer");
assert(result.target === "_blank", "target is _blank");

// validateAboutExternalLinkOrThrow works
validateAboutExternalLinkOrThrow("hol_partners", "https://hol.org/guard/partners");

console.log("about-external-links.test.ts: all assertions passed");
