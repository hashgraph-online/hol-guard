import { assertSafeAboutExternalUrl, validateAboutExternalLinkOrThrow, AboutExternalLinkError } from "./about-external-links";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

// Allowed hosts - HTTPS
assert(
  assertSafeAboutExternalUrl("https://hol.org/partners").hostname === "hol.org",
  "hol.org is allowed"
);
assert(
  assertSafeAboutExternalUrl("https://www.hol.org/guard").hostname === "www.hol.org",
  "www.hol.org is allowed"
);
assert(
  assertSafeAboutExternalUrl("https://github.com/hashgraph-online/standards-sdk").hostname === "github.com",
  "github.com is allowed"
);
assert(
  assertSafeAboutExternalUrl("https://x.com/hashgraphonline").hostname === "x.com",
  "x.com is allowed"
);
assert(
  assertSafeAboutExternalUrl("https://t.me/hashgraphonline").hostname === "t.me",
  "t.me is allowed"
);

// Must use HTTPS
let threw = false;
try {
  assertSafeAboutExternalUrl("http://hol.org/partners");
} catch (e) {
  threw = true;
  assert(e instanceof AboutExternalLinkError, "http throws AboutExternalLinkError");
}
assert(threw, "http is rejected");

// Must not contain credentials
threw = false;
try {
  assertSafeAboutExternalUrl("https://user:pass@hol.org/partners");
} catch (e) {
  threw = true;
}
assert(threw, "credentials are rejected");

// Must not point to localhost
threw = false;
try {
  assertSafeAboutExternalUrl("https://localhost:3000");
} catch (e) {
  threw = true;
}
assert(threw, "localhost is rejected");

threw = false;
try {
  assertSafeAboutExternalUrl("https://127.0.0.1:3000");
} catch (e) {
  threw = true;
}
assert(threw, "127.0.0.1 is rejected");

// Must not have forbidden params
threw = false;
try {
  assertSafeAboutExternalUrl("https://hol.org?guard-token=abc");
} catch (e) {
  threw = true;
}
assert(threw, "guard-token param is rejected");

threw = false;
try {
  assertSafeAboutExternalUrl("https://hol.org?workspace=test");
} catch (e) {
  threw = true;
}
assert(threw, "workspace param is rejected");

// Unknown hosts are rejected
threw = false;
try {
  assertSafeAboutExternalUrl("https://evil.com/phishing");
} catch (e) {
  threw = true;
}
assert(threw, "unknown host is rejected");

// Returns correct rel and target
const result = assertSafeAboutExternalUrl("https://hol.org/partners");
assert(result.rel === "noopener noreferrer", "rel is noopener noreferrer");
assert(result.target === "_blank", "target is _blank");

// validateAboutExternalLinkOrThrow works
validateAboutExternalLinkOrThrow("https://hol.org/partners");

console.log("about-external-links.test.ts: all assertions passed");
