import { parseAppDetail, PROTECT_ROUTE, resolveView, viewTitle } from "./app";
import { harnessDisplayName, isDisplayableHarness, normalizeHarnessFilter, normalizeHarnessSlug } from "./approval-center-utils";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

assert(parseAppDetail("/apps/opencode") === "opencode", "valid app route parses harness slug");
assert(parseAppDetail("/apps/claude-code") === "claude-code", "hyphenated app route parses harness slug");
assert(parseAppDetail("/apps/kimi") === "kimi", "kimi app route parses harness slug");
assert(parseAppDetail("/apps/grok") === "grok", "grok app route parses harness slug");
assert(parseAppDetail("/apps/OpenCode") === "opencode", "app route normalizes case");
assert(parseAppDetail("/apps/*") === null, "wildcard app route is rejected");
assert(parseAppDetail("/apps/%2A") === null, "encoded wildcard app route is rejected");
assert(parseAppDetail("/apps/global") === null, "global pseudo-harness route is rejected");
assert(parseAppDetail("/apps/") === null, "empty app route is rejected");
assert(parseAppDetail("/apps/opencode/settings") === null, "nested app route is rejected");
assert(resolveView("/apps/opencode") === "app-detail", "valid app route opens app detail");
assert(resolveView("/apps/*") === "fleet", "wildcard app route falls back to fleet");
assert(resolveView("/apps/%2A") === "fleet", "encoded wildcard app route falls back to fleet");
assert(resolveView(PROTECT_ROUTE) === "fleet", "/protect resolves to protect workspace view");
assert(resolveView("/about") === "about", "/about resolves to about view");
assert(viewTitle("about") === "About", "about view title is About");

assert(normalizeHarnessSlug(" OpenCode ") === "opencode", "normalizer trims and lowercases app slugs");
assert(normalizeHarnessSlug("*") === null, "normalizer rejects wildcard pseudo-harness");
assert(normalizeHarnessSlug("global") === null, "normalizer rejects global pseudo-harness");
assert(normalizeHarnessSlug("cursor-") === null, "normalizer rejects trailing separators");
assert(
  normalizeHarnessSlug("Ce2b7ac2ccab4fab9902347b033bf25e") === null,
  "normalizer rejects 32-char hex token-like pseudo-harnesses"
);
assert(
  normalizeHarnessSlug("d75ba142-bf53-4f27-aebc-4884278c421a") === null,
  "normalizer rejects UUID token-like pseudo-harnesses"
);
assert(normalizeHarnessFilter("cursor") === "cursor", "filter normalizer keeps valid app harness");
assert(normalizeHarnessFilter("*") === "all", "filter normalizer maps wildcard pseudo-harness to all apps");
assert(normalizeHarnessFilter("Ce2b7ac2ccab4fab9902347b033bf25e") === "all", "filter normalizer maps token-like pseudo-harness to all apps");
assert(isDisplayableHarness("codex"), "real app harness is displayable");
assert(!isDisplayableHarness("*"), "wildcard pseudo-harness is not displayable");
assert(!isDisplayableHarness("Ce2b7ac2ccab4fab9902347b033bf25e"), "token-like pseudo-harness is not displayable");
assert(harnessDisplayName("*") === "All apps", "wildcard pseudo-harness never renders as raw star");
assert(
  harnessDisplayName("Ce2b7ac2ccab4fab9902347b033bf25e") === "Unknown app",
  "token-like pseudo-harness never renders raw"
);
