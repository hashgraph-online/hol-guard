import { parseAppDetail, resolveView } from "./app";
import { harnessDisplayName, isDisplayableHarness, normalizeHarnessFilter, normalizeHarnessSlug } from "./approval-center-utils";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

assert(parseAppDetail("/apps/opencode") === "opencode", "valid app route parses harness slug");
assert(parseAppDetail("/apps/claude-code") === "claude-code", "hyphenated app route parses harness slug");
assert(parseAppDetail("/apps/OpenCode") === "opencode", "app route normalizes case");
assert(parseAppDetail("/apps/*") === null, "wildcard app route is rejected");
assert(parseAppDetail("/apps/%2A") === null, "encoded wildcard app route is rejected");
assert(parseAppDetail("/apps/global") === null, "global pseudo-harness route is rejected");
assert(parseAppDetail("/apps/") === null, "empty app route is rejected");
assert(parseAppDetail("/apps/opencode/settings") === null, "nested app route is rejected");
assert(resolveView("/apps/opencode") === "app-detail", "valid app route opens app detail");
assert(resolveView("/apps/*") === "fleet", "wildcard app route falls back to fleet");
assert(resolveView("/apps/%2A") === "fleet", "encoded wildcard app route falls back to fleet");

assert(normalizeHarnessSlug(" OpenCode ") === "opencode", "normalizer trims and lowercases app slugs");
assert(normalizeHarnessSlug("*") === null, "normalizer rejects wildcard pseudo-harness");
assert(normalizeHarnessSlug("global") === null, "normalizer rejects global pseudo-harness");
assert(normalizeHarnessSlug("cursor-") === null, "normalizer rejects trailing separators");
assert(normalizeHarnessFilter("cursor") === "cursor", "filter normalizer keeps valid app harness");
assert(normalizeHarnessFilter("*") === "all", "filter normalizer maps wildcard pseudo-harness to all apps");
assert(isDisplayableHarness("codex"), "real app harness is displayable");
assert(!isDisplayableHarness("*"), "wildcard pseudo-harness is not displayable");
assert(harnessDisplayName("*") === "All apps", "wildcard pseudo-harness never renders as raw star");
