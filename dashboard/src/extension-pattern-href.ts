import { guardAwareHref } from "./guard-api";

/** Deep link to one extension pattern. Carries catalog ids only, never command text. */
export function extensionPatternHref(extensionId: string, ruleId: string | null): string {
  // guardAwareHref carries the dashboard session in the fragment; append the
  // rule anchor as one more fragment parameter instead of replacing it.
  const url = new URL(guardAwareHref(`/extensions/${extensionId}`), window.location.origin);
  if (ruleId === null) return url.toString();
  url.searchParams.set("tab", "permissions");
  const fragment = url.hash.startsWith("#") ? url.hash.slice(1) : url.hash;
  const params = new URLSearchParams(fragment);
  params.set("rule", ruleId);
  url.hash = params.toString();
  return url.toString();
}
