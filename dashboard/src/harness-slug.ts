const HARNESS_SLUG_PATTERN = /^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$/;
const HEX_TOKEN_HARNESS_PATTERN = /^[a-f0-9]{16,64}$/;
const UUID_HARNESS_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const NON_APP_HARNESS_SLUGS = new Set(["*", "all", "any", "global"]);

export function capitalizeHarness(harness: string): string {
  if (harness.length === 0) {
    return harness;
  }
  return `${harness.charAt(0).toUpperCase()}${harness.slice(1)}`;
}

export function normalizeHarnessSlug(harness: string | null | undefined): string | null {
  const slug = typeof harness === "string" ? harness.trim().toLowerCase() : "";
  if (
    slug.length === 0 ||
    NON_APP_HARNESS_SLUGS.has(slug) ||
    HEX_TOKEN_HARNESS_PATTERN.test(slug) ||
    UUID_HARNESS_PATTERN.test(slug) ||
    !HARNESS_SLUG_PATTERN.test(slug)
  ) {
    return null;
  }
  return slug;
}

export function isDisplayableHarness(harness: string | null | undefined): harness is string {
  return normalizeHarnessSlug(harness) !== null;
}
