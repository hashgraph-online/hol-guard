import { expect, type Locator, type Page } from "@playwright/test";

/** Check persisted opt-out only after Stop acknowledges cleanup and its write. */
export async function stopContextAssistance(
  page: Page,
  button: Locator = page.getByRole("button", { name: "Turn off CIGAR", exact: true }),
) {
  const [response] = await Promise.all([
    page.waitForResponse((reply) => new URL(reply.url()).pathname === "/v1/context-assistance/stop"
      && reply.request().method() === "POST"),
    button.click(),
  ]);
  expect(response.status()).toBe(200);
  const status = await response.json();
  expect(status.requested_enabled).toBe(false);
  expect(status.effective_enabled).toBe(false);
  expect(status.runtime).toBeNull();
}
