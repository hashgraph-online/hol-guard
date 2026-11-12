import { daemonApi, expect, test, type IntegrationState } from "./fixtures";
import { commandDetail, commandFacts, commandsUrl } from "./evidence-helpers";

type Item = { activity_id: string; feedback_label: string | null };
type Analytics = { feedback: { label: string; count: number }[] };

const id = (number: number) => `evidence-e2e-cmd-${String(number).padStart(2, "0")}`;

async function savedLabel(state: IntegrationState, activityId: string): Promise<string | null | undefined> {
  const { items } = await daemonApi<{ items: Item[] }>(state, "/v1/command-activity?limit=100");
  return items.find((item) => item.activity_id === activityId)?.feedback_label;
}

async function feedbackCount(state: IntegrationState, label: string): Promise<number> {
  const analytics = await daemonApi<Analytics>(state, "/v1/command-activity/analytics?days=90&top_limit=10");
  return analytics.feedback.find((bucket) => bucket.label === label)?.count ?? 0;
}

test.describe("evidence: command feedback", () => {
  test("feedback on an interruption is saved and shown after a reload", async ({ page, state }) => {
    const record = commandFacts(state).records[id(1)];
    expect(await savedLabel(state, id(1))).toBeNull();
    const before = await feedbackCount(state, "should_not_have_interrupted");

    await page.goto(commandsUrl(`command_limit=100&command_selected=${id(1)}`));
    const detail = commandDetail(page);
    await expect(detail.getByText(record.command, { exact: true })).toBeVisible();
    await detail.getByRole("button", { name: "Should not have interrupted" }).click();
    await expect(detail.getByText("Feedback saved to local evidence.")).toBeVisible();

    // The daemon holds the label, only for this record, and the summary counts it.
    await expect.poll(() => savedLabel(state, id(1))).toBe("should_not_have_interrupted");
    expect(await savedLabel(state, id(3))).toBeNull();
    expect(await feedbackCount(state, "should_not_have_interrupted")).toBe(before + 1);

    await page.reload();
    await expect(commandDetail(page).getByText("Saved feedback: Should not have interrupted")).toBeVisible();
    await expect(commandDetail(page).getByText("Feedback saved to local evidence.")).toHaveCount(0);
  });

  test("feedback can be changed to the opposite verdict", async ({ page, state }) => {
    const record = commandFacts(state).records[id(2)];
    await page.goto(commandsUrl(`command_limit=100&command_selected=${id(2)}`));
    const detail = commandDetail(page);
    await expect(detail.getByText(record.command, { exact: true })).toBeVisible();

    await detail.getByRole("button", { name: "Expected Guard to stop this" }).click();
    await expect(detail.getByText("Feedback saved to local evidence.")).toBeVisible();
    await expect.poll(() => savedLabel(state, id(2))).toBe("expected_guard_to_stop_this");

    // One label per record: the second verdict replaces the first.
    await detail.getByRole("button", { name: "Should not have interrupted" }).click();
    await expect.poll(() => savedLabel(state, id(2))).toBe("should_not_have_interrupted");

    await page.reload();
    await expect(commandDetail(page).getByText("Saved feedback: Should not have interrupted")).toBeVisible();

    // The label belongs to the record, not the panel: another record starts blank.
    await page.goto(commandsUrl(`command_limit=100&command_selected=${id(4)}`));
    await expect(commandDetail(page).getByText(commandFacts(state).records[id(4)].command, { exact: true })).toBeVisible();
    await expect(commandDetail(page).getByText(/^Saved feedback:/)).toHaveCount(0);
  });
});
