import type { Page } from "@playwright/test";
import { expect, expectNoErrorBoundary, test } from "./fixtures";
import {
  commandDetail,
  commandFacts,
  commandRecords,
  commandRow,
  commandsUrl,
  numberAfter,
  type CommandFacts,
} from "./evidence-helpers";

const DECISIONS: Record<string, string> = {
  allow: "Allowed",
  review: "Review required",
  block: "Blocked",
};

const RUN_RESULTS: Record<string, string> = {
  attempted: "Attempt recorded",
  prevented: "Prevented before execution",
  allowed_unconfirmed: "Result not recorded",
  confirmed_success: "Execution confirmed successful",
  confirmed_failure: "Execution confirmed failed",
  unpaired_post: "Execution observed; initial decision unavailable",
};

const id = (number: number) => `evidence-e2e-cmd-${String(number).padStart(2, "0")}`;

// Every seeded command is either in the table or not, whatever else the store holds.
async function expectRows(page: Page, facts: CommandFacts, present: number[]): Promise<void> {
  const wanted = new Set(present.map(id));
  for (const [activityId, record] of Object.entries(facts.records)) {
    if (!wanted.has(activityId)) await expect(commandRow(page, record.command), activityId).toHaveCount(0);
  }
  for (const activityId of wanted) {
    await expect(commandRow(page, facts.records[activityId].command), activityId).toHaveCount(1);
  }
}

// A select labelled by wrapping text; its accessible name also carries the chosen option.
function field(page: Page, label: string) {
  return page.getByRole("combobox", { name: new RegExp(`^${label}\\b`) });
}

async function summaryNumber(page: Page, label: string): Promise<number> {
  const summary = page.getByRole("region", { name: "Command activity summary" });
  return numberAfter((await summary.textContent()) ?? "", label);
}

test.describe("evidence: command activity", () => {
  test("lists every seeded command with its decision, run result and rule", async ({ page, state }) => {
    const facts = commandFacts(state);
    await page.goto(commandsUrl("command_limit=100"));
    await expectNoErrorBoundary(page);
    await expect(page.getByRole("tab", { name: "Commands" })).toHaveAttribute("aria-selected", "true");
    await expect(page.getByRole("heading", { name: "Commands", level: 1 })).toBeVisible();

    const headers = commandRecords(page).getByRole("columnheader");
    await expect(headers).toHaveText(["Time", "Command", "App", "Decision", "Run result", "Rule evidence", "Open detail"]);
    for (const [activityId, record] of Object.entries(facts.records)) {
      const cells = commandRow(page, record.command).getByRole("cell");
      await expect(cells.nth(2), activityId).toHaveText(record.harness);
      await expect(cells.nth(3), activityId).toHaveText(record.action ? DECISIONS[record.action] : "Decision unavailable");
      await expect(cells.nth(4), activityId).toHaveText(RUN_RESULTS[record.status]);
      if (record.rules.length > 0) {
        // The first rule is named; extra matches show as a +N badge.
        const extra = record.rules.length > 1 ? `\\s*\\+${record.rules.length - 1}` : "";
        await expect(cells.nth(5), activityId).toHaveText(new RegExp(`^${record.rules[0].replaceAll(".", "\\.")}${extra}$`));
      } else {
        await expect(cells.nth(5), activityId).toHaveText(record.action ? "No rule match" : "Rule evidence unavailable");
      }
    }
    const shown = await page.getByText(/^\d+ records on this page$/).textContent();
    expect(Number.parseInt(shown ?? "", 10)).toBeGreaterThanOrEqual(facts.total);
  });

  test("summary reports the recorded checks and follows the app filter", async ({ page, state }) => {
    const facts = commandFacts(state);
    const records = Object.values(facts.records);
    await page.goto(commandsUrl());
    const summary = page.getByRole("region", { name: "Command activity summary" });
    await expect(summary).toBeVisible();

    // Lower bounds: other areas may record command activity into the same store.
    await expect.poll(() => summaryNumber(page, "Commands checked")).toBeGreaterThanOrEqual(facts.total);
    expect(await summaryNumber(page, "Review prompts")).toBeGreaterThanOrEqual(records.filter((r) => r.prompted).length);
    expect(await summaryNumber(page, "Run results recorded")).toBeGreaterThanOrEqual(
      records.filter((r) => r.status.startsWith("confirmed")).length,
    );
    expect(await summaryNumber(page, "Allowed; result not recorded")).toBeGreaterThanOrEqual(
      records.filter((r) => r.status === "allowed_unconfirmed").length,
    );
    await expect(summary.getByText("Top extensions by frequency")).toBeVisible();
    await expect(summary.getByText("Top rules by frequency")).toBeVisible();
    await expect(summary.getByText("command.git", { exact: true })).toBeVisible();

    const global = await summaryNumber(page, "Commands checked");
    await page.goto(commandsUrl("command_harness=cursor"));
    await expect.poll(() => summaryNumber(page, "Commands checked")).toBeGreaterThanOrEqual(facts.by_harness.cursor);
    expect(await summaryNumber(page, "Commands checked")).toBeLessThan(global);
  });

  test("filters narrow the records and the URL", async ({ page, state }) => {
    const facts = commandFacts(state);
    await page.goto(commandsUrl("command_limit=100"));
    await expectRows(page, facts, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);

    const app = field(page, "App");
    await app.selectOption("cursor");
    await expect(page).toHaveURL(/command_harness=cursor/);
    await expectRows(page, facts, [3, 4, 8, 11]);
    await app.selectOption("");
    await expect(page).not.toHaveURL(/command_harness/);

    // Run result, proof source, interaction and authorization reuse.
    const filters: [string, string, string, number[]][] = [
      ["Run result", "Prevented", "command_status=prevented", [2, 6, 11]],
      ["Run result", "Confirmed failure", "command_status=confirmed_failure", [8]],
      ["Proof source", "Post-execution", "command_proof=post_hook", [7, 8]],
      ["Proof source", "Unpaired post proof", "command_proof=unpaired_post", [9]],
      ["Interaction", "Review requested", "command_prompted=true", [1, 3, 5]],
      ["Interaction", "No review prompt", "command_prompted=false", [2, 4, 6, 7, 8, 9, 10, 11]],
      ["Authorization reuse", "Accepted", "command_reuse=accepted", [10]],
    ];
    for (const [label, option, param, rows] of filters) {
      const select = field(page, label);
      await select.selectOption({ label: option });
      await expect(page).toHaveURL(new RegExp(param));
      await expectRows(page, facts, rows);
      await select.selectOption({ index: 0 });
      await expect(page).not.toHaveURL(new RegExp(param.split("=")[0]));
    }
    // Run result narrows a table that the summary cannot follow, so the page says so.
    await field(page, "Run result").selectOption({ label: "Prevented" });
    await expect(page.getByText("Summary and trend totals do not include every active filter below.")).toBeVisible();

    // Filters combine, and a combination without a match says so.
    await field(page, "Run result").selectOption({ index: 0 });
    await app.selectOption("opencode");
    await field(page, "Proof source").selectOption({ label: "Post-execution" });
    await expect(page.getByText("No command activity", { exact: true })).toBeVisible();
    await expect(page.getByText("No recorded commands match these filters.")).toBeVisible();
    await expect(commandRecords(page)).toHaveCount(0);
  });

  test("extension and rule filters pick out the commands that matched", async ({ page, state }) => {
    const facts = commandFacts(state);
    await page.goto(commandsUrl("command_limit=100"));
    await field(page, "Extension").selectOption({ label: "Git protection" });
    await expect(page).toHaveURL(/command_extension=command\.git/);
    await expectRows(page, facts, [1, 2, 11]);
    // The summary's breakdowns only exist globally for an extension, and say so.
    await expect(page.getByRole("region", { name: "Command activity summary" })).toContainText("Global only");

    const title = facts.records[id(2)].rule_titles[0];
    await field(page, "Rule").selectOption({ label: title });
    await expect(page).toHaveURL(/command_rule=command\.git\.hard-reset/);
    await expectRows(page, facts, [2, 11]);

    // Choosing another extension drops the rule that belonged to the first.
    await field(page, "Extension").selectOption({ label: "Filesystem protection" });
    await expect(page).not.toHaveURL(/command_rule/);
    await expectRows(page, facts, [3]);
    await field(page, "Extension").selectOption({ index: 0 });
    await expectRows(page, facts, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
  });

  test("filters survive a reload", async ({ page, state }) => {
    const facts = commandFacts(state);
    await page.goto(commandsUrl("command_limit=100"));
    await field(page, "App").selectOption("cursor");
    await field(page, "Interaction").selectOption({ label: "Review requested" });
    await expect(page).toHaveURL(/command_harness=cursor/);
    await expect(page).toHaveURL(/command_prompted=true/);
    await expectRows(page, facts, [3]);

    await page.reload();
    await expect(field(page, "App")).toHaveValue("cursor");
    await expect(field(page, "Interaction")).toHaveValue("prompted");
    await expectRows(page, facts, [3]);
    await expect(page.getByRole("tab", { name: "Commands" })).toHaveAttribute("aria-selected", "true");
  });

  test("pages through the records with Previous and Next", async ({ page, state }) => {
    const facts = commandFacts(state);
    await page.goto(commandsUrl("command_harness=cursor&command_limit=2"));
    const commands = commandRecords(page).getByRole("code");
    const previous = page.getByRole("button", { name: "Previous page" });
    const next = page.getByRole("button", { name: "Next page" });

    await expect(commands).toHaveCount(2);
    await expect(page.getByText("2 records on this page")).toBeVisible();
    await expect(previous).toBeDisabled();
    await expect(next).toBeEnabled();
    const firstPage = await commands.allInnerTexts();

    // Walk forward to the last page, newest first.
    const seen = [...firstPage];
    for (let step = 0; step < 10 && (await next.isEnabled()); step += 1) {
      const before = await commands.first().innerText();
      await next.click();
      await expect(commands.first()).not.toHaveText(before);
      await expect(previous).toBeEnabled();
      seen.push(...(await commands.allInnerTexts()));
    }
    await expect(next).toBeDisabled();
    const order = [11, 8, 4, 3].map((number) => seen.indexOf(facts.records[id(number)].command));
    expect(order.every((position) => position >= 0), `missing a cursor command in ${seen}`).toBe(true);
    expect(order).toEqual([...order].sort((a, b) => a - b));

    // Previous page walks back to the first page.
    for (let step = 0; step < 10 && (await previous.isEnabled()); step += 1) {
      const before = await commands.first().innerText();
      await previous.click();
      await expect(commands.first()).not.toHaveText(before);
    }
    await expect(previous).toBeDisabled();
    expect(await commands.allInnerTexts()).toEqual(firstPage);
    await expect(page).toHaveURL(/command_limit=2/);
  });

  test("detail panel explains a reviewed command and links to its rule", async ({ page, state }) => {
    const facts = commandFacts(state);
    const record = facts.records[id(1)];
    await page.goto(commandsUrl("command_limit=100"));
    await commandRow(page, record.command).getByRole("button", { name: "Details" }).click();
    await expect(page).toHaveURL(new RegExp(`command_selected=${id(1)}`));

    const detail = commandDetail(page);
    await expect(detail).toBeVisible();
    await expect(detail.getByText(record.command, { exact: true })).toBeVisible();
    await expect(detail.getByText("Review required", { exact: true }).first()).toBeVisible();
    await expect(detail.getByText("Attempt recorded", { exact: true })).toBeVisible();

    await detail.getByText("How Guard checked it").click();
    for (const text of [
      "Before-command check recorded",
      "Guard asked for review",
      "A command rule controlled the decision",
      "Exact parse",
      "Not applicable",
    ]) {
      await expect(detail.getByText(text, { exact: true }), text).toBeVisible();
    }

    await expect(detail.getByText("command.git.force-push", { exact: true })).toBeVisible();
    await expect(detail.getByText("Controlling rule", { exact: true })).toBeVisible();
    await expect(detail.getByText("command.git 1.0.0 · rule 1.0.0")).toBeVisible();
    await expect(detail.getByText("Unsafe evidence", { exact: true })).toBeVisible();
    await expect(detail.getByText("Remote state mutation", { exact: true })).toBeVisible();
    await expect(detail.getByRole("button", { name: "Should not have interrupted" })).toBeEnabled();
    await expect(detail.getByRole("button", { name: "Expected Guard to stop this" })).toBeEnabled();

    // The panel is a deep link: it survives a reload and closes with its button.
    await page.reload();
    await expect(commandDetail(page)).toBeVisible();
    await commandDetail(page).getByRole("button", { name: "Close command activity detail" }).click();
    await expect(commandDetail(page)).toHaveCount(0);
    await expect(page).not.toHaveURL(/command_selected/);

    // Adjust protection opens the extension that owns the rule.
    await commandRow(page, record.command).getByRole("button", { name: "Details" }).click();
    await commandDetail(page).getByRole("button", { name: "Adjust protection" }).click();
    await expect(page).toHaveURL(/\/extensions\/command\.git/);
  });

  test("detail panel tells each kind of run result apart", async ({ page, state }) => {
    const facts = commandFacts(state);
    type Case = { number: number; shows: string[]; checked?: string[] };
    const cases: Case[] = [
      {
        number: 2,
        shows: ["Blocked", "Prevented before execution", "command.git.hard-reset", "Controlling rule"],
        checked: ["Before-command check recorded", "No review prompt recorded"],
      },
      {
        number: 3,
        shows: [
          "Result not recorded",
          "Guard checked this command before the app could run it and allowed it. No matching result was recorded, so Guard cannot tell whether the app ran the command or whether it succeeded.",
          "command.filesystem.recursive-delete",
        ],
      },
      {
        number: 4,
        shows: ["Allowed", "No rule matched this action."],
        checked: ["No command rule controlled the decision"],
      },
      {
        number: 7,
        shows: ["Execution confirmed successful", "No rule matched this action."],
        checked: ["Post-execution proof recorded"],
      },
      { number: 8, shows: ["Execution confirmed failed"], checked: ["Post-execution proof recorded"] },
      {
        number: 9,
        shows: [
          "Decision unavailable",
          "Execution observed; initial decision unavailable",
          "Rule evidence is unavailable for this record.",
        ],
        checked: ["Unpaired post-execution proof", "Parse confidence unavailable"],
      },
      {
        number: 10,
        shows: ["Review required", "command.cloud.aws.resource-deletion"],
        checked: ["Existing authorization reused", "A prior approval was evaluated for reuse", "No review prompt recorded"],
      },
    ];
    for (const { number, shows, checked = [] } of cases) {
      await page.goto(commandsUrl(`command_limit=100&command_selected=${id(number)}`));
      const detail = commandDetail(page);
      await expect(detail, id(number)).toBeVisible();
      await expect(detail.getByText(facts.records[id(number)].command, { exact: true })).toBeVisible();
      for (const text of shows) await expect(detail.getByText(text, { exact: true }).first(), `${id(number)}: ${text}`).toBeAttached();
      if (checked.length > 0) await detail.getByText("How Guard checked it").click();
      for (const text of checked) await expect(detail.getByText(text, { exact: true }), `${id(number)}: ${text}`).toBeAttached();
    }
  });

  // Product bug: command-activity-detail.tsx:64 gives the Command field sm:col-span-2 inside a
  // lg:grid-cols-1 grid, so Decision and Run result share two columns and a long Run result
  // squeezes Decision to 0px (text overlaps) at desktop widths.
  test.fixme("detail panel keeps Decision and Run result readable", async ({ page }) => {
    await page.goto(commandsUrl(`command_limit=100&command_selected=${id(9)}`));
    const detail = commandDetail(page);
    await expect(detail.getByText("Decision unavailable", { exact: true })).toBeVisible();
    await expect(detail.getByText("Execution observed; initial decision unavailable", { exact: true })).toBeVisible();
  });

  test("a command that matched two rules lists both and names the controlling one", async ({ page, state }) => {
    const facts = commandFacts(state);
    const record = facts.records[id(11)];
    await page.goto(commandsUrl(`command_limit=100&command_selected=${id(11)}`));
    const detail = commandDetail(page);
    await expect(detail.getByText(record.command, { exact: true })).toBeVisible();
    const rules = detail.getByRole("listitem").filter({ hasText: "command.git" });
    await expect(rules).toHaveCount(2);
    await expect(rules.nth(0)).toContainText("command.git.hard-reset");
    await expect(rules.nth(0)).toContainText("Controlling rule");
    await expect(rules.nth(1)).toContainText("command.git.force-clean");
    await expect(rules.nth(1)).not.toContainText("Controlling rule");
    await expect(detail.getByRole("button", { name: "Adjust protection" })).toHaveCount(2);
  });
});
