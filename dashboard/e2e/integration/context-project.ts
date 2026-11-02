import { expect, type Page } from "@playwright/test";

type ProjectOptions = { app?: string; files?: string[] };

/** Adds a project the way a person does: browse to the folder, tick notes, pick the app, then confirm. */
export async function addContextProject(page: Page, workspace: string, { app, files = ["README.md"] }: ProjectOptions = {}) {
  await page.getByRole("button", { name: /Choose a project folder/ }).click();
  const picker = page.getByRole("dialog", { name: "Choose a project folder", exact: true });
  await picker.getByRole("button", { name: "Type a path", exact: true }).click();
  const path = picker.getByLabel("Folder path", { exact: true });
  await path.fill(workspace);
  await path.press("Enter");
  await expect(picker.getByRole("status")).toContainText(workspace.split(/[\\/]/).filter(Boolean).pop()!);
  await picker.getByRole("button", { name: "Use this folder", exact: true }).click();
  await expect(picker).toHaveCount(0);
  const chosen = page.getByRole("group", { name: "Files CIGAR may read", exact: true });
  if (await page.getByText("Reading project files is off", { exact: false }).count() === 0) {
    await expect(chosen).toBeVisible();
    for (const box of await chosen.getByRole("checkbox", { checked: true }).all()) await box.uncheck();
    for (const file of files) await chosen.getByRole("checkbox", { name: new RegExp(`^${file.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`) }).check();
    await expect(page.getByText(`${files.length} picked · up to 32`, { exact: true })).toBeVisible();
  } else expect(files).toEqual([]);
  if (app) await page.getByRole("radio", { name: new RegExp(`^${app}`) }).check();
}

export async function confirmContextProject(page: Page, password: string) {
  await page.getByRole("button", { name: "Give CIGAR access", exact: true }).click();
  const proof = page.getByRole("dialog", { name: "Confirm CIGAR access", exact: true });
  await proof.getByLabel("Approval password").fill(password);
  await proof.getByRole("button", { name: "Give access", exact: true }).click();
  await expect(proof).toHaveCount(0);
}
