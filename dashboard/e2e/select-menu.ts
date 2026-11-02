import type { Locator } from "@playwright/test";

/** The options of a SelectMenu combobox, which renders a custom listbox instead of a native select. */
export async function menuOptions(combobox: Locator): Promise<Locator> {
  const list = await combobox.getAttribute("aria-controls");
  if (!list) throw new Error("combobox has no listbox");
  return combobox.page().locator(`[id="${list}"] [role="option"]`);
}

/** Choose a SelectMenu option by value, or by position among its options. */
export async function chooseMenuOption(combobox: Locator, choice: string | { index: number }) {
  const options = await menuOptions(combobox);
  await combobox.click();
  await (typeof choice === "string" ? options.and(combobox.page().locator(`[data-value="${choice}"]`)) : options.nth(choice.index)).click();
}

export async function menuValues(combobox: Locator): Promise<string[]> {
  return (await menuOptions(combobox)).evaluateAll((items) => items.map((item) => item.getAttribute("data-value") ?? ""));
}
