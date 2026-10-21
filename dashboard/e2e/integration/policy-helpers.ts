import type { Locator, Page } from "@playwright/test";

import type { IntegrationState } from "./fixtures";

// Shape of what scripts/ci/dashboard_integration_seeds/policy.py returns.
export type SeededRule = {
  title: string;
  harness: "gemini" | "opencode";
  scope: string;
  action: "allow" | "block";
  source: string;
  workspace: string | null;
  publisher: string | null;
};

export type PolicySeed = {
  workspace_allow: SeededRule;
  artifact_block: SeededRule;
  global_allow: SeededRule;
  publisher_allow: SeededRule;
  harness_block: SeededRule;
  removal_target: SeededRule;
  cloud_block: SeededRule;
  total: number;
  allowCount: number;
  blockCount: number;
  listedCount: number;
};

export function policySeed(state: IntegrationState): PolicySeed {
  return state.seeded.policy as unknown as PolicySeed;
}

// How the dashboard words a harness id and a policy scope.
export const APP_LABEL = { gemini: "Gemini", opencode: "OpenCode" } as const;
export const SCOPE_LABEL: Record<string, string> = {
  artifact: "Once",
  workspace: "This project",
  harness: "This harness",
  publisher: "This cwd",
  global: "Team policy",
};

export const ACTION_LABEL = { allow: "Allow", block: "Block" } as const;

export function localRules(seed: PolicySeed): SeededRule[] {
  return [
    seed.workspace_allow,
    seed.artifact_block,
    seed.global_allow,
    seed.publisher_allow,
    seed.harness_block,
    seed.removal_target,
  ];
}

// The row is found by its exact Inspect button so a rule whose title is a
// substring of another never matches twice.
export function rememberedRow(page: Page, title: string): Locator {
  return page
    .getByRole("table", { name: "Remembered policy rules" })
    .getByRole("row")
    .filter({ has: page.getByRole("button", { name: `Inspect rule ${title}`, exact: true }) });
}

// Local and cloud rules share one table now; a cloud rule's row is the same
// row shape, distinguished by its source cell and read-only actions.
export function cloudRow(page: Page, title: string): Locator {
  return rememberedRow(page, title);
}

export function policyTab(page: Page, name: RegExp): Locator {
  return page.getByRole("tablist", { name: "Rules and exceptions sections" }).getByRole("tab", { name });
}
