import type { Page } from "@playwright/test";

import type { IntegrationState } from "./fixtures";

// Shape of what scripts/ci/dashboard_integration_seeds/settings.py returns.
export type SettingsSeed = {
  approvalWaitTimeoutSeconds: number;
  changedApprovalWaitTimeoutSeconds: number;
};

export function settingsSeed(state: IntegrationState): SettingsSeed {
  return state.seeded.settings as unknown as SettingsSeed;
}

export const SETTINGS_SECTIONS = [
  { key: "protection", nav: /^Protection Security level/ },
  { key: "apps", nav: /^Apps Choose protection/ },
  { key: "approval", nav: /^Approval gate Password/ },
  { key: "notifications", nav: /^Notifications Desktop alerts/ },
  { key: "rules", nav: /^Protection rules Tune risky/ },
  { key: "maintenance", nav: /^Data & repair Export/ },
] as const;

export type SettingsSectionKey = (typeof SETTINGS_SECTIONS)[number]["key"];

export function sectionNav(page: Page) {
  return page.getByRole("navigation", { name: "Settings section navigation" });
}
