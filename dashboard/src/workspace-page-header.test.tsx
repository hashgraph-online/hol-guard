import { renderToStaticMarkup } from "react-dom/server";

import { WorkspacePageHeader } from "./workspace-page-header";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const headerWithoutTabs = renderToStaticMarkup(
  <WorkspacePageHeader
    eyebrow="Policy"
    title="Remembered rules and exceptions"
    description="See what Guard will do next time, in plain language."
  />,
);

assert(
  headerWithoutTabs.includes("Remembered rules and exceptions"),
  "header without tabs should render title copy",
);

assert(
  !headerWithoutTabs.includes('role="tablist"'),
  "header without tabs should not render TabBar",
);

assert(
  headerWithoutTabs.includes("guard-page-header__layout"),
  "workspace headers should expose the responsive layout hook",
);

const headerWithTabs = renderToStaticMarkup(
  <WorkspacePageHeader
    eyebrow="Evidence"
    title="All actions"
    tabs={[
      { value: "actions", label: "All actions" },
      { value: "commands", label: "Commands" },
      { value: "insights", label: "Insights" },
      { value: "apps", label: "Apps" },
      { value: "categories", label: "Categories" },
      { value: "export", label: "Export" },
    ]}
    activeTab="actions"
    onTabChange={() => undefined}
    actions={<button type="button">Clear</button>}
  />,
);

assert(headerWithTabs.includes('role="tablist"'), "header with tabs should render TabBar");
assert(headerWithTabs.includes("All actions"), "header with tabs should render tab labels");
assert(headerWithTabs.includes("guard-page-header__tabs"), "tabs should render inside the horizontal scroller");
assert(headerWithTabs.includes("guard-page-header__actions"), "header actions should have an independent responsive region");
assert(headerWithTabs.includes(">Export<"), "the final tab should remain in the tab list");
assert(headerWithTabs.includes(">Clear<"), "header actions should remain separate from tabs");

console.log("workspace-page-header.test.tsx: all assertions passed");
