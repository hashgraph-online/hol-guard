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

const headerWithTabs = renderToStaticMarkup(
  <WorkspacePageHeader
    eyebrow="Evidence"
    title="Actions"
    tabs={[
      { value: "actions", label: "Actions" },
      { value: "insights", label: "Insights" },
    ]}
    activeTab="actions"
    onTabChange={() => undefined}
  />,
);

assert(headerWithTabs.includes('role="tablist"'), "header with tabs should render TabBar");
assert(headerWithTabs.includes("Actions"), "header with tabs should render tab labels");

console.log("workspace-page-header.test.tsx: all assertions passed");
