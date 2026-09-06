import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";

import { ShellNavigation } from "./shell-navigation";
import {
  canonicalNavigationView,
  isMobilePrimaryView,
  mobilePrimaryNavigationItems,
  navigationItemForView,
  queueAriaLabel,
  queueCountDisplay,
  SHELL_NAV_ITEMS,
} from "./shell-navigation-model";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function source(path: string): string {
  return readFileSync(new URL(path, import.meta.url), "utf8");
}

assert(SHELL_NAV_ITEMS.length === 9, "The shell exposes every top-level Guard destination");
assert(
  new Set(SHELL_NAV_ITEMS.map((item) => item.href)).size === SHELL_NAV_ITEMS.length,
  "Top-level navigation destinations are unique",
);
assert(
  mobilePrimaryNavigationItems().map((item) => item.view).join(",") === "home,inbox,fleet,evidence",
  "Compact screens keep the four highest-frequency sections one tap away",
);
assert(
  canonicalNavigationView("app-detail") === "fleet",
  "App detail routes stay anchored to Protect",
);
assert(
  canonicalNavigationView("audit") === "supply-chain" &&
    canonicalNavigationView("feed-health") === "supply-chain",
  "Supply-chain subroutes keep their parent destination active",
);
assert(
  navigationItemForView("settings").label === "Settings",
  "The current section can be described without a select input",
);
assert(isMobilePrimaryView("home"), "Home belongs in compact primary navigation");
assert(!isMobilePrimaryView("settings"), "Settings is reached through the More surface on compact screens");
assert(queueCountDisplay(104) === "99+", "Large queue counts remain compact");
assert(
  queueAriaLabel(1) === "Inbox, 1 Guard action waiting" &&
    queueAriaLabel(0) === "Inbox, no Guard actions waiting",
  "Queue announcements use useful singular and empty-state copy",
);

const markup = renderToStaticMarkup(
  <ShellNavigation
    queuedCount={104}
    view="settings"
    collapsed={false}
    onToggleCollapse={() => undefined}
    onNavigate={() => undefined}
  />,
);

assert(!markup.includes("<select"), "Responsive shell navigation never collapses into a select input");
assert(
  markup.includes('data-testid="guard-shell-mobile-header"') &&
    markup.includes('data-testid="mobile-bottom-navigation"') &&
    markup.includes('data-testid="guard-shell-sidebar"'),
  "One semantic shell renders mobile, rail, and wide navigation surfaces for CSS to adapt",
);
assert(
  markup.includes('data-testid="mobile-navigation-trigger"') &&
    markup.includes('data-testid="compact-navigation-trigger"') &&
    markup.includes('aria-controls="guard-navigation-drawer"'),
  "Mobile and medium-width layouts expose the same full navigation drawer",
);
assert(
  markup.includes('data-navigation-item="settings"') && markup.includes('aria-current="page"'),
  "The active destination remains visible while the window changes size",
);
assert(
  markup.includes("104 local actions need a Guard decision.") &&
    markup.includes("Open Inbox") &&
    markup.includes("guard-shell-status-action"),
  "Local Guard status keeps compact body copy and a short Inbox action",
);
assert(
  !markup.includes("Open Inbox to review.") &&
    !markup.includes("underline underline-offset") &&
    !markup.includes("guard-quiet-link"),
  "Queue status copy is not a wrapping underlined paragraph",
);
assert(
  markup.includes('aria-label="Primary Guard sections"') &&
    markup.includes('aria-label="More Guard sections"'),
  "Compact navigation has explicit primary and overflow semantics",
);

const css = source("./shell-navigation.css");
const drawerSource = source("./shell-navigation-drawer.tsx");
const layoutSource = source("./approval-center-layout.tsx");
const responsiveSource = source("./responsive-layout.css");
const mainSource = source("./main.tsx");

assert(
  css.includes("@media (min-width: 48rem)") && css.includes("@media (min-width: 80rem)"),
  "The shell has distinct compact, rail, and expanded breakpoints",
);
assert(
  css.includes("env(safe-area-inset-bottom)") && css.includes("min-height: 2.75rem"),
  "Mobile navigation accounts for safe areas and 44px interaction targets",
);
assert(
  css.includes("@media (prefers-reduced-motion: reduce)") &&
    css.includes("@media (forced-colors: active)"),
  "Motion and high-contrast preferences remain supported",
);
assert(
  drawerSource.includes('role="dialog"') &&
    drawerSource.includes('aria-modal="true"') &&
    drawerSource.includes('event.key === "Escape"') &&
    drawerSource.includes("dataset.guardModalOpen") &&
    drawerSource.includes('event.key !== "Tab"') &&
    drawerSource.includes('setAttribute("inert", "")'),
  "The full navigation drawer traps focus, closes with Escape, and makes the background inert",
);
assert(
  layoutSource.includes("<ShellNavigation") &&
    layoutSource.includes('className="guard-shell-content flex flex-col"') &&
    layoutSource.includes("onSetUpdateChannel={onSetUpdateChannel}") &&
    !layoutSource.includes("<ShellHeader") &&
    !layoutSource.includes("<ShellSidebar"),
  "The application layout is driven by the adaptive shell instead of the legacy header and sidebar",
);
assert(
  drawerSource.includes("onSetUpdateChannel={props.onSetUpdateChannel}"),
  "The navigation drawer keeps the alpha update control",
);

const alphaMarkup = renderToStaticMarkup(
  <ShellNavigation
    queuedCount={0}
    view="home"
    collapsed={false}
    onToggleCollapse={() => undefined}
    onNavigate={() => undefined}
    onSetUpdateChannel={() => undefined}
  />,
);
assert(
  alphaMarkup.includes("Try alpha updates") &&
    alphaMarkup.includes('data-testid="guard-alpha-updates-control"'),
  "Local Guard exposes a tap-sized control to enable alpha updates",
);
assert(
  !markup.includes("Try alpha updates"),
  "Alpha enrollment stays hidden when the channel handler is not wired",
);
assert(
  mainSource.indexOf('import "./shell-navigation.css"') <
    mainSource.indexOf('import "./responsive-layout.css"'),
  "Shell layout loads before workspace-level responsive corrections",
);
assert(
  !responsiveSource.includes("min-width: 64rem) and (max-width: 79.999rem"),
  "Workspace CSS no longer swaps the desktop sidebar for a select-based header",
);

console.log("shell-navigation.test.tsx: all assertions passed");
