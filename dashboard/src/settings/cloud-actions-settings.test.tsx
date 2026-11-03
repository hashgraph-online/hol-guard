import { renderToStaticMarkup } from "react-dom/server";

import {
  CLOUD_ACTIONS_STATUS_SCHEMA,
  cloudActionsCheckedCopy,
  cloudActionsCurrentState,
  cloudActionsLinks,
  cloudActionsReconnectCommand,
  cloudActionsRetryAfterSeconds,
  cloudActionsStateCopy,
  cloudActionsSummary,
  normalizeCloudActionsStatus,
} from "./cloud-actions-model";
import { CloudActionsSettingsView } from "./cloud-actions-settings";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

const NOW = new Date("2026-11-03T12:00:00Z");

function payload(connection: unknown, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema: CLOUD_ACTIONS_STATUS_SCHEMA,
    generated_at: "2026-11-03T12:00:00Z",
    stale_after_seconds: 300,
    check_interval_seconds: 60,
    next_check_allowed_at: null,
    connection,
    included_actions: "not_available_yet",
    accounts: "not_available_yet",
    ...extra,
  };
}

const NOT_PAIRED = { state: "not_paired", check: { state: "not_checked" } };

const connected = {
  state: "on",
  workspace: "ws_beta",
  site: "cloud.example.test:8443",
  cloud_url: "https://cloud.example.test:8443",
  cloud_base_url: "https://cloud.example.test:8443/points",
  check: {
    checked_at: "2026-11-03T11:58:00Z",
    stale: false,
    service: { state: "current", message: "Guard Cloud offers Cloud actions.", http_status: 200 },
  },
};

const withCheck = (check: unknown, extra: Record<string, unknown> = {}) => ({ ...connected, ...extra, check });

// A report from another schema version is not guessed at, including the alpha one with saved sign-ins.
assert(normalizeCloudActionsStatus({ ...payload(connected), schema: "other" }) === null, "unknown schema is rejected");
assert(
  normalizeCloudActionsStatus({ ...payload(connected), schema: "guard.cloud-actions.local-status.v1", sign_ins: [] }) === null,
  "the alpha report is rejected",
);
assert(normalizeCloudActionsStatus({ schema: CLOUD_ACTIONS_STATUS_SCHEMA }) === null, "a missing connection is rejected");
assert(normalizeCloudActionsStatus(null) === null, "null is rejected");

const status = normalizeCloudActionsStatus(payload(connected));
assert(status?.connection !== null && status?.connection !== undefined, "the connection is read");
const connection = status.connection;
assert(connection.workspace === "ws_beta" && connection.site === "cloud.example.test:8443", "workspace and site stay explicit");
assert(connection.setting === "on", "Cloud actions left on are read");
assert(connection.check.state === "current" && connection.check.message === "Guard Cloud offers Cloud actions.", "the service answer is read");

const unpaired = normalizeCloudActionsStatus(payload(NOT_PAIRED));
assert(unpaired !== null && unpaired.connection === null, "not connected is its own answer");
assert(cloudActionsSummary(unpaired) === "This computer is not connected to Guard Cloud.", "not connected summary");

// Whether Cloud actions were left on is only what Guard Cloud said.
assert(normalizeCloudActionsStatus(payload({ ...connected, state: "off" }))?.connection?.setting === "off", "off is read");
assert(
  normalizeCloudActionsStatus(payload({ ...connected, state: "unknown" }))?.connection?.setting === "unknown",
  "an unreported setting stays unknown",
);
assert(
  normalizeCloudActionsStatus(payload({ ...connected, state: "enabled" }))?.connection?.setting === "unknown",
  "an unexpected setting is not guessed at",
);

// Values that would end up in a copyable command must look like IDs.
const hostile = normalizeCloudActionsStatus(payload({ ...connected, workspace: "ws; rm -rf ~", site: "evil.test/path?x" }));
assert(hostile?.connection?.workspace === null, "a workspace that is not an ID is not shown");
assert(hostile.connection.site === null, "a site that is not a host is not shown");
assert(cloudActionsReconnectCommand(hostile.connection) === "hol-guard connect", "the command never carries an unchecked workspace");
assert(
  cloudActionsReconnectCommand(connection) ===
    "hol-guard connect --connect-url https://cloud.example.test:8443/points/guard/connect --cloud-workspace ws_beta",
  "reconnecting names the same Guard Cloud and workspace",
);
assert(
  cloudActionsReconnectCommand({ workspace: "ws_beta", cloudBaseUrl: "https://hol.org" }) ===
    "hol-guard connect --cloud-workspace ws_beta",
  "the default Guard Cloud needs no address",
);
assert(cloudActionsReconnectCommand(null) === "hol-guard connect", "connecting needs no options");

// Guard Cloud pages are offered only for a recognised site, under that same site.
function baseOf(cloudBaseUrl: unknown, site = "cloud.example.test", cloudUrl = "https://cloud.example.test"): string | null | undefined {
  return normalizeCloudActionsStatus(payload({ ...connected, site, cloud_url: cloudUrl, cloud_base_url: cloudBaseUrl }))
    ?.connection?.cloudBaseUrl;
}
assert(baseOf("https://cloud.example.test") === "https://cloud.example.test", "the site itself is a base");
assert(baseOf("https://cloud.example.test/points") === "https://cloud.example.test/points", "one short path is a base");
assert(baseOf(null) === null, "no base when Guard does not recognise the site");
assert(baseOf("https://other.example.test/points") === null, "a base on another site is dropped");
assert(baseOf("https://cloud.example.test.evil.test") === null, "a base that only starts like the site is dropped");
assert(baseOf("https://cloud.example.test@evil.test") === null, "a base with a user part is dropped");
assert(baseOf("https://cloud.example.test/points/../x") === null, "a base with more than one path part is dropped");
assert(baseOf("https://cloud.example.test/points?x=1") === null, "a base with a query is dropped");
assert(baseOf("https://cloud.example.test", "other.example.test", "https://other.example.test") === null, "a base must match the site");
assert(baseOf("https://cloud.example.test", "cloud.example.test", "https://other.example.test") === null, "an address for another site is dropped");
assert(baseOf("http://cloud.example.test", "cloud.example.test", "http://cloud.example.test") === null, "plain http to another computer is dropped");
assert(baseOf("http://127.0.0.1:3000", "127.0.0.1:3000", "http://127.0.0.1:3000") === "http://127.0.0.1:3000", "plain http on this computer is kept");
assert(baseOf("javascript:alert(1)") === null, "a script address is dropped");

const links = cloudActionsLinks(connection);
assert(
  links.map((link) => link.href).join("\n") ===
    [
      "https://cloud.example.test:8443/points/guard/review?workspaceId=ws_beta&tab=needs-review",
      "https://cloud.example.test:8443/points/guard/evidence?workspaceId=ws_beta&tab=decisions&source=cloud",
      "https://cloud.example.test:8443/points/guard/settings?tab=billing&workspaceId=ws_beta#included-actions",
      "https://cloud.example.test:8443/points/guard/settings?tab=integrations&workspaceId=ws_beta#connected-accounts",
    ].join("\n"),
  "each Guard Cloud page is scoped to the connected workspace",
);
assert(
  links.every((link) => !/gateway|token|secret|grant|client/i.test(link.href)),
  "links carry nothing but the site and workspace",
);
assert(cloudActionsLinks({ workspace: "ws_beta", cloudBaseUrl: null }).length === 0, "no links without a recognised site");
assert(cloudActionsLinks({ workspace: null, cloudBaseUrl: "https://hol.org" }).length === 0, "no links without a workspace");
assert(
  cloudActionsLinks({ workspace: "ws:a.b", cloudBaseUrl: "https://hol.org" })[0]?.href ===
    "https://hol.org/guard/review?workspaceId=ws%3Aa.b&tab=needs-review",
  "the workspace is encoded",
);

// A message from the daemon is bounded.
const long = normalizeCloudActionsStatus(payload(withCheck({ ...connected.check, service: { state: "current", message: "x".repeat(1000) } })));
assert(long?.connection?.check.message?.length === 240, "messages are bounded");

// A connection that was never checked says so.
const unchecked = normalizeCloudActionsStatus(payload(withCheck({ state: "not_checked" })));
assert(unchecked?.connection?.check.state === "not_checked" && unchecked.connection.check.checkedAt === null, "no check time is invented");
assert(cloudActionsCheckedCopy(unchecked.connection.check, NOW, 300) === "Not checked yet", "unchecked copy");
assert(cloudActionsCheckedCopy(connection.check, NOW, 300) === "Checked 2 minutes ago", "fresh copy");
const old = normalizeCloudActionsStatus(payload(withCheck({ ...connected.check, checked_at: "2026-11-03T09:00:00Z", stale: true })));
assert(old?.connection?.check.stale === true, "an old answer is marked stale");
assert(
  cloudActionsCheckedCopy(old.connection.check, NOW, 300) === "Checked 3 hours ago. This answer may be out of date.",
  "stale copy",
);

// The page stays open, so an answer that was fresh when loaded goes out of date by the clock.
const LATER = new Date(NOW.getTime() + 10 * 60 * 1000);
assert(
  cloudActionsCheckedCopy(connection.check, LATER, 300) === "Checked 12 minutes ago. This answer may be out of date.",
  "an answer ages out while the page is open",
);

// Cloud actions left off on this computer outrank what Guard Cloud offers.
assert(cloudActionsCurrentState(connection) === "current", "the service answer is the state while Cloud actions are on");
assert(cloudActionsCurrentState({ setting: "off", check: connection.check }) === "off", "off on this computer comes first");

// Every state has plain copy; none of them blames local protection or mentions a separate sign-in.
for (const state of ["current", "not_checked", "offline", "not_turned_on", "changed", "unexpected_answer", "off"]) {
  const copy = cloudActionsStateCopy(state);
  assert(copy.label !== "Unknown", `${state} has a label`);
  const words = `${copy.label} ${copy.remedy ?? ""}`;
  assert(!/protection|token|gateway|endpoint|agent|receipt|harness|posture/i.test(words), `${state} copy stays in plain terms`);
  assert(!/sign[ -]?in|log ?in|log ?out|sign[ -]?out/i.test(words), `${state} copy never asks for a separate sign-in`);
}
assert(cloudActionsStateCopy("something_new").label === "Unknown", "unknown states are not guessed");
assert(cloudActionsStateCopy("changed").reconnect && cloudActionsStateCopy("changed").label === "Reconnect", "a changed service asks to reconnect");
assert(cloudActionsStateCopy("off").reconnect, "Cloud actions left off are turned on by reconnecting");
assert(!cloudActionsStateCopy("offline").reconnect, "reconnecting does not fix being offline");

assert(cloudActionsRetryAfterSeconds("2026-11-03T12:00:42Z", NOW) === 42, "retry wait is read");
assert(cloudActionsRetryAfterSeconds("2026-11-03T11:59:00Z", NOW) === 0, "past wait is zero");
assert(cloudActionsRetryAfterSeconds(null, NOW) === 0, "no wait without a check");
assert(cloudActionsSummary(status) === "Connected to workspace ws_beta.", "summary names the workspace");
const changed = normalizeCloudActionsStatus(payload(withCheck({ ...connected.check, service: { state: "changed", message: "Guard Cloud now describes a different Cloud actions address." } })));
assert(changed !== null && cloudActionsSummary(changed) === "Connected to workspace ws_beta. Cloud actions need attention.", "summary flags attention");

function render(overrides: Partial<Parameters<typeof CloudActionsSettingsView>[0]> = {}): string {
  return renderToStaticMarkup(
    <CloudActionsSettingsView
      status={status}
      error={null}
      loading={false}
      checking={false}
      notice={null}
      retryAfterSeconds={0}
      now={NOW}
      onCheck={() => undefined}
      {...overrides}
    />,
  );
}

const visible = (html: string) => html.replace(/<[^>]+>/g, " ");

const html = render();
assert(html.includes("Protection on this computer does not depend on Cloud actions."), "local protection independence is stated");
assert(html.includes("ws_beta") && html.includes("cloud.example.test:8443"), "workspace and site are named");
assert(html.includes(">Available<") && html.includes(">On<"), "the state and the setting are labelled");
assert(!html.includes("hol-guard connect"), "nothing to run while Cloud actions are available");
assert(html.includes(">Check now<"), "check button is offered when connected");
assert(html.includes("Open in Guard Cloud") && html.includes(">Review requests"), "Guard Cloud pages are linked for a recognised site");
assert((html.match(/href="https:\/\/cloud\.example\.test:8443\/points\/guard\//g) ?? []).length === 4, "four Guard Cloud pages");
assert(html.includes('rel="noopener noreferrer"'), "Guard Cloud opens without access to this page");
assert(
  html.includes("Approving one there never approves anything paused on this computer."),
  "review in Guard Cloud is kept apart from local approvals",
);
assert(!/>\s*(Approve|Allow|Deny|Block)\b/.test(html), "no decision controls for Guard Cloud actions on this computer");
assert(!/token|gateway|endpoint|harness|posture|receipt/i.test(visible(html)), "page copy stays in plain terms");
assert(!/cloud-actions login|cloud-actions logout|--profile/.test(html), "no separate sign-in command");

const changedHtml = render({ status: changed });
assert(changedHtml.includes(">Reconnect<"), "a changed service shows Reconnect");
assert(
  changedHtml.includes(
    "hol-guard connect --connect-url https://cloud.example.test:8443/points/guard/connect --cloud-workspace ws_beta",
  ),
  "reconnect command names the same Guard Cloud",
);
assert(!/sign[ -]?in again/i.test(visible(changedHtml)), "reconnecting is never called signing in again");

const offHtml = render({ status: normalizeCloudActionsStatus(payload({ ...connected, state: "off" })) });
assert(offHtml.includes(">Off on this computer<") && offHtml.includes(">Off<"), "Cloud actions left off are labelled");
assert(offHtml.includes("/points/guard/connect --cloud-workspace ws_beta"), "turning them on is reconnecting");

assert(render({ retryAfterSeconds: 12 }).includes("Check again in 12s"), "the wait is shown on the button");
assert(render({ checking: true }).includes("Checking..."), "checking state");

const empty = render({ status: unpaired });
assert(empty.includes("This computer is not connected to Guard Cloud."), "not connected state");
assert(empty.includes(">hol-guard connect<"), "connecting is the one command");
assert(!empty.includes("Check now"), "no check button before connecting");
assert(empty.includes("Protection on this computer does not depend on Cloud actions."), "independence stated before connecting");

const failed = render({ status: null, error: "Guard on this computer did not answer." });
assert(failed.includes("Guard on this computer did not answer."), "daemon failure is shown");
assert(failed.includes("Protection on this computer does not depend on Cloud actions."), "independence stated on failure");

console.log("cloud-actions-settings.test.tsx: all tests passed");
