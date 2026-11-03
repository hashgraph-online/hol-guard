import { renderToStaticMarkup } from "react-dom/server";

import {
  CLOUD_ACTIONS_STATUS_SCHEMA,
  cloudActionsCheckedCopy,
  cloudActionsCurrentState,
  cloudActionsRetryAfterSeconds,
  cloudActionsSignInCommand,
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

function payload(signIns: unknown[], extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema: CLOUD_ACTIONS_STATUS_SCHEMA,
    generated_at: "2026-11-03T12:00:00Z",
    stale_after_seconds: 300,
    check_interval_seconds: 60,
    next_check_allowed_at: null,
    sign_ins: signIns,
    included_actions: "not_available_yet",
    accounts: "not_available_yet",
    ...extra,
  };
}

const connected = {
  profile: "default",
  workspace: "ws_alpha",
  site: "cloud.example.test",
  signed_in_at: "2026-11-03T10:00:00Z",
  expires_at: "2026-11-03T22:00:00Z",
  expired: false,
  state: "connected",
  check: {
    checked_at: "2026-11-03T11:58:00Z",
    stale: false,
    service: { state: "current", message: "Guard Cloud offers Cloud actions as this sign-in expects." },
    connection: { state: "connected", message: "Guard Cloud accepted this sign-in." },
  },
};

const ended = {
  profile: "client",
  workspace: "ws_beta",
  site: "cloud.example.test:8443",
  cloud_url: "https://cloud.example.test:8443",
  signed_in_at: "2026-11-01T10:00:00Z",
  expires_at: "2026-11-02T10:00:00Z",
  expired: true,
  state: "sign_in_expired",
  check: {
    checked_at: "2026-11-03T09:00:00Z",
    stale: true,
    service: { state: "current", message: "Guard Cloud offers Cloud actions as this sign-in expects." },
    connection: { state: "sign_in_again", message: "Guard Cloud no longer accepts this sign-in. Sign in again." },
  },
};

// A report from another schema version is not guessed at.
assert(normalizeCloudActionsStatus({ ...payload([connected]), schema: "other" }) === null, "unknown schema is rejected");
assert(normalizeCloudActionsStatus({ schema: CLOUD_ACTIONS_STATUS_SCHEMA }) === null, "missing rows are rejected");
assert(normalizeCloudActionsStatus(null) === null, "null is rejected");

const status = normalizeCloudActionsStatus(payload([connected, ended]));
assert(status !== null && status.signIns.length === 2, "both sign-ins are read");
const [first, second] = status.signIns;
assert(first.workspace === "ws_alpha" && first.site === "cloud.example.test", "workspace and site stay explicit");
assert(first.check.message === "Guard Cloud accepted this sign-in.", "connection message is shown once the service check passed");
assert(second.check.stale, "an old answer is marked stale");

// The service answer wins when Guard Cloud itself is not offering Cloud actions.
const offline = normalizeCloudActionsStatus(payload([{
  ...connected,
  state: "offline",
  check: { ...connected.check, service: { state: "offline", message: "Guard Cloud could not be reached." } },
}]));
assert(offline?.signIns[0]?.check.message === "Guard Cloud could not be reached.", "service failure message is shown");

// Values that would end up in a copyable command must look like IDs.
const hostile = normalizeCloudActionsStatus(payload([
  { ...connected, profile: "work", workspace: "ws; rm -rf ~", site: "evil.test/path?x" },
  { ...connected, profile: "../escape" },
]));
assert(hostile?.signIns.length === 1, "a sign-in with an invalid name is dropped");
assert(hostile.signIns[0]?.workspace === null, "a workspace that is not an ID is not shown");
assert(hostile.signIns[0]?.site === null, "a site that is not a host is not shown");
assert(
  cloudActionsSignInCommand(hostile.signIns[0]!) === "hol-guard cloud-actions login --cloud-url <guard-cloud-address> --profile work",
  "the sign-in command never carries an unchecked workspace or site",
);
assert(
  cloudActionsSignInCommand(second) ===
    "hol-guard cloud-actions login --cloud-url https://cloud.example.test:8443 --cloud-workspace ws_beta --profile client",
  "the sign-in command names the same Guard Cloud, workspace and sign-in",
);

// The address only counts when it names the site the row shows, and plain http only for this computer.
function cloudUrlOf(site: string, cloudUrl: string): string | null | undefined {
  return normalizeCloudActionsStatus(payload([{ ...connected, site, cloud_url: cloudUrl }]))?.signIns[0]?.cloudUrl;
}
assert(cloudUrlOf("cloud.example.test", "https://other.example.test") === null, "an address for another site is dropped");
assert(cloudUrlOf("cloud.example.test", "http://cloud.example.test") === null, "plain http to another computer is dropped");
assert(cloudUrlOf("127.0.0.1:3000", "http://127.0.0.1:3000") === "http://127.0.0.1:3000", "plain http on this computer is kept");
assert(
  cloudActionsSignInCommand({ profile: "default", workspace: "ws_alpha", cloudUrl: "https://hol.org" }) ===
    "hol-guard cloud-actions login --cloud-workspace ws_alpha",
  "the default Guard Cloud needs no address",
);
assert(
  cloudActionsSignInCommand({ profile: "default", workspace: null, cloudUrl: null }) ===
    "hol-guard cloud-actions login --cloud-url <guard-cloud-address>",
  "an unknown address is never filled in with the default site",
);

// A message from the daemon is bounded.
const long = normalizeCloudActionsStatus(payload([{
  ...connected,
  check: { ...connected.check, connection: { state: "connected", message: "x".repeat(1000) } },
}]));
assert(long?.signIns[0]?.check.message?.length === 240, "messages are bounded");

// Never-checked rows say so.
const unchecked = normalizeCloudActionsStatus(payload([{ ...connected, state: "not_checked", check: { state: "not_checked" } }]));
assert(unchecked?.signIns[0]?.check.checkedAt === null, "no check time is invented");
assert(cloudActionsCheckedCopy(unchecked.signIns[0]!.check, NOW, 300) === "Not checked yet", "unchecked copy");
assert(cloudActionsCheckedCopy(first.check, NOW, 300) === "Checked 2 minutes ago", "fresh copy");
assert(
  cloudActionsCheckedCopy(second.check, NOW, 300) === "Checked 3 hours ago. This answer may be out of date.",
  "stale copy",
);

// The page stays open, so an answer that was fresh when loaded goes out of date by the clock.
const LATER = new Date(NOW.getTime() + 10 * 60 * 1000);
assert(
  cloudActionsCheckedCopy(first.check, LATER, 300) === "Checked 12 minutes ago. This answer may be out of date.",
  "an answer ages out while the page is open",
);

// A sign-in whose end time passes while the page is open shows as ended.
assert(cloudActionsCurrentState(first, NOW) === "connected", "a live sign-in keeps its state");
const AFTER_END = new Date("2026-11-03T22:00:01Z");
assert(cloudActionsCurrentState(first, AFTER_END) === "sign_in_expired", "a sign-in past its end time has ended");
assert(
  cloudActionsCurrentState({ state: "profile_damaged", expiresAt: "2026-11-02T00:00:00Z" }, NOW) === "profile_damaged",
  "a damaged sign-in keeps that state",
);

// Every state the daemon reports has plain copy; none of them blames local protection.
for (const state of [
  "connected", "current", "not_checked", "offline", "not_turned_on", "sign_in_expired", "sign_in_again",
  "changed", "not_permitted", "workspace_mismatch", "unexpected_answer", "profile_damaged",
]) {
  const copy = cloudActionsStateCopy(state);
  assert(copy.label !== "Unknown", `${state} has a label`);
  assert(!/protection|token|gateway|endpoint|agent|receipt/i.test(`${copy.label} ${copy.remedy ?? ""}`), `${state} copy stays in plain terms`);
}
assert(cloudActionsStateCopy("something_new").label === "Unknown", "unknown states are not guessed");
assert(cloudActionsStateCopy("sign_in_expired").signInAgain, "an ended sign-in offers signing in again");
assert(!cloudActionsStateCopy("not_permitted").signInAgain, "signing in again does not fix missing access");

assert(cloudActionsRetryAfterSeconds("2026-11-03T12:00:42Z", NOW) === 42, "retry wait is read");
assert(cloudActionsRetryAfterSeconds("2026-11-03T11:59:00Z", NOW) === 0, "past wait is zero");
assert(cloudActionsRetryAfterSeconds(null, NOW) === 0, "no wait without a check");
assert(cloudActionsSummary(status, NOW) === "2 sign-ins on this computer. 1 needs attention.", "summary counts attention");

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

const html = render();
assert(html.includes("Protection on this computer does not depend on Cloud actions."), "local protection independence is stated");
assert(html.includes("ws_alpha") && html.includes("ws_beta"), "each workspace is named");
assert(html.includes("cloud.example.test:8443"), "each Guard Cloud site is named");
assert(html.includes("Sign-in ended") && html.includes("Connected"), "each state is labelled");
assert(html.includes("This answer may be out of date."), "stale answers are labelled");
assert(
  html.includes("hol-guard cloud-actions login --cloud-url https://cloud.example.test:8443 --cloud-workspace ws_beta --profile client"),
  "sign in again command",
);
assert(cloudActionsSummary(status, AFTER_END) === "2 sign-ins on this computer. 2 need attention.", "summary follows the clock");
const endedLater = render({ now: AFTER_END });
assert(!endedLater.includes(">Connected<"), "a sign-in past its end time is not shown as connected");
assert(!endedLater.includes("Guard Cloud accepted this sign-in."), "an old answer does not contradict the current state");
assert(html.includes(">Check now<"), "check button is offered with sign-ins");
assert(!/token|gateway|endpoint|harness|posture|receipt/i.test(html.replace(/<[^>]+>/g, " ")), "page copy stays in plain terms");

assert(render({ retryAfterSeconds: 12 }).includes("Check again in 12s"), "the wait is shown on the button");
assert(render({ checking: true }).includes("Checking..."), "checking state");

const empty = render({ status: normalizeCloudActionsStatus(payload([])) });
assert(empty.includes("No AI tool on this computer is signed in to Cloud actions."), "empty state");
assert(!empty.includes("Check now"), "no check button without sign-ins");
assert(empty.includes("Protection on this computer does not depend on Cloud actions."), "independence stated when empty");

const failed = render({ status: null, error: "Guard on this computer did not answer." });
assert(failed.includes("Guard on this computer did not answer."), "daemon failure is shown");
assert(failed.includes("Protection on this computer does not depend on Cloud actions."), "independence stated on failure");

console.log("cloud-actions-settings.test.tsx: all tests passed");
