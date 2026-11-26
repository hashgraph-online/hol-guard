import { HiMiniWindow } from "react-icons/hi2";
import type { GuardBrowserProfileLineV1 } from "../guard-types";
import { browserProfileLabel } from "../mcp-call/browser-card";
import { CardRow, Flag } from "./browser-call-parts";

/** What else the browser can reach, said once beside the profile. */
const REACH: Record<GuardBrowserProfileLineV1, string | null> = {
  shared: "Your signed-in sites and saved data are reachable.",
  "remote-debugging": "Anything attached to this browser can drive it.",
  unknown: "Guard treats it as your own profile.",
  dedicated: null,
  isolated: null,
};

/** Which browser the step runs in. A profile that holds your sign-ins is flagged. */
export function BrowserProfileLine({ profile }: { profile: GuardBrowserProfileLineV1 }) {
  const reach = REACH[profile];
  return (
    <CardRow icon={HiMiniWindow} label="Browser">
      <span className="text-brand-dark">{browserProfileLabel(profile)}</span>
      {reach !== null && (
        <span className="mt-1.5">
          <Flag tone="attention">{reach}</Flag>
        </span>
      )}
    </CardRow>
  );
}
