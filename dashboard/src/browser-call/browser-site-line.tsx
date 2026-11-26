import { HiMiniGlobeAlt } from "react-icons/hi2";
import type { GuardBrowserCardV1 } from "../guard-types";
import { browserSiteLabel } from "../mcp-call/browser-card";
import { CardRow, Flag } from "./browser-call-parts";

/** The site the step acts on, and whether the task has been there before. */
export function BrowserSiteLine({ site }: { site: GuardBrowserCardV1["site"] }) {
  const label = browserSiteLabel(site.origin);
  return (
    <CardRow icon={HiMiniGlobeAlt} label="Site">
      {label !== null ? (
        <span className="break-all font-mono text-[13px] text-brand-dark" title={site.origin ?? undefined}>
          {label}
        </span>
      ) : (
        <span className="text-brand-dark/80">Guard could not tell which site</span>
      )}
      {(site.first_visit_in_task || site.left_granted_site) && (
        <span className="mt-1.5 flex flex-wrap gap-1.5">
          {site.first_visit_in_task && <Flag tone="note">First visit in this task</Flag>}
          {site.left_granted_site && <Flag tone="attention">Outside the site you allowed</Flag>}
        </span>
      )}
    </CardRow>
  );
}
