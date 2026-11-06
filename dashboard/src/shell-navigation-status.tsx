import { HiMiniArrowRight } from "react-icons/hi2";

import { navigateFromAnchor, shellHref } from "./shell-navigation-link";

export function LocalGuardStatusCopy(props: {
  queuedCount: number;
  onNavigate: (pathname: string) => void;
}) {
  if (props.queuedCount <= 0) {
    return (
      <div className="guard-shell-status-copy">
        <p>No local approvals are waiting.</p>
      </div>
    );
  }

  return (
    <div className="guard-shell-status-copy">
      <p>
        {props.queuedCount} local {props.queuedCount === 1 ? "action needs" : "actions need"} a Guard decision.
      </p>
      <a
        href={shellHref("/inbox")}
        className="guard-shell-status-action"
        onClick={(event) => navigateFromAnchor(event, "/inbox", { onNavigate: props.onNavigate })}
      >
        Open Inbox
        <HiMiniArrowRight aria-hidden="true" />
      </a>
    </div>
  );
}
