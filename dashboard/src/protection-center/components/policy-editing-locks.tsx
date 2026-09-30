import { HiMiniExclamationTriangle, HiMiniLockClosed } from "react-icons/hi2";

import type { EffectiveExtensionControls } from "../../extension-controls-api";

/**
 * The editing-lock notices shared by the policy panel and the search console,
 * so both surfaces explain a locked control with the same words.
 */
export function PolicyEditingLocks(props: {
  health?: EffectiveExtensionControls["health"];
  globalLockdown?: boolean;
  refreshRequired?: boolean;
}) {
  return (
    <>
      {props.globalLockdown ? (
        <p role="status" className="mt-4 flex gap-2 text-sm text-brand-dark">
          <HiMiniLockClosed className="mt-0.5 size-4 shrink-0" />
          Emergency Lockdown remains dominant. You can prepare a local draft, but matching commands stay blocked while lockdown is active.
        </p>
      ) : null}
      {props.health !== undefined && props.health !== "protected" ? (
        <p role="alert" className="mt-4 flex gap-2 text-sm text-amber-950">
          <HiMiniExclamationTriangle className="mt-0.5 size-4 shrink-0" />
          Settings cannot be changed until Guard verifies local settings integrity.
        </p>
      ) : null}
      {props.refreshRequired ? (
        <p role="status" className="mt-4 text-sm text-blue-950">Settings applied. Editing stays locked until Guard reloads the current protected state.</p>
      ) : null}
    </>
  );
}
