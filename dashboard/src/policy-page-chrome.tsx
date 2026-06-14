import { useCallback, type KeyboardEvent } from "react";
import { HiMiniArrowPath } from "react-icons/hi2";
import { ActionButton, Badge } from "./approval-center-primitives";
import type { GuardRuntimeSnapshot } from "./guard-types";
import { resolvePolicyViewLabel, type PolicyPageView } from "./policy-workspace";

const POLICY_VIEWS: PolicyPageView[] = ["rules", "exceptions", "strict"];

type PolicyUnderlineTabBarProps = {
  activeView: PolicyPageView;
  onViewChange: (view: PolicyPageView) => void;
};

export function PolicyUnderlineTabBar({ activeView, onViewChange }: PolicyUnderlineTabBarProps) {
  const handleKeyDown = useCallback(
    (event: KeyboardEvent<HTMLButtonElement>, view: PolicyPageView) => {
      const index = POLICY_VIEWS.indexOf(view);
      if (index < 0) {
        return;
      }
      let nextView: PolicyPageView | undefined;
      if (event.key === "ArrowRight") {
        nextView = POLICY_VIEWS[(index + 1) % POLICY_VIEWS.length];
      } else if (event.key === "ArrowLeft") {
        nextView = POLICY_VIEWS[(index - 1 + POLICY_VIEWS.length) % POLICY_VIEWS.length];
      }
      if (nextView) {
        event.preventDefault();
        onViewChange(nextView);
        document.getElementById(`policy-tab-${nextView}`)?.focus();
      }
    },
    [onViewChange],
  );

  return (
    <div
      className="flex flex-wrap gap-6 border-b border-slate-200"
      role="tablist"
      aria-label="Policy sections"
    >
      {POLICY_VIEWS.map((view) => {
        const selected = activeView === view;
        return (
          <button
            key={view}
            type="button"
            role="tab"
            id={`policy-tab-${view}`}
            aria-controls={`policy-panel-${view}`}
            aria-selected={selected}
            tabIndex={selected ? 0 : -1}
            onClick={() => onViewChange(view)}
            onKeyDown={(event) => handleKeyDown(event, view)}
            className={`-mb-px border-b-2 px-1 pb-3 text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${
              selected
                ? "border-brand-blue text-brand-blue"
                : "border-transparent text-slate-500 hover:border-slate-300 hover:text-brand-dark"
            }`}
          >
            {resolvePolicyViewLabel(view)}
          </button>
        );
      })}
    </div>
  );
}

function resolveHealthTone(snapshot: GuardRuntimeSnapshot): "success" | "attention" | "default" {
  if (snapshot.headline_state === "protected" || snapshot.headline_state === "connected") {
    return "success";
  }
  if (snapshot.headline_state === "blocked" || snapshot.headline_state === "setup") {
    return "attention";
  }
  return "default";
}

type PolicyPageToolbarProps = {
  snapshot: GuardRuntimeSnapshot;
  onReloadPolicy?: () => void;
  reloading?: boolean;
};

export function PolicyPageToolbar({ snapshot, onReloadPolicy, reloading = false }: PolicyPageToolbarProps) {
  const handleReload = useCallback(() => {
    onReloadPolicy?.();
  }, [onReloadPolicy]);

  return (
    <div className="flex flex-wrap items-center justify-end gap-2">
      <Badge tone={resolveHealthTone(snapshot)}>{snapshot.headline_label}</Badge>
      {onReloadPolicy ? (
        <ActionButton variant="secondary" onClick={handleReload} disabled={reloading}>
          <HiMiniArrowPath className={`mr-1.5 h-4 w-4 ${reloading ? "animate-spin" : ""}`} aria-hidden="true" />
          Reload policy
        </ActionButton>
      ) : null}
    </div>
  );
}
