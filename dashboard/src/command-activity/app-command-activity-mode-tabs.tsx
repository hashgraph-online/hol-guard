import { useCallback, type KeyboardEvent } from "react";

export type AppActivityMode = "recorded" | "commands" | "pending";

function ActivityModeButton(props: {
  mode: AppActivityMode;
  value: AppActivityMode;
  label: string;
  onChange: (mode: AppActivityMode) => void;
}) {
  const active = props.mode === props.value;
  const handleClick = useCallback(() => props.onChange(props.value), [props.onChange, props.value]);
  return (
    <button
      id={`app-activity-tab-${props.value}`}
      type="button"
      role="tab"
      aria-selected={active}
      aria-controls={`app-activity-panel-${props.value}`}
      tabIndex={active ? 0 : -1}
      onClick={handleClick}
      className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
        active
          ? "bg-white text-brand-dark shadow-sm"
          : "text-slate-500 hover:text-brand-dark"
      }`}
    >
      {props.label}
    </button>
  );
}

export function AppCommandActivityModeTabs(props: {
  mode: AppActivityMode;
  pendingCount: number;
  onChange: (mode: AppActivityMode) => void;
}) {
  const handleKeyDown = useCallback((event: KeyboardEvent<HTMLDivElement>) => {
    if (!new Set(["ArrowLeft", "ArrowRight", "Home", "End"]).has(event.key)) return;
    const tabs = Array.from(event.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]'));
    const current = tabs.indexOf(document.activeElement as HTMLButtonElement);
    if (current < 0) return;
    event.preventDefault();
    let next = current;
    if (event.key === "ArrowLeft") next = (current - 1 + tabs.length) % tabs.length;
    if (event.key === "ArrowRight") next = (current + 1) % tabs.length;
    if (event.key === "Home") next = 0;
    if (event.key === "End") next = tabs.length - 1;
    tabs[next]?.focus();
    tabs[next]?.click();
  }, []);

  return (
    <div
      className="inline-flex flex-wrap gap-1 rounded-lg border border-slate-200 bg-slate-50 p-0.5"
      role="tablist"
      aria-label="App activity type"
      onKeyDown={handleKeyDown}
    >
      <ActivityModeButton mode={props.mode} value="recorded" label="Recorded actions" onChange={props.onChange} />
      <ActivityModeButton mode={props.mode} value="commands" label="Command protection" onChange={props.onChange} />
      <ActivityModeButton mode={props.mode} value="pending" label={`Pending (${props.pendingCount})`} onChange={props.onChange} />
    </div>
  );
}
