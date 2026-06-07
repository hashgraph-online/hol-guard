import type { ReactNode } from "react";

import { TabBar } from "./approval-center-primitives";

export interface WorkspacePageHeaderProps<T extends string> {
  eyebrow: string;
  title: string;
  tabs: Array<{ value: T; label: string; id?: string }>;
  activeTab: T;
  onTabChange: (value: T) => void;
  actions?: ReactNode;
}

export function WorkspacePageHeader<T extends string>({
  eyebrow,
  title,
  tabs,
  activeTab,
  onTabChange,
  actions,
}: WorkspacePageHeaderProps<T>) {
  return (
    <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div className="space-y-1">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">{eyebrow}</p>
        <h1 className="text-2xl font-semibold tracking-tight text-brand-dark">{title}</h1>
      </div>
      <div className="flex w-full flex-col gap-3 sm:w-auto sm:flex-row sm:items-start sm:justify-end sm:gap-4">
        <div className="-mx-1 w-full overflow-x-auto px-1 pb-1 sm:mx-0 sm:w-auto sm:pb-0 [&>div]:!flex-nowrap">
          <TabBar tabs={tabs} active={activeTab} onChange={onTabChange} />
        </div>
        {actions ? <div className="flex shrink-0 flex-wrap items-center justify-end gap-2">{actions}</div> : null}
      </div>
    </div>
  );
}
