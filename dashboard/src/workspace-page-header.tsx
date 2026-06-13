import type { ReactNode } from "react";

import { TabBar } from "./approval-center-primitives";

type WorkspacePageHeaderBase = {
  eyebrow: string;
  title: string;
  description?: string;
  actions?: ReactNode;
};

type WorkspacePageHeaderTabConfig<T extends string> = {
  tabs: Array<{ value: T; label: string; id?: string }>;
  activeTab: T;
  onTabChange: (value: T) => void;
};

export type WorkspacePageHeaderProps<T extends string> =
  | (WorkspacePageHeaderBase & WorkspacePageHeaderTabConfig<T>)
  | (WorkspacePageHeaderBase & {
      tabs?: undefined;
      activeTab?: undefined;
      onTabChange?: undefined;
    });

function WorkspacePageHeaderToolbar<T extends string>(props: {
  tabConfig: WorkspacePageHeaderTabConfig<T> | null;
  actions?: ReactNode;
}) {
  if (!props.tabConfig && !props.actions) {
    return null;
  }

  return (
    <div className="flex w-full flex-col gap-3 sm:w-auto sm:flex-row sm:items-start sm:justify-end sm:gap-4">
      {props.tabConfig ? (
        <div className="w-full min-w-0 sm:w-auto">
          <TabBar
            tabs={props.tabConfig.tabs}
            active={props.tabConfig.activeTab}
            onChange={props.tabConfig.onTabChange}
          />
        </div>
      ) : null}
      {props.actions ? (
        <div className="flex shrink-0 flex-wrap items-center justify-end gap-2">{props.actions}</div>
      ) : null}
    </div>
  );
}

export function WorkspacePageHeader<T extends string>(props: WorkspacePageHeaderProps<T>) {
  const { eyebrow, title, description, actions } = props;
  const tabConfig =
    props.tabs !== undefined
      ? {
          tabs: props.tabs,
          activeTab: props.activeTab,
          onTabChange: props.onTabChange,
        }
      : null;

  return (
    <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div className="space-y-1">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">{eyebrow}</p>
        <h1 className="text-2xl font-semibold tracking-tight text-brand-dark">{title}</h1>
        {description ? <p className="text-sm text-slate-500">{description}</p> : null}
      </div>
      <WorkspacePageHeaderToolbar tabConfig={tabConfig} actions={actions} />
    </div>
  );
}
