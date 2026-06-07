import { useCallback, type ReactNode } from "react";
import { HiMiniChevronRight } from "react-icons/hi2";
import { TabBar } from "../approval-center-primitives";
import {
  localSettingsMobileTabLabels,
  localSettingsNavGroups,
  localSettingsNavItems,
  type LocalSettingsNavItem,
  type LocalSettingsTabKey,
} from "./settings-ia";

export interface SettingsSectionShellProps {
  activeTab: LocalSettingsTabKey;
  onTabChange: (tab: LocalSettingsTabKey) => void;
  intro?: ReactNode;
  children: ReactNode;
}

interface SettingsSectionNavItemProps {
  active: boolean;
  item: LocalSettingsNavItem;
  onSelect: (item: LocalSettingsNavItem) => void;
}

function SettingsSectionNavItem({ active, item, onSelect }: SettingsSectionNavItemProps) {
  const handleClick = useCallback(() => {
    onSelect(item);
  }, [item, onSelect]);

  return (
    <li>
      <button
        type="button"
        onClick={handleClick}
        aria-current={active ? "page" : undefined}
        data-testid={`settings-section-nav-${item.key}`}
        className={`flex min-h-11 w-full flex-col gap-0.5 rounded-lg px-3 py-2 text-left text-sm font-semibold transition-[color,background-color] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/50 ${
          active
            ? "bg-brand-blue/10 text-brand-blue"
            : "text-slate-600 hover:bg-slate-100 hover:text-brand-dark"
        }`}
      >
        <span className="flex min-w-0 items-center gap-2">
          <span className={active ? "text-brand-blue" : "text-slate-400"} aria-hidden="true">
            {item.icon}
          </span>
          <span className="truncate">{item.label}</span>
          {active ? (
            <HiMiniChevronRight className="ml-auto h-4 w-4 shrink-0" aria-hidden="true" />
          ) : null}
        </span>
        <span
          className={`truncate text-[11px] font-normal leading-snug ${
            active ? "text-brand-blue/70" : "text-slate-400"
          }`}
        >
          {item.summary}
        </span>
      </button>
    </li>
  );
}

export function SettingsSectionShell({
  activeTab,
  onTabChange,
  intro,
  children,
}: SettingsSectionShellProps) {
  const handleNavSelect = useCallback(
    (item: LocalSettingsNavItem) => {
      onTabChange(item.key);
    },
    [onTabChange],
  );

  const mobileTabs = localSettingsNavItems.map((item) => ({
    value: item.key,
    label: localSettingsMobileTabLabels[item.key],
    id: `settings-tab-${item.key}`,
  }));

  const activeItem = localSettingsNavItems.find((item) => item.key === activeTab);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-6">
      {intro}
      <div className="flex min-h-0 flex-1 flex-col gap-6 lg:flex-row lg:items-stretch">
        <nav
          aria-label="Settings section navigation"
          data-testid="settings-section-nav"
          className="hidden w-full shrink-0 lg:block lg:w-60"
        >
          <ul className="flex flex-col gap-0.5 p-0">
            {localSettingsNavGroups.map((group) => (
              <li key={group.key} className="flex flex-col">
                <p className="px-3 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-400">
                  {group.label}
                </p>
                <ul className="flex flex-col gap-0.5">
                  {localSettingsNavItems
                    .filter((item) => item.group === group.key)
                    .map((item) => (
                      <SettingsSectionNavItem
                        key={item.key}
                        active={activeTab === item.key}
                        item={item}
                        onSelect={handleNavSelect}
                      />
                    ))}
                </ul>
              </li>
            ))}
          </ul>
        </nav>

        <div className="flex min-h-0 min-w-0 flex-1 flex-col gap-4">
          <div className="-mx-1 overflow-x-auto px-1 lg:hidden">
            <TabBar tabs={mobileTabs} active={activeTab} onChange={onTabChange} />
          </div>
          <div
            role="tabpanel"
            id={`settings-panel-${activeTab}`}
            aria-label={activeItem ? `${activeItem.label} settings` : undefined}
            className="guard-tab-enter flex min-h-[min(28rem,calc(100dvh-18rem))] flex-1 flex-col rounded-2xl border border-slate-100 bg-white p-4 sm:p-6"
          >
            {activeItem ? (
              <header className="mb-5 shrink-0 border-b border-slate-100 pb-4 lg:hidden">
                <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">
                  {activeItem.label}
                </p>
                <p className="mt-1 text-sm text-slate-500">{activeItem.summary}</p>
              </header>
            ) : null}
            <div className="flex min-h-0 flex-1 flex-col">{children}</div>
          </div>
        </div>
      </div>
    </div>
  );
}
