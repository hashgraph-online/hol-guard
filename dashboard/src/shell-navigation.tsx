import { useCallback, useEffect, useState } from "react";
import {
  HiBars3,
  HiMiniArrowTopRightOnSquare,
  HiMiniBugAnt,
  HiMiniChevronLeft,
  HiMiniChevronRight,
  HiMiniCommandLine,
  HiMiniInbox,
  HiMiniShieldCheck,
} from "react-icons/hi2";

import { CloudUserMenu } from "./cloud-user-menu";
import { GuardUpdatePanel } from "./guard-update-panel";
import { GITHUB_ISSUE_BUTTON_LABEL, GITHUB_ISSUE_LINK } from "./github-issue-link";
import { OpenGuardCloudAction } from "./open-guard-cloud-action";
import { NavigationDrawer } from "./shell-navigation-drawer";
import { NavigationLink, navigateFromAnchor, shellHref } from "./shell-navigation-link";
import { LocalGuardStatusCopy } from "./shell-navigation-status";
import {
  isMobilePrimaryView,
  mobilePrimaryNavigationItems,
  navigationItemForView,
  queueAriaLabel,
  queueCountDisplay,
  NAVIGATION_GROUPS,
  SHELL_NAV_ITEMS,
} from "./shell-navigation-model";
import type { ShellNavigationProps } from "./shell-navigation-model";

function NavigationTrigger(props: {
  open: boolean;
  onOpen: () => void;
  className: string;
  testId: string;
  updateAvailable: boolean;
}) {
  return (
    <button
      type="button"
      className={props.className}
      data-testid={props.testId}
      aria-label="Open all Guard sections"
      aria-expanded={props.open}
      aria-controls="guard-navigation-drawer"
      onClick={props.onOpen}
    >
      <HiBars3 aria-hidden="true" />
      {props.updateAvailable ? (
        <span className="guard-shell-navigation-update-dot" aria-hidden="true" />
      ) : null}
    </button>
  );
}

function MobileHeader(
  props: ShellNavigationProps & { drawerOpen: boolean; onOpenDrawer: () => void },
) {
  const currentItem = navigationItemForView(props.view);
  return (
    <header
      className="guard-shell-mobile-header"
      data-testid="guard-shell-mobile-header"
      data-navigation-surface="persistent"
    >
      <NavigationTrigger
        open={props.drawerOpen}
        onOpen={props.onOpenDrawer}
        className="guard-shell-mobile-header__button"
        testId="mobile-navigation-trigger"
        updateAvailable={Boolean(props.updateStatus?.update_available)}
      />
      <a
        href={shellHref("/")}
        className="guard-shell-mobile-header__brand"
        aria-label="HOL Guard Home"
        onClick={(event) => navigateFromAnchor(event, "/", props)}
      >
        <img src="/brand/Logo_Icon_Dark.png" alt="" aria-hidden="true" />
        <span className="guard-shell-mobile-header__brand-name">HOL Guard</span>
      </a>
      <div className="guard-shell-mobile-header__location" aria-live="polite">
        <span>Current section</span>
        <strong>{currentItem.label}</strong>
      </div>
      <a
        href={shellHref("/inbox")}
        className="guard-shell-mobile-header__queue"
        aria-label={queueAriaLabel(props.queuedCount)}
        onClick={(event) => navigateFromAnchor(event, "/inbox", props)}
      >
        <HiMiniInbox aria-hidden="true" />
        <span>{queueCountDisplay(props.queuedCount)}</span>
      </a>
    </header>
  );
}

function PersistentSidebar(
  props: ShellNavigationProps & { drawerOpen: boolean; onOpenDrawer: () => void },
) {
  return (
    <aside
      className="guard-shell-sidebar"
      data-testid="guard-shell-sidebar"
      data-navigation-surface="persistent"
      data-collapsed={props.collapsed ? "true" : "false"}
    >
      <div className="guard-shell-sidebar__brand-row">
        <a
          href={shellHref("/")}
          className="guard-shell-sidebar__brand"
          aria-label="HOL Guard Home"
          onClick={(event) => navigateFromAnchor(event, "/", props)}
        >
          <img src="/brand/Logo_Icon_Dark.png" alt="" aria-hidden="true" />
          <span className="guard-shell-sidebar__expanded-only">HOL Guard</span>
        </a>
        <button
          type="button"
          className="guard-shell-sidebar__collapse guard-shell-sidebar__expanded-only"
          onClick={props.onToggleCollapse}
          aria-label="Collapse sidebar"
          title="Collapse sidebar"
        >
          <HiMiniChevronLeft aria-hidden="true" />
        </button>
        <button
          type="button"
          className="guard-shell-sidebar__expand guard-shell-sidebar__collapsed-only"
          onClick={props.onToggleCollapse}
          aria-label="Expand sidebar"
          title="Expand sidebar"
        >
          <HiMiniChevronRight aria-hidden="true" />
        </button>
      </div>

      <div className="guard-shell-sidebar__scroll">
        <NavigationTrigger
          open={props.drawerOpen}
          onOpen={props.onOpenDrawer}
          className="guard-shell-sidebar__drawer-trigger guard-shell-sidebar__collapsed-only"
          testId="compact-navigation-trigger"
          updateAvailable={Boolean(props.updateStatus?.update_available)}
        />

        <nav className="guard-shell-sidebar__nav" aria-label="Guard dashboard">
          {NAVIGATION_GROUPS.map((group) => (
            <div
              key={group.id}
              className="guard-shell-sidebar__nav-group"
              data-navigation-group={group.id}
            >
              <p className="guard-shell-sidebar__group-label guard-shell-sidebar__expanded-only">
                {group.label}
              </p>
              {SHELL_NAV_ITEMS.filter((item) => item.group === group.id).map((item) => (
                <NavigationLink
                  key={item.href}
                  item={item}
                  view={props.view}
                  queuedCount={props.queuedCount}
                  variant="sidebar"
                  onNavigate={props.onNavigate}
                />
              ))}
            </div>
          ))}
        </nav>

        <div className="guard-shell-sidebar__quick-actions guard-shell-sidebar__expanded-only">
          <p className="guard-shell-sidebar__group-label">Quick actions</p>
          <a href={shellHref("/")} onClick={(event) => navigateFromAnchor(event, "/", props)}>
            <HiMiniCommandLine aria-hidden="true" />
            <span>Local dashboard</span>
          </a>
          <OpenGuardCloudAction variant="sidebar" />
          <a href={GITHUB_ISSUE_LINK} target="_blank" rel="noopener noreferrer">
            <HiMiniBugAnt aria-hidden="true" />
            <span>{GITHUB_ISSUE_BUTTON_LABEL}</span>
            <HiMiniArrowTopRightOnSquare aria-hidden="true" />
          </a>
        </div>

        <div className="guard-shell-sidebar__footer">
          {props.cloudUserProfile ? (
            <>
              <div className="guard-shell-sidebar__account guard-shell-sidebar__expanded-only">
                <CloudUserMenu
                  userProfile={props.cloudUserProfile}
                  workspaceId={props.workspaceId}
                  planId={props.planId}
                  collapsed={false}
                />
              </div>
              <div className="guard-shell-sidebar__account guard-shell-sidebar__collapsed-only">
                <CloudUserMenu
                  userProfile={props.cloudUserProfile}
                  workspaceId={props.workspaceId}
                  planId={props.planId}
                  collapsed
                />
              </div>
            </>
          ) : null}

          <div className="guard-shell-sidebar__status guard-shell-sidebar__expanded-only">
            <div className="guard-shell-sidebar__status-heading">
              <HiMiniShieldCheck aria-hidden="true" />
              <span>Local Guard</span>
              <strong>{props.queuedCount > 0 ? "Review" : "Clear"}</strong>
            </div>
            <LocalGuardStatusCopy queuedCount={props.queuedCount} onNavigate={props.onNavigate} />
            <GuardUpdatePanel
              guardVersion={props.guardVersion}
              updateStatus={props.updateStatus}
              updatePhase={props.updatePhase}
              updateError={props.updateError}
              onUpdateGuard={props.onUpdateGuard}
              onReinstallGuard={props.onReinstallGuard}
              approvalGate={props.approvalGate}
            />
          </div>

          <div className="guard-shell-sidebar__compact-status guard-shell-sidebar__collapsed-only">
            <span className="guard-shell-sidebar__compact-count" aria-label={queueAriaLabel(props.queuedCount)}>
              {queueCountDisplay(props.queuedCount)}
            </span>
            {props.guardVersion ? (
              <span title={`Guard version ${props.guardVersion}`}>v{props.guardVersion}</span>
            ) : null}
          </div>
        </div>
      </div>
    </aside>
  );
}

function MobileBottomNavigation(
  props: ShellNavigationProps & { drawerOpen: boolean; onOpenDrawer: () => void },
) {
  const moreActive = !isMobilePrimaryView(props.view);
  return (
    <nav
      className="guard-shell-bottom-nav"
      aria-label="Primary Guard sections"
      data-testid="mobile-bottom-navigation"
      data-navigation-surface="persistent"
    >
      {mobilePrimaryNavigationItems().map((item) => (
        <NavigationLink
          key={item.href}
          item={item}
          view={props.view}
          queuedCount={props.queuedCount}
          variant="bottom"
          onNavigate={props.onNavigate}
        />
      ))}
      <button
        type="button"
        className="guard-shell-navigation-link guard-shell-navigation-link--bottom"
        data-navigation-item="more"
        data-active={moreActive ? "true" : "false"}
        data-testid="mobile-more-navigation"
        aria-label="More Guard sections"
        aria-current={moreActive ? "page" : undefined}
        aria-expanded={props.drawerOpen}
        aria-controls="guard-navigation-drawer"
        onClick={props.onOpenDrawer}
      >
        <span className="guard-shell-navigation-link__icon" aria-hidden="true">
          <HiBars3 />
        </span>
        <span className="guard-shell-navigation-link__label">More</span>
        {props.updateStatus?.update_available ? (
          <span className="guard-shell-navigation-update-dot" aria-hidden="true" />
        ) : null}
      </button>
    </nav>
  );
}

export function ShellNavigation(props: ShellNavigationProps) {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const openDrawer = useCallback(() => setDrawerOpen(true), []);
  const closeDrawer = useCallback(() => setDrawerOpen(false), []);

  useEffect(() => {
    setDrawerOpen(false);
  }, [props.view]);

  useEffect(() => {
    const persistentQuery = window.matchMedia("(min-width: 48rem)");
    const expandedQuery = window.matchMedia("(min-width: 80rem)");
    const closeForResponsiveMode = (event: MediaQueryListEvent) => {
      if (event.matches) setDrawerOpen(false);
    };
    persistentQuery.addEventListener("change", closeForResponsiveMode);
    expandedQuery.addEventListener("change", closeForResponsiveMode);
    return () => {
      persistentQuery.removeEventListener("change", closeForResponsiveMode);
      expandedQuery.removeEventListener("change", closeForResponsiveMode);
    };
  }, []);

  return (
    <>
      <MobileHeader {...props} drawerOpen={drawerOpen} onOpenDrawer={openDrawer} />
      <PersistentSidebar {...props} drawerOpen={drawerOpen} onOpenDrawer={openDrawer} />
      <MobileBottomNavigation {...props} drawerOpen={drawerOpen} onOpenDrawer={openDrawer} />
      <NavigationDrawer {...props} open={drawerOpen} onClose={closeDrawer} />
    </>
  );
}
