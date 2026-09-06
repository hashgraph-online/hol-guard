import { useCallback, useEffect, useRef } from "react";
import type { RefObject } from "react";
import {
  HiMiniArrowTopRightOnSquare,
  HiMiniBugAnt,
  HiMiniCommandLine,
  HiMiniXMark,
} from "react-icons/hi2";

import { CloudUserMenu } from "./cloud-user-menu";
import { GuardUpdatePanel } from "./guard-update-panel";
import { GITHUB_ISSUE_BUTTON_LABEL, GITHUB_ISSUE_LINK } from "./github-issue-link";
import { OpenGuardCloudAction } from "./open-guard-cloud-action";
import { NavigationLink, navigateFromAnchor, shellHref } from "./shell-navigation-link";
import { LocalGuardStatusCopy } from "./shell-navigation-status";
import {
  NAVIGATION_GROUPS,
  SHELL_NAV_ITEMS,
} from "./shell-navigation-model";
import type { ShellNavigationProps } from "./shell-navigation-model";

function focusableElements(container: HTMLElement): HTMLElement[] {
  const selector = [
    "a[href]",
    "button:not([disabled])",
    "input:not([disabled])",
    "select:not([disabled])",
    "textarea:not([disabled])",
    '[tabindex]:not([tabindex="-1"])',
  ].join(",");
  return Array.from(container.querySelectorAll<HTMLElement>(selector)).filter(
    (element) => !element.hasAttribute("hidden") && element.getAttribute("aria-hidden") !== "true",
  );
}

function useNavigationDrawerFocus(
  open: boolean,
  dialogRef: RefObject<HTMLElement | null>,
  closeButtonRef: RefObject<HTMLButtonElement | null>,
  onClose: () => void,
) {
  const restoreFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;

    restoreFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const persistentSurfaces = Array.from(
      document.querySelectorAll<HTMLElement>('[data-navigation-surface="persistent"], .guard-shell-content'),
    );
    persistentSurfaces.forEach((surface) => surface.setAttribute("inert", ""));

    const focusFrame = window.requestAnimationFrame(() => closeButtonRef.current?.focus());
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab" || dialogRef.current === null) return;
      const focusable = focusableElements(dialogRef.current);
      if (focusable.length === 0) {
        event.preventDefault();
        dialogRef.current.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", handleKeyDown);

    return () => {
      window.cancelAnimationFrame(focusFrame);
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = previousOverflow;
      persistentSurfaces.forEach((surface) => surface.removeAttribute("inert"));
      const restoreTarget = restoreFocusRef.current;
      restoreFocusRef.current = null;
      if (restoreTarget?.isConnected && restoreTarget.getClientRects().length > 0) {
        restoreTarget.focus();
      }
    };
  }, [open, dialogRef, closeButtonRef, onClose]);

  return useCallback(() => {
    restoreFocusRef.current = null;
  }, []);
}

export function NavigationDrawer(
  props: ShellNavigationProps & { open: boolean; onClose: () => void },
) {
  const dialogRef = useRef<HTMLElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const suppressFocusRestore = useNavigationDrawerFocus(
    props.open,
    dialogRef,
    closeButtonRef,
    props.onClose,
  );

  if (!props.open) return null;

  const handleNavigate = (pathname: string) => {
    suppressFocusRestore();
    props.onClose();
    props.onNavigate(pathname);
  };

  return (
    <div className="guard-navigation-drawer-layer" data-testid="navigation-drawer">
      <button
        type="button"
        className="guard-navigation-drawer-scrim"
        aria-label="Close navigation"
        onClick={props.onClose}
      />
      <section
        id="guard-navigation-drawer"
        ref={dialogRef}
        className="guard-navigation-drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby="guard-navigation-drawer-title"
        tabIndex={-1}
      >
        <header className="guard-navigation-drawer__header">
          <div>
            <p>HOL Guard</p>
            <h2 id="guard-navigation-drawer-title">All sections</h2>
          </div>
          <button
            ref={closeButtonRef}
            type="button"
            aria-label="Close navigation"
            onClick={props.onClose}
          >
            <HiMiniXMark aria-hidden="true" />
          </button>
        </header>

        <div className="guard-navigation-drawer__body">
          {NAVIGATION_GROUPS.map((group) => (
            <section key={group.id} aria-labelledby={`guard-navigation-group-${group.id}`}>
              <h3 id={`guard-navigation-group-${group.id}`}>{group.label}</h3>
              <nav aria-label={`${group.label} sections`}>
                {SHELL_NAV_ITEMS.filter((item) => item.group === group.id).map((item) => (
                  <NavigationLink
                    key={item.href}
                    item={item}
                    view={props.view}
                    queuedCount={props.queuedCount}
                    variant="drawer"
                    onNavigate={handleNavigate}
                  />
                ))}
              </nav>
            </section>
          ))}

          <section aria-labelledby="guard-navigation-quick-actions">
            <h3 id="guard-navigation-quick-actions">Quick actions</h3>
            <div className="guard-navigation-drawer__quick-actions">
              <a
                href={shellHref("/")}
                onClick={(event) => navigateFromAnchor(event, "/", { onNavigate: handleNavigate })}
              >
                <HiMiniCommandLine aria-hidden="true" />
                <span>Local dashboard</span>
              </a>
              <OpenGuardCloudAction variant="drawer" />
              <a href={GITHUB_ISSUE_LINK} target="_blank" rel="noopener noreferrer">
                <HiMiniBugAnt aria-hidden="true" />
                <span>{GITHUB_ISSUE_BUTTON_LABEL}</span>
                <HiMiniArrowTopRightOnSquare aria-hidden="true" />
              </a>
            </div>
          </section>

          {props.cloudUserProfile ? (
            <section aria-labelledby="guard-navigation-account">
              <h3 id="guard-navigation-account">Account</h3>
              <CloudUserMenu
                userProfile={props.cloudUserProfile}
                workspaceId={props.workspaceId}
                planId={props.planId}
                collapsed={false}
              />
            </section>
          ) : null}

          <section
            className="guard-navigation-drawer__status"
            aria-labelledby="guard-navigation-local-status"
          >
            <h3 id="guard-navigation-local-status">Local Guard</h3>
            <LocalGuardStatusCopy queuedCount={props.queuedCount} onNavigate={handleNavigate} />
            <GuardUpdatePanel
              guardVersion={props.guardVersion}
              updateStatus={props.updateStatus}
              updatePhase={props.updatePhase}
              updateError={props.updateError}
              onUpdateGuard={props.onUpdateGuard}
              onReinstallGuard={props.onReinstallGuard}
              onSetUpdateChannel={props.onSetUpdateChannel}
              approvalGate={props.approvalGate}
            />
          </section>
        </div>
      </section>
    </div>
  );
}
