import type { MouseEvent as ReactMouseEvent } from "react";

import { guardAwareHref } from "./guard-api";
import {
  isNavigationItemActive,
  queueAriaLabel,
  queueCountDisplay,
} from "./shell-navigation-model";
import type { ShellNavigationItem, ShellNavigationProps } from "./shell-navigation-model";

type NavigateProps = Pick<ShellNavigationProps, "onNavigate"> & {
  onBeforeNavigate?: () => void;
};

export function shellHref(pathname: string): string {
  return typeof window === "undefined" ? pathname : guardAwareHref(pathname);
}

export function navigateFromAnchor(
  event: ReactMouseEvent<HTMLAnchorElement>,
  pathname: string,
  props: NavigateProps,
): void {
  if (
    event.defaultPrevented ||
    event.button !== 0 ||
    event.metaKey ||
    event.ctrlKey ||
    event.shiftKey ||
    event.altKey
  ) {
    return;
  }
  event.preventDefault();
  props.onBeforeNavigate?.();
  props.onNavigate(pathname);
}

export function NavigationLink(props: {
  item: ShellNavigationItem;
  view: ShellNavigationProps["view"];
  queuedCount: number;
  variant: "sidebar" | "drawer" | "bottom";
  onNavigate: (pathname: string) => void;
  onBeforeNavigate?: () => void;
}) {
  const Icon = props.item.icon;
  const active = isNavigationItemActive(props.item, props.view);
  const accessibleLabel =
    props.item.view === "inbox" ? queueAriaLabel(props.queuedCount) : props.item.label;
  return (
    <a
      href={shellHref(props.item.href)}
      aria-current={active ? "page" : undefined}
      aria-label={accessibleLabel}
      data-navigation-item={props.item.view}
      data-navigation-variant={props.variant}
      data-active={active ? "true" : "false"}
      className={`guard-shell-navigation-link guard-shell-navigation-link--${props.variant}`}
      title={props.variant === "sidebar" ? props.item.label : undefined}
      onClick={(event) =>
        navigateFromAnchor(event, props.item.href, {
          onNavigate: props.onNavigate,
          onBeforeNavigate: props.onBeforeNavigate,
        })
      }
    >
      <span className="guard-shell-navigation-link__icon" aria-hidden="true">
        <Icon />
      </span>
      <span className="guard-shell-navigation-link__label">
        {props.variant === "bottom" ? props.item.shortLabel : props.item.label}
      </span>
      {props.variant === "drawer" ? (
        <span className="guard-shell-navigation-link__description">{props.item.description}</span>
      ) : null}
      {props.item.badge ? (
        // Decorative status chip: the link's aria-label already names the
        // destination, matching how the Inbox count badge is announced.
        <span
          className="guard-shell-navigation-link__badge guard-shell-navigation-link__flag"
          aria-hidden="true"
        >
          {props.item.badge}
        </span>
      ) : null}
      {props.item.view === "inbox" && props.queuedCount > 0 ? (
        <span className="guard-shell-navigation-link__badge" aria-hidden="true">
          {queueCountDisplay(props.queuedCount)}
        </span>
      ) : null}
    </a>
  );
}
