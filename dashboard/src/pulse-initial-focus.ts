/** A vertical span in viewport coordinates. */
export type PulseBox = { top: number; bottom: number };

/** The part of an element this module reads, so tests can pass a stand-in without a browser. */
export type PulseMeasurable = {
  getBoundingClientRect: () => PulseBox;
  parentElement: PulseMeasurable | null;
};

export type PulseView = {
  innerHeight: number;
  overflowY: (node: PulseMeasurable) => string;
};

export function boxWithin(inner: PulseBox, outer: PulseBox): boolean {
  return inner.top >= outer.top && inner.bottom <= outer.bottom;
}

/**
 * Whether the element is fully inside the viewport and inside every scrolling or clipping ancestor, such
 * as the setup modal's own scroll area. A field below the fold of a short window is not in view even
 * though the window itself is wide.
 */
export function isFullyVisible(element: PulseMeasurable, view: PulseView): boolean {
  let clip: PulseBox = { top: 0, bottom: view.innerHeight };
  for (let node = element.parentElement; node !== null; node = node.parentElement) {
    if (view.overflowY(node) === "visible") continue;
    const rect = node.getBoundingClientRect();
    clip = { top: Math.max(clip.top, rect.top), bottom: Math.min(clip.bottom, rect.bottom) };
  }
  return boxWithin(element.getBoundingClientRect(), clip);
}

/** Where focus goes when the connect step opens, and whether the browser may scroll to get it there. */
export type PulseFocusPlan = { target: "key" | "qr"; scroll: boolean };

/**
 * The key field takes focus when the user can see it. Otherwise focus starts on the QR panel at the top
 * of the step, and the next Tab reaches the field: focusing a field nobody can see leaves keyboard users
 * typing blind. The panel is focused without scrolling while it is in view, so opening the step never
 * carries the QR code away before it can be scanned. When it is not in view, such as a very short window
 * or a modal that kept its scroll position from the last step, focusing scrolls it into view.
 */
export function pulseInitialFocusPlan(keyFieldVisible: boolean, qrPanelVisible: boolean): PulseFocusPlan {
  if (keyFieldVisible) return { target: "key", scroll: false };
  return { target: "qr", scroll: !qrPanelVisible };
}

/** Focus an element, scrolling only when the plan says the user cannot see it yet. */
export function focusForPlan(element: { focus: (options?: FocusOptions) => void } | null, scroll: boolean): void {
  element?.focus({ preventScroll: !scroll });
}

/** The browser's view, for the real call. */
export function browserView(): PulseView {
  return {
    innerHeight: window.innerHeight,
    overflowY: (node) => window.getComputedStyle(node as unknown as Element).overflowY,
  };
}
