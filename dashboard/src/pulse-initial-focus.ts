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

/**
 * Where focus goes when the connect step opens. The key field takes it when the user can see the field.
 * Otherwise focus starts on the QR panel, which is at the top, and the next Tab reaches the field:
 * focusing a field nobody can see leaves keyboard users typing blind.
 */
export function pulseInitialFocusTarget(keyFieldVisible: boolean): "key" | "qr" {
  return keyFieldVisible ? "key" : "qr";
}

/** Focus without scrolling, so opening the step never carries the QR code out of view before it can be scanned. */
export function focusWithoutScrolling(element: { focus: (options?: FocusOptions) => void } | null): void {
  element?.focus({ preventScroll: true });
}

/** The browser's view, for the real call. */
export function browserView(): PulseView {
  return {
    innerHeight: window.innerHeight,
    overflowY: (node) => window.getComputedStyle(node as unknown as Element).overflowY,
  };
}
